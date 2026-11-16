#!/usr/bin/env python3
"""Convert validator failures into concise repair instructions for Agents.

This helper does not repair files. It normalizes common validator messages so a
weaker model can edit the right JSON field without interpreting long logs.

Usage:
    python make_repair_instructions.py --gate check_claim_assessments.py \
        --stdout gate.out --stderr gate.err --review-dir reviews/Report/run \
        --out repair_instructions.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import review_io


def read_optional(path: Path | None) -> str:
    if path is None:
        return ""
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def add_repair(
    repairs: list[dict[str, Any]],
    target_file: str,
    problem: str,
    instruction: str,
    *,
    json_path: str | None = None,
    allowed_values: list[str] | None = None,
    blocking: bool = True,
) -> None:
    repairs.append({
        "problem_id": f"RPR-{len(repairs) + 1:03d}",
        "target_file": target_file,
        "json_path": json_path,
        "problem": problem,
        "instruction": instruction,
        "allowed_values": allowed_values,
        "blocking": blocking,
    })


def classify_line(gate: str, line: str, repairs: list[dict[str, Any]]) -> bool:
    lower = line.lower()

    if "check_claim_assessments" in gate:
        if "still contains 【要記入】" in line:
            add_repair(
                repairs, "claim_assessments.json", line,
                "雛形に残っている 【要記入】 を、該当行の根拠 span（source_span_ids）と "
                "aggregation_worksheet.json の topics を読んで、実際の評価に Edit で置き換えて"
                "ください（review_verdict と reason。reason には根拠・論理・確度の"
                "観点から見た評価をまとめて書く）。全面的な書き直しや"
                "修正用スクリプトは不要です。",
            )
            return True
        if "is not_reported, but SubAgent observations" in line:
            add_repair(
                repairs, "claim_assessments.json", line,
                "SubAgent が根拠 span 付きで観測した topic です。presence を reported に戻し、"
                "その span を使うか、観測を採用しない理由を override_reason に書いてください。",
                json_path="conclusion_inventory",
            )
            return True
        if "appears in" in line and "rows" in line:
            add_repair(
                repairs, "claim_assessments.json", line,
                "同じ topic の行が複数あります。1行に統合し、presence と assessment_ids を"
                "一貫させてください。",
                json_path="conclusion_inventory",
            )
            return True
        if "reported conclusion requires source_span_ids" in line:
            label = line.split(":", 1)[0]
            add_repair(
                repairs,
                "claim_assessments.json",
                line,
                "reported の conclusion_inventory 行には、source_index.json に存在する SPN-ID を source_span_ids に1件以上入れてください。",
                json_path=f"conclusion_inventory[{label}].source_span_ids",
            )
            return True
        if "reported conclusion requires assessment_ids" in line:
            add_repair(
                repairs,
                "claim_assessments.json",
                line,
                "reported の conclusion_inventory 行には、対応する claim_assessments[].assessment_id の ASM-* を assessment_ids に入れてください。",
            )
            return True
        if "not_reported conclusion requires absence_check_ids" in line:
            label = line.split(":", 1)[0]
            add_repair(
                repairs,
                "claim_assessments.json",
                line,
                "not_reported の conclusion_inventory 行には、SubAgent が観測しなかったことを示す"
                " absence_check_ids（例: ABS-CON-<topic>）を入れてください。",
                json_path=f"conclusion_inventory[{label}].absence_check_ids",
            )
            return True
        if "source_span_ids or absence_check_ids is required" in line:
            add_repair(
                repairs,
                "claim_assessments.json",
                line,
                "該当行に、根拠となる source_span_ids（存在する SPN-ID）、または未記載確認済みの"
                " absence_check_ids のいずれかを入れてください。",
            )
            return True
        if "related_conclusion_ids must contain at least two IDs" in line:
            add_repair(
                repairs,
                "claim_assessments.json",
                line,
                "consistency_assessments の該当行の related_conclusion_ids に、比較対象となる"
                " conclusion_inventory の CON-* を2件以上入れてください。",
            )
            return True
        if "unknown assessment_ids" in line:
            add_repair(
                repairs,
                "claim_assessments.json",
                line,
                "assessment_ids は claim_assessments[].assessment_id に存在する ASM-* だけを参照してください。",
            )
            return True
        if "review_verdict" in line and "invalid" in lower:
            allowed = ["supported", "partially_supported", "unsupported", "not_assessable"]
            if "recommendation" in lower or "aligned" in lower:
                allowed = ["mapped", "partially_mapped", "not_mapped", "not_assessable"]
            add_repair(
                repairs,
                "claim_assessments.json",
                line,
                "review_verdict を許可された enum 値に修正してください。",
                allowed_values=allowed,
            )
            return True
        if "linked_finding_ids" in line:
            add_repair(
                repairs,
                "claim_assessments.json",
                line,
                "recommendation_assessments[].linked_finding_ids は CON-* ではなく、claim_assessments[].assessment_id の ASM-* を参照してください。",
            )
            return True
        if "required topics are missing" in line:
            add_repair(
                repairs,
                "claim_assessments.json",
                line,
                "必須 topic を conclusion_inventory に追加し、記載がない場合は not_reported、対象外なら not_applicable として理由を記録してください。",
            )
            return True

    if "check_issues" in gate:
        if "【要記入】" in line:
            add_repair(
                repairs,
                "issues.json",
                line,
                "issues.json の雛形に残っている【要記入】を、該当 issue の内容に基づく実際の記述に"
                "Edit で置き換えてください（suggested_revision / reason / category）。"
                "ファイル全体の書き直しや修正用スクリプトは不要です。",
            )
            return True
        if "missing fields" in line:
            add_repair(
                repairs,
                "issues.json",
                line,
                "該当 issue に不足している必須フィールドを追加してください。少なくとも category、severity、checklist_ids、reason、suggested_revision が必要です。",
            )
            return True
        if "checklist" in lower and ("missing" in lower or "unknown" in lower):
            add_repair(
                repairs,
                "issues.json",
                line,
                "issue の checklist_ids を results.json に存在する該当 checklist ID に修正してください。",
            )
            return True
        if "non-substantive source_span_ids" in line:
            label = line.split(":", 1)[0]
            add_repair(
                repairs,
                "issues.json",
                line,
                "この span はページ区切り・機密区分表示・ヘッダー/フッターなど本文以外の"
                "テキストで、根拠として使えません。新しい span を推測で選ばず、"
                "merged_observations.json の checklist_observations（この issue の"
                " checklist_ids と一致する行）または issue_observations の"
                " source_span_ids をそのまま使ってください。該当行が見つからない、"
                "または全て空の場合は、issue の checklist_ids に対応する"
                " subagent_observations/*.json を検索し、実際に本文を読んだ chunk の"
                " source_span_ids を確認してください。それでも実在する根拠 span が"
                "見つからない場合は、この issue を削除するか、報告書全体を確認した"
                "うえで absence_check_ids に切り替えてください。",
                json_path=f"issues[{label}].source_span_ids",
            )
            return True
        if "ground" in lower or "source_span_ids" in line or "absence_check_ids" in line:
            add_repair(
                repairs,
                "issues.json",
                line,
                "指摘を source_span_ids、quotes、absence_check_ids のいずれかに接地してください。接地できない一般論の指摘は削除してください。",
            )
            return True

    if "check_coverage" in gate:
        if "missing verdict" in line:
            add_repair(
                repairs,
                "results.json",
                line,
                "該当 checklist 項目の result 行を追加し、verdict と rationale を埋めてください。",
            )
            return True
        if "invalid verdict" in line:
            add_repair(
                repairs,
                "results.json",
                line,
                "verdict を met / partial / not_met / not_applicable / unknown のいずれかに修正してください。",
                allowed_values=["met", "partial", "not_met", "not_applicable", "unknown"],
            )
            return True
        if "unknown is not allowed" in line:
            add_repair(
                repairs,
                "results.json",
                line,
                "報告書本文から判定できる項目に unknown は使わず、met / partial / not_met / not_applicable のいずれかに修正してください。",
                allowed_values=["met", "partial", "not_met", "not_applicable"],
            )
            return True
        if "unknown_reason" in line or "external_confirmation_needed" in line:
            add_repair(
                repairs,
                "results.json",
                line,
                "unknown を使う場合は unknown_reason と external_confirmation_needed を必ず記録してください。",
            )
            return True

    if "check_review_doc" in gate or "render_review" in gate:
        if "does not match" in lower or "final_review" in lower:
            add_repair(
                repairs,
                "final_review.md",
                line,
                "final_review.md を手編集せず、render_review.py を再実行して生成物を正式成果物にしてください。",
            )
            return True

    return False


def lines_from_source(raw: str) -> list[str]:
    """Turn one gate's raw output into normalized single-issue lines.

    Some gates (check_claim_assessments.py) print their whole result as one
    pretty-printed JSON object with a top-level "problems" array. Splitting
    that on newlines yields JSON syntax noise (braces, quoted/escaped
    fragments, trailing commas) instead of the actual problem text, which
    both defeats classify_line's pattern matching and floods
    repair_instructions.json with junk rows. When the source parses as such a
    JSON object, use its "problems" strings directly instead.
    """
    stripped = raw.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except Exception:
            data = None
        if isinstance(data, dict) and isinstance(data.get("problems"), list):
            return [
                re.sub(r"\s+", " ", str(p)).strip()
                for p in data["problems"]
                if str(p).strip()
            ]
    return [
        re.sub(r"\s+", " ", line).strip()
        for line in raw.splitlines()
        if line.strip()
    ]


def fallback(gate: str, line: str, repairs: list[dict[str, Any]]) -> None:
    target = "review artifacts"
    if "claim" in gate:
        target = "claim_assessments.json"
    elif "issue" in gate:
        target = "issues.json"
    elif "coverage" in gate:
        target = "results.json"
    add_repair(
        repairs,
        target,
        line,
        "validator の指摘に従って対象 JSON を修正し、同じ gate を再実行してください。",
    )


def main() -> int:
    review_io.require_via_review_status("make_repair_instructions.py")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--stdout", type=Path)
    parser.add_argument("--stderr", type=Path)
    parser.add_argument("--message", default="")
    parser.add_argument("--review-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--attempt", type=int, default=1)
    args = parser.parse_args()

    lines: list[str] = []
    for raw in (read_optional(args.stdout), read_optional(args.stderr), args.message):
        if raw.strip():
            lines.extend(lines_from_source(raw))
    repairs: list[dict[str, Any]] = []
    for line in lines:
        if line.startswith("PASS:"):
            continue
        if not classify_line(args.gate, line, repairs):
            fallback(args.gate, line, repairs)

    # Deduplicate by target/problem/instruction while preserving order.
    seen: set[tuple[str, str, str]] = set()
    unique_repairs: list[dict[str, Any]] = []
    for repair in repairs:
        key = (
            str(repair.get("target_file")),
            str(repair.get("problem")),
            str(repair.get("instruction")),
        )
        if key in seen:
            continue
        seen.add(key)
        repair = dict(repair)
        repair["problem_id"] = f"RPR-{len(unique_repairs) + 1:03d}"
        unique_repairs.append(repair)

    data = {
        "schema_version": "1.0",
        "failed_gate": args.gate,
        "attempt": args.attempt,
        "review_dir": str(args.review_dir),
        "repairs": unique_repairs,
    }
    review_io.atomic_write_json(args.out, data)
    print(f"wrote {len(unique_repairs)} repair instructions to {args.out}")
    return 0 if unique_repairs else 1


if __name__ == "__main__":
    sys.exit(main())

