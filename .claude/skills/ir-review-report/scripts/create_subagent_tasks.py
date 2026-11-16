#!/usr/bin/env python3
"""Create explicit SubAgent task files from review chunks and checklist items.

Each task contains the assigned chunk, the mode-specific checklist items, the
major-conclusion review focus, the required SubAgent observation schema, and the
path where the SubAgent must write its observation file. The parent Agent
should launch one SubAgent per task and pass only the task file path, not the
task contents.

Usage:
    python create_subagent_tasks.py \
        --chunk-dir review_chunks \
        --out-dir subagent_tasks \
        --mode customer
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import parse_checklists
import review_io

REQUIRED_OBSERVATION_KEYS = [
    "chunk_id",
    "review_mode",
    "covered_span_ids",
    "checklist_observations",
    "conclusion_observations",
    "issue_observations",
    "open_questions",
]
FORBIDDEN_OBSERVATION_KEYS = [
    "reviewed_span_ids",
    "checklist_relevant_observations",
    "potential_issues",
    "claim_extractions",
    "evidence_hits",
]


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def load_checklist_items(skill_dir: Path, mode: str) -> list[dict[str, Any]]:
    ref = skill_dir / "references"
    if mode == "customer":
        path = ref / "checklist_customer.md"
        source = "customer"
        prefix = "CUS"
    elif mode == "reporter":
        path = ref / "checklist_reporter.md"
        source = "reporter"
        prefix = "REP"
    else:
        raise ValueError(f"unsupported mode: {mode}")
    if not path.exists():
        raise FileNotFoundError(f"checklist not found: {path}")
    return parse_checklists.parse_markdown(path, source, prefix)


# Allowed values mirror references/json_contracts.md so SubAgent output can be
# consumed without translation.
ALLOWED_VALUES = {
    "candidate_verdict": ["met", "partial", "not_met", "not_applicable", "unknown"],
    "topic": [
        "initial_access",
        "scope",
        "lateral_movement",
        "persistence",
        "c2_external",
        "exfiltration",
        "impact",
        "limitations",
        "recommendations",
        "other",
    ],
    "confidence_language": [
        "confirmed",
        "highly_likely",
        "possible",
        "unknown",
        "negative",
    ],
    "category": [
        "evidence_integrity",
        "unsupported_claim",
        "certainty_inconsistency",
        "cross_section_inconsistency",
        "missing_required_item",
        "countermeasure_mapping",
        "format_or_usability",
        "external_confirmation",
        "optional_enhancement",
    ],
    "severity_hint": ["critical", "high", "medium", "low", "info"],
}


def output_schema() -> dict[str, Any]:
    return {
        "required_top_level_keys": REQUIRED_OBSERVATION_KEYS,
        "optional_top_level_keys": ["schema_version", "reviewed_at", "metadata"],
        "forbidden_top_level_keys": FORBIDDEN_OBSERVATION_KEYS,
        "allowed_values": ALLOWED_VALUES,
        "observation_template": {
            "schema_version": "1.0",
            "chunk_id": "CHK-001",
            "review_mode": "customer",
            "covered_span_ids": ["SPN-0001"],
            "checklist_observations": [
                {
                    "observation_id": "OBS-CHK-001-001",
                    "checklist_id": "CUS-1-1",
                    "candidate_verdict": "|".join(ALLOWED_VALUES["candidate_verdict"]),
                    "rationale": "本文spanに基づく短い理由",
                    "source_span_ids": ["SPN-0001"],
                    "absence_check_ids": [],
                    "confidence": 0.8,
                }
            ],
            "conclusion_observations": [
                {
                    "observation_id": "OBS-CHK-001-002",
                    "topic": "|".join(ALLOWED_VALUES["topic"]),
                    "stated_conclusion": "chunk内で確認した主要結論",
                    "source_span_ids": ["SPN-0001"],
                    "confidence_language": "|".join(ALLOWED_VALUES["confidence_language"]),
                    "notes": "根拠、制約、詳細章との照合要否",
                }
            ],
            "issue_observations": [
                {
                    "observation_id": "OBS-CHK-001-003",
                    "category": "|".join(ALLOWED_VALUES["category"]),
                    "severity_hint": "|".join(ALLOWED_VALUES["severity_hint"]),
                    "related_checklist_ids": ["CUS-1-1"],
                    "reason": "指摘理由",
                    "source_span_ids": ["SPN-0001"],
                    "absence_check_ids": [],
                    "suggested_revision": "改善案",
                }
            ],
            "open_questions": [
                {
                    "question_id": "Q-CHK-001-001",
                    "question": "追加確認が必要な事項",
                    "reason": "chunk内の記載だけでは判断できない理由",
                    "source_span_ids": ["SPN-0001"],
                    "related_checklist_ids": ["CUS-1-1"],
                }
            ],
        },
    }


def conclusion_review_focus() -> list[str]:
    return [
        "主要結論を抽出する。初期侵入、侵害範囲、横展開、永続化、情報窃取、影響、推奨対策に関する記載を優先する。",
        "結論の根拠となる本文spanを source_span_ids に記録する。",
        "断定、推測、未確認事項の区別が曖昧な箇所を issue_observations に記録する。",
        "他章との整合性確認が必要な結論は conclusion_observations.notes に記録する。",
    ]


MODE_PERSPECTIVE = {
    "customer": "被害組織・依頼者が報告書を受領した際に確認すべき事項（ユーザー向けチェックリスト）",
    "reporter": "報告書作成者が報告書の品質を確認すべき事項（レポーター向けチェックリスト）",
}


def review_context(mode: str) -> dict[str, Any]:
    return {
        "purpose": (
            "インシデント調査報告書の本文を、チェックリストに照らして評価する。"
            f"観点: {MODE_PERSPECTIVE[mode]}。"
        ),
        "your_role": (
            "あなたは報告書全体のうち 1 つの chunk だけを担当する観測担当である。"
            "role が core の span が担当範囲、overlap の span は文脈参照用であり "
            "covered_span_ids には core だけを入れる。"
            "最終判定は親 Agent が全 chunk の観測を集約して行う。"
        ),
        "out_of_scope": [
            "調査の再実施や技術的な真偽の判定はしない。",
            "報告書に書かれていない事実を推測で補わない。",
            "報告書外の資料（契約書、合意記録、証拠保全記録など）は参照できない前提で扱う。",
        ],
        "verdict_rules": [
            "chunk 内に項目に対応する記載がある場合だけ checklist_observations を出す。"
            "記載がない項目の observation は出さない（chunk 単独では未記載と判断できない）。",
            "candidate_verdict はこの chunk の記載だけで見た暫定判定である。"
            "項目の詳細要件を満たせば met、一部なら partial、記載はあるが要件を満たさなければ not_met。",
            "unknown は checklist_items の unknown_allowed が true で、"
            "報告書外の資料がないと判断できない場合だけ使う。"
            "evaluable_from_report が true の項目には unknown を使わない。",
            "根拠は source_span_ids に本文 span だけを入れる。"
            "目次、表紙、ヘッダー、フッターだけの span は根拠にしない。",
        ],
    }


def task_instructions(output_path: Path) -> list[str]:
    return [
        "この task JSON だけを入力として扱う。報告書原本や他の chunk / task は読まない。",
        "まず review_context（目的、担当範囲、判定ルール）を読む。",
        "chunk.spans の本文を確認し、checklist_items と major_conclusion_review_focus に基づいて観測結果を作成する。",
        "最終的な results.json、issues.json、claim_assessments.json、final_review.md は作成しない。",
        "covered_span_ids には確認した担当chunk内の span ID を入れる。",
        "reviewed_span_ids、checklist_relevant_observations、potential_issues、claim_extractions、evidence_hits は使用しない。",
        "出力は output_schema.required_top_level_keys を満たす JSON object とする。",
        "open_questions に項目を入れる場合、文字列ではなく output_schema.observation_template.open_questions "
        "と同じ JSON object 形式にする。質問がなければ空配列 [] にする。",
        "topic / confidence_language / category / severity_hint / candidate_verdict は "
        "output_schema.allowed_values の値だけを使う。",
        f"完成した JSON object を {output_path} に Write する。ファイル名は変更しない。",
        "covered_span_ids には確認した core span を漏れなく入れる。"
        "空の observation を書いて完了扱いにしない。",
        "最終応答には、書き込んだパス、covered_span_ids の件数、各 observation 配列の件数だけを返す。"
        "観測 JSON の全文は返さない。",
    ]


def create_tasks(
    *,
    chunk_dir: Path,
    out_dir: Path,
    skill_dir: Path,
    mode: str,
) -> dict[str, Any]:
    manifest_path = chunk_dir / "chunk_manifest.json"
    manifest = load_json(manifest_path)
    chunks = manifest.get("chunks", [])
    if not isinstance(chunks, list) or not chunks:
        raise ValueError("chunk_manifest.json must contain non-empty chunks list")

    checklist_items = load_checklist_items(skill_dir, mode)
    if not checklist_items:
        raise ValueError(f"no checklist items found for mode {mode}")

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir.parent / "subagent_observations").mkdir(parents=True, exist_ok=True)
    task_records: list[dict[str, Any]] = []
    for record in chunks:
        if not isinstance(record, dict):
            continue
        chunk_id = str(record.get("chunk_id") or "")
        chunk_path = chunk_dir / str(record.get("path") or "")
        if not chunk_id:
            raise ValueError("chunk manifest record missing chunk_id")
        if not chunk_path.exists():
            raise FileNotFoundError(f"chunk file not found for {chunk_id}: {chunk_path}")
        chunk = load_json(chunk_path)
        if chunk.get("review_mode") != mode:
            raise ValueError(
                f"{chunk_path}: review_mode {chunk.get('review_mode')!r} does not match {mode!r}"
            )

        # Absolute, so neither the SubAgent nor review_status.py depends on the
        # current directory of whoever runs them.
        output_path = (out_dir.parent / "subagent_observations" / f"{chunk_id}.json").resolve()
        task = {
            "schema_version": "1.0",
            "task_id": f"TASK-{chunk_id}",
            "chunk_id": chunk_id,
            "review_mode": mode,
            "chunk_path": str(chunk_path),
            "observation_output_path": str(output_path),
            "review_context": review_context(mode),
            "chunk": chunk,
            "checklist_items": checklist_items,
            "major_conclusion_review_focus": conclusion_review_focus(),
            "output_schema": output_schema(),
            "instructions": task_instructions(output_path),
        }
        task_path = (out_dir / f"{chunk_id}.json").resolve()
        review_io.atomic_write_json(task_path, task)
        task_records.append({
            "task_id": task["task_id"],
            "chunk_id": chunk_id,
            "path": task_path.name,
            "task_path": str(task_path),
            "observation_output_path": str(output_path),
            "checklist_item_count": len(checklist_items),
            "core_span_count": len(chunk.get("core_span_ids", [])),
            "span_count": len(chunk.get("spans", [])),
        })

    task_manifest = {
        "schema_version": "1.0",
        "review_mode": mode,
        "chunk_manifest_path": str(manifest_path),
        "checklist_item_count": len(checklist_items),
        "tasks": task_records,
    }
    review_io.atomic_write_json(out_dir / "task_manifest.json", task_manifest)
    return task_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chunk-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--mode", choices=("customer", "reporter"), required=True)
    parser.add_argument(
        "--skill-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="ir-review-report skill directory",
    )
    args = parser.parse_args()

    if not args.chunk_dir.exists():
        print(f"error: chunk dir not found: {args.chunk_dir}", file=sys.stderr)
        return 2
    try:
        manifest = create_tasks(
            chunk_dir=args.chunk_dir,
            out_dir=args.out_dir,
            skill_dir=args.skill_dir,
            mode=args.mode,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"wrote {len(manifest['tasks'])} SubAgent tasks with "
        f"{manifest['checklist_item_count']} checklist items each"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
