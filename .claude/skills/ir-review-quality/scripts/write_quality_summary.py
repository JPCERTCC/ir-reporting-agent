#!/usr/bin/env python3
"""Write reviews/quality_review_NNN.md from a finished checklist review run.

The quality review of our own draft is the same checklist review applied to
external reports (ir-review-report-reporter, run until review_status.py says
DONE) plus the draft lint (ir_agent.reporting.draft_lint). This script only
collects those two results into the summary the human reads at CP3; it does
not judge anything itself, so the summary cannot claim checks that never ran.

Refuses to write when the review run is not DONE, when it reviewed a different
file, or when the draft changed after the review started.

Usage:
    python write_quality_summary.py --case-dir <case> --review-dir <review-run-dir>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

from ir_agent.reporting.draft_lint import (  # noqa: E402
    REVIEW_COMMENT_SECTIONS,
    lint_case,
    section_body,
)

REVIEW_STATUS = REPO / ".claude" / "skills" / "ir-review-report" / "scripts" / "review_status.py"
NON_DEFECT = {"external_confirmation", "optional_enhancement"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Findings the draft cannot fix from the case material: what only the human or
# the customer knows (pre-agreements, contact, preservation records, hearings).
# Rewriting the draft to "address" them only adds filler, so they are listed
# for the human and kept out of the verdict.
EXTERNAL_INPUT = re.compile(
    r"提供資料(から|上|では|からは|上は)?[^。]{0,30}確認でき(ない|ず|ません)|報告書外"
    r"|事前.{0,6}合意|合意(した|され)|合意記録|保全記録|チェーン・オブ・カストディ"
    r"|問い合わせ先|ヒアリング|照会(した)?結果"
)
# From this round on, re-drafting to clear checklist findings is stopped and
# the remaining ones go to the human at CP3.
HUMAN_ROUND = 3


def needs_external_input(issue: dict) -> bool:
    return bool(EXTERNAL_INPUT.search(str(issue.get("reason") or "")))


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def cell(text) -> str:
    return " ".join(str(text or "").split()).replace("|", "\\|") or "—"


def source_trace_lines(case_dir: Path, text: str) -> list[str]:
    """Trace each provided file: source → ledger → cited in the draft.

    A file is "cited" when the draft cites one of its evidence aliases (EV-###)
    or mentions its file name. Mechanical only; it flags files the draft never
    touches so the human can decide whether that omission is acceptable.
    """
    from ir_agent.analysis.source_coverage import IN_LEDGER, load_source_coverage

    report = load_source_coverage(case_dir)
    if not report.get("files"):
        return []
    material_path = case_dir / "reports" / "case_material.json"
    alias_of: dict[str, str] = {}
    if material_path.exists():
        alias_map = load(material_path).get("alias_map", {})
        alias_of = {eid: alias for alias, eid in alias_map.items()}
    cited_aliases = set(re.findall(r"EV-\d{3}", text))

    lines = ["", "## ソース網羅状況(提供資料 → 証拠台帳 → 本文)", ""]
    s = report["summary"]
    lines.append(
        f"- 提供ファイル {len(report['files'])} 件: 台帳あり {s.get('in_ledger', 0)}、"
        f"未承認 {s.get('not_approved', 0)}、未抽出 {s.get('not_extracted', 0)}、"
        f"未取り込み {s.get('not_chunked', 0)}"
    )
    if report["missing_hosts"]:
        lines.append("- 未提供のホスト: "
                     + "、".join(str(h["host"]) for h in report["missing_hosts"]))
    untouched = []
    for f in report["files"]:
        name = Path(f["path"]).name
        aliases = {alias_of[e] for e in f["evidence_ids"] if e in alias_of}
        if aliases & cited_aliases or (name and name in text):
            continue
        untouched.append(f)
    ledger_untouched = [f for f in untouched if f["status"] == IN_LEDGER]
    if ledger_untouched:
        lines.append("- 台帳に証拠があるのに本文で引用されていないファイル: "
                     + "、".join(f["path"] for f in ledger_untouched))
    others = [f for f in untouched if f["status"] != IN_LEDGER]
    if others:
        lines.append(f"- 本文で触れられていない未使用ファイル {len(others)} 件"
                     "(不足事項 CASE-SCOPE の記載で足りるかを確認してください):")
        lines += [f"  - [{f['status_label']}] {f['path']}" for f in others[:30]]
        if len(others) > 30:
            lines.append(f"  - ほか {len(others) - 30} 件")
    if not untouched:
        lines.append("- すべての提供ファイルが本文から追跡できます")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", required=True, type=Path)
    parser.add_argument("--review-dir", required=True, type=Path)
    args = parser.parse_args()
    case_dir = args.case_dir.resolve()
    review_dir = args.review_dir.resolve()
    draft = case_dir / "reports" / "draft_report.md"

    manifest = load(review_dir / "run_manifest.json")
    reviewed = Path(manifest.get("report_path", ""))
    if not reviewed.is_absolute():
        reviewed = (Path.cwd() / reviewed).resolve()
    if reviewed != draft.resolve():
        print(f"error: このレビューは {reviewed} を対象にしています({draft} ではありません)")
        return 2
    normalized = review_dir / "normalized.txt"
    if normalized.exists() and draft.stat().st_mtime > normalized.stat().st_mtime:
        print("error: ドラフトがレビュー開始後に変更されています。"
              "新しい作業フォルダでチェックリストレビューをやり直してください")
        return 2

    mode = manifest.get("review_mode", "reporter")
    proc = subprocess.run(
        [sys.executable, str(REVIEW_STATUS), "--review-dir", str(review_dir), "--mode", mode],
        capture_output=True, text=True,
    )
    if proc.returncode != 0 or "\nDONE" not in proc.stdout:
        print("error: チェックリストレビューが DONE になっていません。"
              "review_status.py の NEXT STEP に従って完了させてください")
        return 2

    lint = lint_case(case_dir, draft)
    summary = load(review_dir / "summary.json")
    issues = load(review_dir / "issues_normalized.json")
    issues = issues.get("issues", []) if isinstance(issues, dict) else issues
    candidates = [i for i in issues if i.get("category") not in NON_DEFECT]
    awaiting = [i for i in candidates if needs_external_input(i)]
    defects = sorted(
        (i for i in candidates if not needs_external_input(i)),
        key=lambda i: SEVERITY_ORDER.get(i.get("severity"), 9),
    )
    external = [i for i in issues if i.get("category") == "external_confirmation"]
    serious = [i for i in defects if i.get("severity") in ("critical", "high")]
    text = draft.read_text(encoding="utf-8")
    unfilled = [h.lstrip("#").strip() for h in REVIEW_COMMENT_SECTIONS
                if re.sub(r"(?s)<!--.*?-->", "", section_body(text, h)).strip() == ""]

    reviews = case_dir / "reviews"
    reviews.mkdir(parents=True, exist_ok=True)
    nums = [int(m.group(1)) for p in reviews.glob("quality_review_*.md")
            if (m := re.match(r"quality_review_(\d+)\.md$", p.name))]
    round_no = max(nums, default=0) + 1
    out = reviews / f"quality_review_{round_no:03d}.md"

    counts = summary.get("verdict_counts", {})
    overall = summary.get("overall_achievement", {})
    # Medium defects (e.g. missing_required_item) and unjudged checklist items
    # are not "no findings": they still need the human's attention before CP3.
    medium = [i for i in defects if i.get("severity") == "medium"]
    unknown = int(counts.get("unknown", 0) or 0)
    if lint.failures or serious:
        verdict = "承認前に修正すべき点あり"
    elif medium or unknown:
        verdict = (f"確認・修正を要する指摘あり(medium {len(medium)} 件、"
                   f"判定不能 unknown {unknown} 件)")
    else:
        verdict = "重大な指摘なし"
    if round_no >= HUMAN_ROUND and (serious or medium):
        verdict += (f"(品質レビュー {round_no} 回目: 残る指摘はドラフトの再修正で解消を図らず、"
                    "CP3 で人間が対応要否を判断する)")
    lines = [
        "# 品質レビュー: draft_report.md",
        "",
        f"- 作成日時: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- 対象ドラフト SHA-256: {hashlib.sha256(draft.read_bytes()).hexdigest()}",
        f"- チェックリストレビュー({mode}): `{review_dir / 'final_review.md'}`",
        "- 位置づけ: 機械検査とチェックリストレビューの集約。人間承認の代替ではない",
        f"- レビュー回数: {round_no} 回目",
        f"- 総合所見: {verdict}",
        "",
        "## 機械検査(構造・承認内容の反映・根拠)",
        "",
        "PASS" if lint.passed else f"FAIL({len(lint.failures)} 件)",
        "",
    ]
    lines += [f"- {m}" for m in lint.failures]
    lines += [f"- 注意: {m}" for m in lint.warnings]
    lines += [
        "",
        "## チェックリスト評価",
        "",
        "| met | partial | not_met | unknown | not_applicable | 達成率 |",
        "|---|---|---|---|---|---|",
        f"| {counts.get('met', 0)} | {counts.get('partial', 0)} | {counts.get('not_met', 0)} | "
        f"{counts.get('unknown', 0)} | {counts.get('not_applicable', 0)} | "
        f"{overall.get('rate') if overall.get('rate') is not None else '—'} |",
        "",
        "### 修正すべき指摘",
        "",
    ]
    if defects:
        lines += ["| 指摘ID | チェック項目 | 重大度 | 指摘 | 修正案 |", "|---|---|---|---|---|"]
        lines += [
            f"| {i.get('issue_id')} | {', '.join(i.get('checklist_ids') or []) or '—'} | "
            f"{i.get('severity')} | {cell(i.get('reason'))} | {cell(i.get('suggested_revision'))} |"
            for i in defects
        ]
    else:
        lines.append("なし")
    lines += source_trace_lines(case_dir, text)
    lines += ["", "## 人間が最終版までに記入・確認すべき事項", ""]
    if unfilled:
        lines.append("- 未記入のレビュー担当者記入欄(これに起因する not_met を含む): "
                     + "、".join(unfilled))
    if external:
        ids = sorted({c for i in external for c in i.get("checklist_ids") or []})
        lines.append(f"- 報告書外の資料で確認が必要な項目 {len(external)} 件: {', '.join(ids)}")
    if awaiting:
        lines += ["", "### 人間・外部入力待ちの指摘(総合所見の判定に含めない)", "",
                  "提供資料に含まれない情報(事前合意・問い合わせ先・保全記録・ヒアリング等)が"
                  "必要な指摘です。ドラフトを「確認できない」旨の文で埋めて解消せず、人間が"
                  "情報を示した場合のみ記入します。", "",
                  "| 指摘ID | チェック項目 | 重大度 | 指摘 |", "|---|---|---|---|"]
        lines += [f"| {i.get('issue_id')} | {', '.join(i.get('checklist_ids') or []) or '—'} | "
                  f"{i.get('severity')} | {cell(i.get('reason'))} |" for i in awaiting]
    if not unfilled and not external and not awaiting:
        lines.append("- なし")
    lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"written: {out}")
    print(f"総合所見: {verdict}(機械検査 {'PASS' if lint.passed else 'FAIL'}、"
          f"修正すべき指摘 {len(defects)} 件、うち critical/high {len(serious)} 件、"
          f"medium {len(medium)} 件、unknown {unknown} 件、人間・外部入力待ち {len(awaiting)} 件、"
          f"レビュー {round_no} 回目)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
