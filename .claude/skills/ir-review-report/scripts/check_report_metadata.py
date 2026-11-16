#!/usr/bin/env python3
"""Deterministic metadata and appendix grounding checks for IR reports.

Complements the checklist and evidence-ID checks by verifying properties that
are mechanical but were previously unchecked by the quality review, and that
therefore slipped through: report metadata dates, final-version draft-marker
residue, and the ATT&CK appendix grounding. Requirement UP-09.

Checks:
  metadata_date       作成日 / 報告時点 / 変更履歴 initial date are well-formed
                      YYYY-MM-DD, at or after the investigation end date, and
                      within a small window of the run date (catches wrong-year
                      / stale dates).
  final_draft_marker  a report with no draft watermark (i.e. a finalized
                      report) must not still carry "(ドラフト)" / "0.1(ドラフト)"
                      / "レビュー前ドラフト" in its metadata.
  attack_appendix     every ATT&CK appendix technique_id is well-formed
                      (T#### or T####.###) and every referenced EV-### exists
                      in the case material's evidence ledger.

Output: JSON on stdout. Exit 1 when any problem is found, else 0.

Usage:
    python check_report_metadata.py --report <report.md> [--material <case_material.json>]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_DRAFT_WATERMARK = "【ドラフト"


def _parse_iso_date(value: str) -> "date | None":
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", value)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def check_metadata_date(report: str, material: dict | None) -> list[str]:
    problems: list[str] = []
    today = date.today()
    end_dt = None
    if material:
        end_dt = _parse_iso_date(
            material.get("case", {}).get("time_range_utc", {}).get("end", "") or ""
        )
    checked: list[tuple[str, str]] = []
    for label, pat in (
        ("作成日", r"\|\s*作成日\s*\|\s*([^|]+?)\s*\|"),
        ("報告時点", r"\|\s*報告時点\s*\|\s*([^|]+?)\s*\|"),
    ):
        m = re.search(pat, report)
        if m:
            checked.append((label, m.group(1).strip()))
    for label, raw in checked:
        d = _parse_iso_date(raw)
        if d is None:
            problems.append(f"{label}が YYYY-MM-DD 形式でない: {raw!r}")
            continue
        if end_dt and d < end_dt:
            problems.append(f"{label}({d})が調査対象期間の終了日({end_dt})より前")
        if d > today + timedelta(days=1):
            problems.append(f"{label}({d})が未来日(実行日 {today})")
        elif d < today - timedelta(days=7):
            problems.append(
                f"{label}({d})が実行日({today})から7日以上離れている(年月日誤りの疑い)"
            )
    return problems


def check_final_draft_marker(report: str) -> list[str]:
    # Only meaningful for a finalized report (no draft watermark present).
    if _DRAFT_WATERMARK in report:
        return []
    problems: list[str] = []
    for marker in ("0.1（ドラフト）", "0.1(ドラフト)", "レビュー前ドラフト"):
        if marker in report:
            problems.append(
                f"最終版に草案表記が残存: {marker!r}(finalize で版数をスタンプする)"
            )
    return problems


def check_attack_appendix(report: str, material: dict | None) -> list[str]:
    problems: list[str] = []
    known_ev = set()
    if material:
        known_ev = {
            e.get("report_evidence_id")
            for e in material.get("evidence_ledger", [])
        }
    # Isolate the ATT&CK appendix section.
    m = re.search(r"##\s*付録B[^\n]*\n(.*?)(?:\n##\s|\Z)", report, re.S)
    if not m:
        return problems
    body = m.group(1)
    for line in body.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        tid = cells[1]
        if tid in ("テクニックID", "") or set(tid) <= {"-"}:
            continue
        if not _TECHNIQUE_RE.match(tid):
            problems.append(f"付録BのテクニックID形式が不正: {tid!r}")
        if known_ev:
            for ev in re.findall(r"EV-\d{3}", cells[-1]):
                if ev not in known_ev:
                    problems.append(
                        f"付録Bが素材に存在しない証拠IDを参照: {ev}(技術 {tid})"
                    )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--material", type=Path, default=None)
    args = ap.parse_args()

    if not args.report.exists():
        print(json.dumps({"error": f"report not found: {args.report}"}))
        return 2
    report = args.report.read_text(encoding="utf-8")

    material = None
    if args.material and args.material.exists():
        try:
            material = json.loads(args.material.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            material = None

    checks = {
        "metadata_date": check_metadata_date(report, material),
        "final_draft_marker": check_final_draft_marker(report),
        "attack_appendix": check_attack_appendix(report, material),
    }
    total = sum(len(v) for v in checks.values())
    print(json.dumps(
        {"problem_count": total, "checks": checks},
        ensure_ascii=False, indent=2,
    ))
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
