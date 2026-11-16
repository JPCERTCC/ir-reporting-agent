#!/usr/bin/env python3
"""Copy worksheet suggestions into results.json rows that are still unfilled.

aggregation_worksheet.json offers a ``suggestion`` where SubAgents agree: every
observation gives the same verdict (met / partial / not_met) and cites spans,
or no chunk observed anything for an item the report itself must answer
(recorded as not_met with an absence id). Typing those rows out one Edit at a
time is the slowest part of the review, and it is not judgment: this script
copies the suggestion (verdict, source_span_ids, absence_check_ids,
rationale) into results.json.

Safety rules:
  * only rows whose verdict is still null are touched — a verdict the Agent
    already wrote is never overwritten
  * ``--all-auto`` applies only suggestions flagged ``auto_applicable``
    (unanimous verdict with cited spans, or no observation at all; a ``met``
    on an "all of X" requirement is excluded);
    everything else must be named with ``--ids`` after the Agent has read it
  * conflicting, mixed-verdict and unknown items have no suggestion and stay
    with the Agent
  * the rationale records that it came from SubAgent consensus, so the review
    document shows the provenance

Usage:
    python apply_suggested_results.py --review-dir reviews/Report/run --all-auto
    python apply_suggested_results.py --review-dir reviews/Report/run --ids CUS-1-1 CUS-2-3
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

import review_io


def _load(path: Path) -> dict:
    data, error = review_io.load_json_safe(path)
    if error is not None:
        raise ValueError(f"{path}: {error}")
    return data if isinstance(data, dict) else {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--review-dir", required=True, type=Path)
    ap.add_argument("--all-auto", action="store_true",
                    help="apply every auto_applicable suggestion")
    ap.add_argument("--ids", nargs="*", default=[],
                    help="checklist ids to apply (Agent has read them)")
    args = ap.parse_args()
    if not args.all_auto and not args.ids:
        print("error: give --all-auto and/or --ids", file=sys.stderr)
        return 2

    results_path = args.review_dir / "results.json"
    worksheet_path = args.review_dir / "aggregation_worksheet.json"
    for path in (results_path, worksheet_path):
        if not path.exists():
            print(f"error: not found: {path}", file=sys.stderr)
            return 2
    try:
        results = _load(results_path)
        worksheet = _load(worksheet_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    suggestions = {
        c["checklist_id"]: c["suggestion"]
        for c in worksheet.get("checklist_items", [])
        if isinstance(c, dict) and c.get("suggestion")
    }
    wanted = set(args.ids)
    unknown = sorted(i for i in wanted if i not in suggestions)
    if unknown:
        print(
            f"error: no suggestion for {unknown} — only items where all observations "
            "say met and cite spans have one; fill these rows yourself",
            file=sys.stderr,
        )
        return 2

    applied: list[str] = []
    skipped_filled: list[str] = []
    for row in results.get("results", []):
        cid = row.get("checklist_id") or row.get("id")
        sug = suggestions.get(cid)
        if not sug:
            continue
        if not ((args.all_auto and sug.get("auto_applicable")) or cid in wanted):
            continue
        if row.get("verdict") is not None:
            skipped_filled.append(cid)
            continue
        row["verdict"] = sug["verdict"]
        row["rationale"] = sug["rationale"]
        row["source_span_ids"] = list(sug["source_span_ids"])
        if sug.get("absence_check_ids"):
            row["absence_check_ids"] = list(sug["absence_check_ids"])
        if sug["verdict"] == "unknown":
            row["unknown_reason"] = sug.get("unknown_reason")
            row["external_confirmation_needed"] = sug.get("external_confirmation_needed", "")
        applied.append(cid)

    if applied:
        review_io.atomic_write_json(results_path, results)
        with (args.review_dir / "run_log.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "event": "apply_suggested_results", "count": len(applied), "ids": applied,
            }, ensure_ascii=False) + "\n")
    print(f"applied {len(applied)} suggestion(s) to {results_path}")
    if skipped_filled:
        print(f"skipped (already judged, not overwritten): {', '.join(skipped_filled)}")
    remaining = [
        r.get("checklist_id") or r.get("id") for r in results.get("results", [])
        if r.get("verdict") is None and r.get("evaluation_scope") != "out_of_scope"
    ]
    print(f"remaining unfilled: {len(remaining)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
