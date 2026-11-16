#!/usr/bin/env python3
"""Pre-fill source_span_ids on still-unjudged results.json rows from SubAgent observations.

A verdict of not_met / unknown written with no source_span_ids silently drops
whatever the SubAgents observed for that item. Rather than checking for that
afterwards (which invites "fix it by whatever passes"), this puts the observed
spans on the row before the Agent judges it, so keeping them costs nothing and
dropping them takes a deliberate edit.

Touches only rows whose verdict is still null and whose source_span_ids is
empty; never a verdict, rationale, or an already-judged row. Spans that do not
exist in source_index.json, or that cannot ground a finding (page markers,
boilerplate), are skipped. At most 6 spans per row.

Usage:
    python prefill_result_spans.py --review-dir reviews/Report/run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import check_issues
import review_io

MAX_SPANS = 6


def prefill(results: list[dict], merged: dict, spans: dict[str, dict]) -> list[str]:
    observed: dict[str, list[str]] = {}
    for obs in merged.get("checklist_observations", []):
        if not isinstance(obs, dict) or not obs.get("checklist_id"):
            continue
        for sid in obs.get("source_span_ids") or []:
            if sid in spans and not check_issues._is_non_substantive_span(spans[sid]):
                bucket = observed.setdefault(str(obs["checklist_id"]), [])
                if sid not in bucket:
                    bucket.append(sid)
    touched: list[str] = []
    for row in results:
        cid = check_issues.result_id(row) if isinstance(row, dict) else None
        if not cid or row.get("verdict") is not None or row.get("source_span_ids"):
            continue
        if observed.get(cid):
            row["source_span_ids"] = observed[cid][:MAX_SPANS]
            touched.append(cid)
    return touched


def main() -> int:
    review_io.require_via_review_status("prefill_result_spans.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--review-dir", required=True, type=Path)
    args = ap.parse_args()
    d = args.review_dir
    try:
        results_data, e1 = review_io.load_json_safe(d / "results.json")
        merged, e2 = review_io.load_json_safe(d / "merged_observations.json")
        source_index, e3 = review_io.load_json_safe(d / "source_index.json")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for name, err in (("results.json", e1), ("merged_observations.json", e2),
                      ("source_index.json", e3)):
        if err is not None:
            print(f"error: {d / name}: {err}", file=sys.stderr)
            return 2
    spans = {
        str(s.get("source_span_id") or s.get("span_id") or s.get("id")): s
        for s in (source_index or {}).get("spans", [])
        if isinstance(s, dict) and (s.get("source_span_id") or s.get("span_id") or s.get("id"))
    }
    rows = results_data.get("results", []) if isinstance(results_data, dict) else results_data
    touched = prefill(rows, merged or {}, spans)
    if touched:
        review_io.atomic_write_json(d / "results.json", results_data)
    print(f"prefilled source_span_ids on {len(touched)} unjudged row(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
