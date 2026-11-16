#!/usr/bin/env python3
"""Catch a not_met/unknown verdict that discards a SubAgent's own observed span.

This is not a wording check — it never looks at what the rationale text
*says*. It compares two independent facts: what a checklist item's row in
results.json is grounded in (source_span_ids), and what SubAgent(s) actually
observed for that same checklist item while reading the report
(aggregation_worksheet.json, itself built from merged_observations.json).

If a row is judged "not_met" / "unknown" with *no* source_span_ids (i.e. the
agent is claiming the item is simply absent from the report), but one or more
SubAgents did record an observation with a real source_span_id for that same
checklist item, the absence claim contradicts evidence that already exists.
Either the row should cite that span (and possibly a different verdict), or
the rationale should say why that particular span does not satisfy the item
— either way, silently dropping it is not acceptable.

When no SubAgent observation carries a span for an item (including the
common case of zero observations at all — genuinely nothing was found by any
independent reader), this check has nothing to compare against and stays
silent. It never asks for extra evidence just because a verdict is absence
-based; it only objects when real, already-collected evidence is being
ignored.

Usage:
    python check_absence_grounding.py --results results.json \
        --worksheet aggregation_worksheet.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import review_io

ABSENCE_VERDICTS = {"not_met", "unknown"}


def _load(path: Path) -> dict:
    data, error = review_io.load_json_safe(path)
    if error is not None:
        raise ValueError(f"{path}: {error}")
    return data if isinstance(data, dict) else {}


def result_id(result: dict) -> str | None:
    return result.get("checklist_id") or result.get("id")


def observed_spans_by_id(worksheet: dict) -> dict[str, list[str]]:
    by_id: dict[str, list[str]] = {}
    for group in worksheet.get("checklist_items", []):
        if not isinstance(group, dict):
            continue
        cid = group.get("checklist_id")
        if not cid:
            continue
        spans: list[str] = []
        for obs in group.get("observations", []):
            for sid in obs.get("source_span_ids") or []:
                if sid not in spans:
                    spans.append(sid)
        if spans:
            by_id[str(cid)] = spans
    return by_id


def check(results: list[dict], worksheet: dict) -> list[str]:
    observed = observed_spans_by_id(worksheet)
    problems: list[str] = []
    for row in results:
        if not isinstance(row, dict):
            continue
        cid = result_id(row)
        if not cid or row.get("evaluation_scope") == "out_of_scope":
            continue
        if row.get("verdict") not in ABSENCE_VERDICTS:
            continue
        if row.get("source_span_ids"):
            continue  # already grounded in a span; nothing to cross-check
        spans = observed.get(cid)
        if not spans:
            continue  # no SubAgent observation had a span either — silent
        problems.append(
            f"{cid}: verdict {row.get('verdict')!r} has no source_span_ids, but "
            f"SubAgent observation(s) cite {spans} for this item — cite the span "
            "in source_span_ids, or explain in rationale why it does not satisfy "
            "this item; do not drop an observed span silently"
        )
    return problems


def main() -> int:
    review_io.require_via_review_status("check_absence_grounding.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", required=True, type=Path)
    ap.add_argument("--worksheet", required=True, type=Path)
    args = ap.parse_args()

    try:
        results_data = _load(args.results)
        worksheet = _load(args.worksheet)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    results = results_data.get("results", results_data if isinstance(results_data, list) else [])

    problems = check(results, worksheet)
    if problems:
        print(f"FAIL ({len(problems)}):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"PASS: {len(results)} results checked, no dropped observed spans")
    return 0


if __name__ == "__main__":
    sys.exit(main())
