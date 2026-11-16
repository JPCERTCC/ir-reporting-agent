#!/usr/bin/env python3
"""Create the official checklist-results template for a review run.

This script does not evaluate the report. It only expands the selected
checklist into the canonical ``results.json`` shape so the Agent can fill every
item without inventing one-off evaluator scripts.

Usage:
    python init_results_template.py --mode customer --out reviews/Report/run/results.json
    python init_results_template.py --mode reporter --out reviews/Report/run/results.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import parse_checklists
import review_io


def build_template(skill_dir: Path, mode: str) -> dict:
    ref = skill_dir / "references"
    sources = {
        "customer": (ref / "checklist_customer.md", "customer", "CUS"),
        "reporter": (ref / "checklist_reporter.md", "reporter", "REP"),
    }
    path, source, prefix = sources[mode]
    if not path.exists():
        raise FileNotFoundError(f"checklist not found: {path}")

    items = parse_checklists.parse_markdown(path, source, prefix)
    return {
        "metadata": {
            "schema_version": "1.0",
            "mode": mode,
            "note": (
                "This is an Agent-filled checklist review template. "
                "The template generator does not evaluate the report."
            ),
        },
        "results": [
            {
                "checklist_id": item["id"],
                "section": item["section"],
                "item": item["text"],
                "detail": item.get("detail", ""),
                "level": item.get("level", "-"),
                "requirement_level": item.get("requirement_level", "unspecified"),
                "applies_to": item.get("applies_to"),
                "evaluable_from_report": item.get("evaluable_from_report", True),
                "unknown_allowed": item.get("unknown_allowed", False),
                "verdict": None,
                "applicability": "applicable",
                "rationale": "",
                "source_span_ids": [],
                "absence_check_ids": [],
                "unknown_reason": None,
                "external_confirmation_needed": "",
            }
            for item in items
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill-dir", type=Path,
                        default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--mode", choices=("customer", "reporter"), required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    try:
        data = build_template(args.skill_dir, args.mode)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    review_io.atomic_write_json(args.out, data)
    print(f"wrote {len(data['results'])} checklist result rows to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
