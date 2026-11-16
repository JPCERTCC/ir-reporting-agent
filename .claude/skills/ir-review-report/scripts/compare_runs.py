#!/usr/bin/env python3
"""Diff two review runs for reproducibility evaluation.

Issue IDs are content-derived (check_issues.py), so re-running the review on
the same report should mostly reproduce the same IDs. This tool compares two
normalized issue files (and optionally their summaries) and reports what was
added, removed, or changed — run_metadata is ignored so only substantive
differences count.

Usage:
    python compare_runs.py --a run1/issues.json --b run2/issues.json
        [--summary-a run1/summary.json --summary-b run2/summary.json]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_issues(path: Path) -> dict[str, dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    issues = data.get("issues", data if isinstance(data, list) else [])
    return {i["issue_id"]: i for i in issues if "issue_id" in i}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--a", required=True, type=Path)
    ap.add_argument("--b", required=True, type=Path)
    ap.add_argument("--summary-a", type=Path)
    ap.add_argument("--summary-b", type=Path)
    args = ap.parse_args()

    a, b = load_issues(args.a), load_issues(args.b)
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = sorted(
        i for i in set(a) & set(b)
        if any(a[i].get(k) != b[i].get(k)
               for k in ("severity", "status", "category", "reason"))
    )
    out: dict = {
        "issues": {
            "a_total": len(a), "b_total": len(b),
            "stable": len(set(a) & set(b)) - len(changed),
            "added_in_b": added, "removed_in_b": removed, "changed": changed,
        }
    }
    if args.summary_a and args.summary_b:
        sa = json.loads(args.summary_a.read_text(encoding="utf-8"))
        sb = json.loads(args.summary_b.read_text(encoding="utf-8"))
        sa.pop("run_metadata", None)
        sb.pop("run_metadata", None)
        out["summary_identical"] = sa == sb
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    main()
