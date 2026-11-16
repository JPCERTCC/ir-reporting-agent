#!/usr/bin/env python3
"""Lint a drafted Japanese incident report — every problem in one pass.

Structure (template headings, watermark, reviewer fill-in sections, wording,
defang, dates), unwritten 【要記入】 skeleton markers, carry-over of the
analysis results and limitation gaps approved at CP2, and grounding against
reports/case_material.json (evidence IDs, verbatim chapter-4 excerpts, IP
addresses). The checks live in ir_agent.reporting.draft_lint so that
``ir-agent check-draft`` applies exactly the same gate. Exit code 1 on any
failure.

Usage:
    python lint_draft.py --case-dir <case> [--draft reports/draft_report.md]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make the repository's ir_agent package importable without an install.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ir_agent.reporting.draft_lint import lint_case  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", required=True, type=Path)
    parser.add_argument("--draft", type=Path, default=None)
    args = parser.parse_args()

    draft_path = args.draft or args.case_dir / "reports" / "draft_report.md"
    if not draft_path.exists():
        print(f"error: draft not found: {draft_path}")
        return 2
    result = lint_case(args.case_dir, draft_path)
    for message in result.warnings:
        print(f"warning: {message}")
    if result.failures:
        print(f"\nFAIL ({len(result.failures)}):")
        for message in result.failures:
            print(f"  - {message}")
        return 1
    print("\nPASS: draft satisfies structural and grounding checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
