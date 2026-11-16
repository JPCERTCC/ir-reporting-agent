#!/usr/bin/env python3
"""Verify a checklist review covers every checklist item.

The point of a checklist-based QA tool is thoroughness: no item silently
skipped. This script cross-checks the agent's per-item results against the
parsed checklist and fails if any item is missing or has an invalid verdict.

Inputs:
  --skill-dir  the ir-review-report skill directory (to find the checklists)
  --results    JSON file the agent wrote: {"results": [{"id","verdict",...}]}

Allowed verdicts: met | partial | not_met | not_applicable | unknown
  - unknown is legitimate only for checklist items whose definition explicitly
    allows out-of-report confirmation. Report-content items must be judged as
    met / partial / not_met / not_applicable from the report itself.

Exit code 1 if coverage is incomplete or verdicts are invalid.

Usage:
    python check_coverage.py --skill-dir <dir> --results <results.json> \
        [--mode customer|reporter|both|auto]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import review_io

VALID = {"met", "partial", "not_met", "not_applicable", "unknown"}
REASONS_FOR_UNKNOWN = {
    "external_information_missing",
    "applicability_unknown",
    "extraction_incomplete",
}


def result_id(result: dict) -> str | None:
    """Return the canonical checklist ID from new or legacy result objects."""
    return result.get("checklist_id") or result.get("id")


def result_rationale(result: dict) -> str:
    return str(result.get("rationale") or result.get("finding") or "").strip()


def is_formal_result(result: dict) -> bool:
    """New-schema results use checklist_id and explicit applicability fields."""
    return "checklist_id" in result or "evaluation_scope" in result or "applicability" in result


def load_checklist_ids(skill_dir: Path, mode: str) -> list[dict]:
    parser = skill_dir / "scripts" / "parse_checklists.py"
    out = subprocess.run(
        [
            sys.executable,
            str(parser),
            "--skill-dir",
            str(skill_dir),
            "--mode",
            mode,
        ],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print(out.stderr, file=sys.stderr)
        raise SystemExit(2)
    return json.loads(out.stdout)["items"]


def infer_mode(results: list[dict], requested: str) -> str:
    """Infer checklist mode from result IDs when --mode is omitted."""
    if requested != "auto":
        return requested
    ids = {
        result_id(r) for r in results
        if isinstance(r, dict) and result_id(r)
    }
    has_customer = any(str(i).startswith("CUS-") for i in ids)
    has_reporter = any(str(i).startswith("REP-") for i in ids)
    if has_customer and not has_reporter:
        return "customer"
    if has_reporter and not has_customer:
        return "reporter"
    return "both"


def main() -> int:
    review_io.require_via_review_status("check_coverage.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skill-dir", type=Path,
                    default=Path(__file__).resolve().parent.parent)
    ap.add_argument(
        "--mode",
        choices=("customer", "reporter", "both", "auto"),
        default="auto",
        help="Checklist set expected in results.json",
    )
    ap.add_argument("--results", required=True, type=Path)
    ap.add_argument("--summary-json", type=Path,
                    help="Write score/bucket summary JSON to this path")
    args = ap.parse_args()

    data = json.loads(args.results.read_text(encoding="utf-8"))
    results = data.get("results", data if isinstance(data, list) else [])
    mode = infer_mode(results, args.mode)
    items = load_checklist_ids(args.skill_dir, mode)
    checklist_ids = {i["id"] for i in items}
    item_by_id = {i["id"]: i for i in items}
    by_id: dict[str, dict] = {}
    duplicate_ids: list[str] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        rid = result_id(r)
        if rid in by_id:
            duplicate_ids.append(str(rid))
        elif rid:
            by_id[rid] = r

    problems: list[str] = []
    for did in sorted(set(duplicate_ids)):
        problems.append(f"duplicate result for {did}")

    missing = sorted(checklist_ids - set(by_id))
    for mid in missing:
        problems.append(f"missing verdict for {mid}")

    unknown_ids = sorted(set(by_id) - checklist_ids)
    for uid in unknown_ids:
        problems.append(f"result references unknown checklist id {uid!r}")

    for rid, r in by_id.items():
        if "id" in r and "checklist_id" in r and r["id"] != r["checklist_id"]:
            problems.append(
                f"{rid}: id and checklist_id disagree "
                f"({r['id']!r} != {r['checklist_id']!r})"
            )
        if r.get("evaluation_scope") == "out_of_scope":
            if r.get("verdict") is not None:
                problems.append(f"{rid}: out_of_scope result must have verdict null")
            if not result_rationale(r):
                problems.append(f"{rid}: out_of_scope result requires a rationale")
            continue
        verdict = r.get("verdict")
        if verdict not in VALID:
            problems.append(f"{rid}: invalid verdict {verdict!r} (allowed: {sorted(VALID)})")
        if verdict == "unknown":
            item = item_by_id.get(rid, {})
            if not item.get("unknown_allowed", False):
                problems.append(
                    f"{rid}: unknown is not allowed for report-content items; "
                    "use met/partial/not_met/not_applicable"
                )
        if verdict in ("not_met", "partial") and not result_rationale(r):
            problems.append(
                f"{rid}: verdict {verdict} requires a rationale/finding explaining the gap"
            )
        if is_formal_result(r):
            if r.get("applicability") not in (None, "applicable", "not_applicable", "unknown"):
                problems.append(f"{rid}: invalid applicability {r.get('applicability')!r}")
            if verdict == "unknown":
                reason = r.get("unknown_reason")
                if reason not in REASONS_FOR_UNKNOWN:
                    problems.append(
                        f"{rid}: unknown verdict requires unknown_reason in "
                        f"{sorted(REASONS_FOR_UNKNOWN)}"
                    )
                if not str(r.get("external_confirmation_needed") or "").strip():
                    problems.append(
                        f"{rid}: unknown verdict requires external_confirmation_needed "
                        "describing the out-of-report material to check"
                    )
            if verdict == "not_met" and "未記載" in result_rationale(r):
                if not r.get("absence_check_ids"):
                    problems.append(
                        f"{rid}: not_met based on absence requires absence_check_ids"
                    )

    total = len(checklist_ids)
    covered = len(checklist_ids & set(by_id))
    from collections import Counter
    dist = Counter(
        by_id[i].get("verdict") for i in (checklist_ids & set(by_id))
        if by_id[i].get("evaluation_scope") != "out_of_scope"
    )
    print(f"mode: {mode}")
    print(f"checklist items: {total}  covered: {covered}")
    print("verdict distribution:", dict(dist))

    # --- Scoring per the review policy -------------------------------------
    # unknown (needs out-of-report confirmation) and not_applicable are NOT
    # quality defects: both are excluded from every achievement denominator.
    # Optional (任意) shortfalls are improvement suggestions, not defects.
    level_of = {i["id"]: i.get("level", "-") for i in items}
    per_level: dict[str, Counter] = {}
    for cid in checklist_ids & set(by_id):
        if by_id[cid].get("evaluation_scope") == "out_of_scope":
            continue
        level = level_of.get(cid, "-")
        per_level.setdefault(level, Counter())[by_id[cid].get("verdict")] += 1

    def rate(counter: Counter) -> tuple[int, int]:
        met = counter.get("met", 0)
        denom = met + counter.get("partial", 0) + counter.get("not_met", 0)
        return met, denom

    scores = {}
    total_counter = Counter()
    for counter in per_level.values():
        total_counter.update(counter)
    print("\nachievement (denominator excludes unknown / not_applicable):")
    total_met, total_denom = rate(total_counter)
    total_pct = f"{100 * total_met / total_denom:.0f}%" if total_denom else "n/a"
    scores["all"] = {
        "met": total_met,
        "denominator": total_denom,
        "unknown": total_counter.get("unknown", 0),
        "not_applicable": total_counter.get("not_applicable", 0),
    }
    print(f"  all: {total_met}/{total_denom} ({total_pct})  "
          f"[unknown {total_counter.get('unknown', 0)}, "
          f"n/a {total_counter.get('not_applicable', 0)}]")
    for level in ("必須", "推奨", "任意", "-"):
        counter = per_level.get(level)
        if not counter:
            continue
        met, denom = rate(counter)
        pct = f"{100 * met / denom:.0f}%" if denom else "n/a"
        scores[level] = {
            "met": met, "denominator": denom,
            "unknown": counter.get("unknown", 0),
            "not_applicable": counter.get("not_applicable", 0),
        }
        print(f"  {level}: {met}/{denom} ({pct})  "
              f"[unknown {counter.get('unknown', 0)}, n/a {counter.get('not_applicable', 0)}]")

    buckets = {
        "quality_defects": sorted(
            cid for cid in checklist_ids & set(by_id)
            if by_id[cid].get("verdict") in ("not_met", "partial")
            and level_of.get(cid) in ("必須", "推奨", "-")
        ),
        "improvement_suggestions": sorted(
            cid for cid in checklist_ids & set(by_id)
            if by_id[cid].get("verdict") in ("not_met", "partial")
            and level_of.get(cid) == "任意"
        ),
        "external_confirmation_needed": sorted(
            cid for cid in checklist_ids & set(by_id)
            if by_id[cid].get("verdict") == "unknown"
        ),
    }
    print(f"quality defects (必須/推奨): {len(buckets['quality_defects'])}")
    print(f"improvement suggestions (任意): {len(buckets['improvement_suggestions'])}")
    print(f"external confirmation needed (unknown): "
          f"{len(buckets['external_confirmation_needed'])}")

    if problems:
        print(f"\nFAIL ({len(problems)}):")
        for p in problems[:40]:
            print(f"  - {p}")
        if len(problems) > 40:
            print(f"  ... and {len(problems) - 40} more")
        return 1

    if args.summary_json:
        review_io.atomic_write_json(
            args.summary_json,
            {"scores": scores, "buckets": buckets, "distribution": dict(dist)},
        )
        print(f"summary written: {args.summary_json}")
    print("\nPASS: every checklist item has a valid verdict")
    return 0


if __name__ == "__main__":
    sys.exit(main())
