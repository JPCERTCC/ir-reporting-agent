#!/usr/bin/env python3
"""Give every weak assessment its own issue and keep ``issue_ids`` truthful.

claim_assessments.json rows judged ``partially_supported`` / ``unsupported``
(and inconsistent consistency rows, unmapped recommendations) must point at an
issue that tells the requester what is wrong. Left to the Agent, ``issue_ids``
became whatever passed the check: two unrelated issues reused for four
conclusions, then SubAgent observation ids (``OBS-…``) that are not issues at
all. That is bookkeeping, not judgment, so this script does it:

  * every issue in issues.json gets a local ``issue_id`` (ISS-001, …) if it
    has none — existing ids are kept
  * for each weak assessment without an issue of its own, a dedicated issue is
    created (``assessment_ids`` / ``recommendation_ids`` carry the link; span,
    observation ids and reason are copied from the assessment)
  * each row's ``issue_ids`` becomes: its own issue(s) plus any id the Agent
    wrote that really exists in issues.json. Ids that do not exist (for
    example observation ids) are dropped and reported
  * a dedicated issue this script created earlier is removed again when the
    Agent has since judged the assessment ``supported``

The Agent never writes ``issue_ids``. Only issues created here carry
``auto_for``; issues the Agent wrote are never touched except for the id.

Usage (run by review_status.py):
    python link_assessment_issues.py --review-dir reviews/Report/run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import check_issues
import review_io

# (array, id field, weak verdicts, issue category, severity by verdict, link field)
RULES = [
    ("claim_assessments", "assessment_id", {"partially_supported": "medium", "unsupported": "high"},
     "unsupported_claim", "assessment_ids"),
    ("consistency_assessments", "consistency_id",
     {"minor_inconsistency": "low", "major_inconsistency": "high"},
     "cross_section_inconsistency", "assessment_ids"),
    ("recommendation_assessments", "recommendation_id",
     {"partially_mapped": "medium", "not_mapped": "high"},
     "countermeasure_mapping", "recommendation_ids"),
]
VERDICT_FIELD = {
    "claim_assessments": "review_verdict",
    "consistency_assessments": "consistency_verdict",
    "recommendation_assessments": "review_verdict",
}


def _clip(text: Any, n: int = 70) -> str:
    t = " ".join(str(text or "").split())
    return t if len(t) <= n else t[: n - 1] + "…"


def _next_id(existing: set[str], counter: list[int]) -> str:
    while True:
        counter[0] += 1
        candidate = f"ISS-{counter[0]:03d}"
        if candidate not in existing:
            existing.add(candidate)
            return candidate


def _new_issue(array: str, row: dict, rid: str, verdict: str, severity: str,
               category: str, link_field: str, spans: dict[str, dict]) -> dict:
    span_ids = [
        s for s in dict.fromkeys(row.get("source_span_ids") or [])
        if s in spans and not check_issues._is_non_substantive_span(spans[s])
    ]
    topic = row.get("topic") or ""
    subject = _clip(
        row.get("conclusion") or row.get("recommendation")
        or f"{row.get('related_conclusion_ids', '')}", 70)
    reason = str(row.get("reason") or "").strip() or f"{rid} は {verdict} と評価された"
    if array == "claim_assessments":
        revision = (
            f"主要結論（{topic}）「{subject}」について、根拠となる調査結果・ログを本文に示すか、"
            "確度表現を根拠に見合う強さに改める"
        )
    elif array == "consistency_assessments":
        revision = str(row.get("suggested_revision") or "").strip() or (
            "主要結論の間で食い違っている記述（サマリーと詳細章、時系列など）をそろえる")
    else:
        revision = str(row.get("suggested_revision") or "").strip() or (
            f"推奨対策「{subject}」を、対応する調査結果・未確認事項・残存リスクに紐づけて示す")
    issue: dict[str, Any] = {
        "category": category,
        "severity": severity,
        "checklist_ids": [],
        link_field: [rid],
        "source_span_ids": span_ids,
        "absence_check_ids": [] if span_ids else [f"ABS-{rid}"],
        "reason": reason,
        "suggested_revision": revision,
        "auto_for": rid,
        "auto_filled": ["category", "severity", "assessment link", "source_span_ids",
                        "reason", "suggested_revision"],
    }
    if row.get("source_observation_ids"):
        issue["source_observation_ids"] = list(row["source_observation_ids"])
    return issue


def link(claims: dict, issues: list[dict], spans: dict[str, dict]) -> dict[str, Any]:
    """Mutates ``claims`` and ``issues``; returns a report of what changed."""
    report: dict[str, Any] = {"created": [], "removed": [], "dropped": [], "assigned": 0}

    existing_ids = {str(i["issue_id"]) for i in issues if i.get("issue_id")}
    counter = [0]
    for issue in issues:
        if not issue.get("issue_id"):
            issue["issue_id"] = _next_id(existing_ids, counter)
            report["assigned"] += 1

    weak: dict[str, tuple[str, dict, str, str, str, str]] = {}
    for array, id_field, verdicts, category, link_field in RULES:
        for row in claims.get(array, []) or []:
            if not isinstance(row, dict) or not row.get(id_field):
                continue
            verdict = row.get(VERDICT_FIELD[array])
            if verdict in verdicts:
                weak[str(row[id_field])] = (
                    array, row, str(verdict), verdicts[verdict], category, link_field)

    # an auto issue whose assessment is no longer weak goes away
    kept: list[dict] = []
    for issue in issues:
        target = issue.get("auto_for")
        if target and target not in weak:
            report["removed"].append(issue["issue_id"])
            continue
        kept.append(issue)
    issues[:] = kept

    def issue_links(rid: str) -> list[str]:
        return [
            str(i["issue_id"]) for i in issues
            if rid in (i.get("assessment_ids") or []) or rid in (i.get("recommendation_ids") or [])
        ]

    for rid, (array, row, verdict, severity, category, link_field) in weak.items():
        if not issue_links(rid):
            issue = _new_issue(array, row, rid, verdict, severity, category, link_field, spans)
            issue["issue_id"] = _next_id(existing_ids, counter)
            issues.append(issue)
            report["created"].append((rid, issue["issue_id"]))

    valid = {str(i["issue_id"]) for i in issues}
    for array, id_field, _v, _c, _l in RULES:
        for row in claims.get(array, []) or []:
            if not isinstance(row, dict) or not row.get(id_field):
                continue
            rid = str(row[id_field])
            own = issue_links(rid)
            given = [str(x) for x in row.get("issue_ids") or []]
            for x in given:
                if x not in valid:
                    report["dropped"].append((rid, x))
            new_ids = list(dict.fromkeys(own + [x for x in given if x in valid]))
            if new_ids or "issue_ids" in row:
                row["issue_ids"] = new_ids
    return report


def main() -> int:
    review_io.require_via_review_status("link_assessment_issues.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--review-dir", required=True, type=Path)
    args = ap.parse_args()
    d = args.review_dir

    claims, e1 = review_io.load_json_safe(d / "claim_assessments.json")
    issues_data, e2 = review_io.load_json_safe(d / "issues.json")
    source_index, e3 = review_io.load_json_safe(d / "source_index.json")
    for name, err in (("claim_assessments.json", e1), ("issues.json", e2),
                      ("source_index.json", e3)):
        if err is not None:
            print(f"error: {d / name}: {err}", file=sys.stderr)
            return 2
    if not isinstance(claims, dict):
        print("error: claim_assessments.json must be a JSON object", file=sys.stderr)
        return 2
    wrapped = isinstance(issues_data, dict)
    issues = issues_data.get("issues") if wrapped else issues_data
    if not isinstance(issues, list):
        print("error: issues.json has no issues list", file=sys.stderr)
        return 2
    spans = {
        str(s.get("source_span_id") or s.get("span_id") or s.get("id")): s
        for s in (source_index or {}).get("spans", [])
        if isinstance(s, dict) and (s.get("source_span_id") or s.get("span_id") or s.get("id"))
    }

    report = link(claims, issues, spans)
    if report["created"] or report["removed"] or report["dropped"] or report["assigned"]:
        review_io.atomic_write_json(d / "claim_assessments.json", claims)
        review_io.atomic_write_json(d / "issues.json", issues_data if wrapped else issues)
    print(
        f"assigned {report['assigned']} issue_id(s); created {len(report['created'])} issue(s) "
        f"for weak assessments; removed {len(report['removed'])} stale auto issue(s); "
        f"dropped {len(report['dropped'])} invalid issue_ids"
    )
    for rid, issue_id in report["created"]:
        print(f"  {rid} -> {issue_id}")
    for rid, bad in report["dropped"]:
        print(f"  dropped {bad!r} from {rid}.issue_ids (not an issue in issues.json)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
