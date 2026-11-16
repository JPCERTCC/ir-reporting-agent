#!/usr/bin/env python3
"""Validate semantic assessments of the report's major conclusions.

This script does not decide whether a conclusion is supported. The agent/LLM
does that with reasons. The script only checks that each assessment is typed,
grounded to real source spans or absence checks, and uses the agreed verdict
taxonomy.

Usage:
    python check_claim_assessments.py --assessments claim_assessments.json \
        [--source-index source_index.json] [--absence-checks absence_checks.json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import review_io
from review_io import load_json_safe

# init_claims_skeleton.py leaves this marker in fields that need the Agent's
# judgment; a row still containing it must never reach the final review.
SKELETON_PLACEHOLDER = "【要記入】"
STATED_CONFIDENCE = {"confirmed", "highly_likely", "possible", "unknown", "negative"}
REVIEW_VERDICTS = {"supported", "partially_supported", "unsupported", "not_assessable"}
MAJOR_TOPICS = {
    "initial_access",
    "scope",
    "lateral_movement",
    "persistence",
    "c2_external",
    "exfiltration",
    "impact",
    "limitations",
    "recommendations",
    "other",
}
REQUIRED_INVENTORY_TOPICS = {
    "initial_access",
    "scope",
    "lateral_movement",
    "persistence",
    "c2_external",
    "exfiltration",
    "impact",
    "limitations",
    "recommendations",
}
CONCLUSION_PRESENCE = {"reported", "not_reported", "not_applicable", "not_assessable"}
CONSISTENCY_VERDICTS = {
    "consistent",
    "minor_inconsistency",
    "major_inconsistency",
    "not_assessable",
}
REC_VERDICTS = {"mapped", "partially_mapped", "not_mapped", "not_assessable"}


def load_id_set(path: Path | None, key: str, fields: tuple[str, ...]) -> set[str] | None:
    if path is None:
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    ids = set()
    for row in data.get(key, []):
        if not isinstance(row, dict):
            continue
        for field in fields:
            if row.get(field):
                ids.add(str(row[field]))
                break
    return ids


def require_fields(row: dict, fields: list[str], label: str, problems: list[str]) -> bool:
    missing = [f for f in fields if f not in row]
    if missing:
        problems.append(f"{label}: missing fields {missing}")
        return False
    return True


def check_ids(label: str, field: str, values: list[str], known: set[str] | None,
              problems: list[str]) -> None:
    if known is None:
        return
    unknown = [v for v in values if v not in known]
    if unknown:
        problems.append(f"{label}: unknown {field} {unknown}")


_GENERIC_CONCLUSION_PATTERNS = (
    re.compile(r"^.{0,12}(に関する)?記載(がある|が確認できる|があります)。?$"),
    re.compile(r"^.{0,12}について(記載されている|言及がある)。?$"),
)


def _is_generic_conclusion_text(topic: str, text: str) -> bool:
    """Reject a stated_conclusion that just restates the topic label.

    A conclusion like "報告書にinitial_accessに関する記載がある" tells the
    reader nothing an Agent couldn't have produced without reading the report
    (it doesn't say what was found — which host, which technique, which
    confidence). Concrete text ("Citrix NetScalerの脆弱性悪用によりUNS40-76へ
    初期侵入された可能性が高い") is required instead. This only catches the
    worst, mechanically-detectable case (the raw topic identifier leaking into
    Japanese prose, or a bare "there is a mention of X" template) — it is not
    a substitute for an Agent actually reading the source_span_ids.
    """
    compact = re.sub(r"\s+", "", text or "")
    if not compact:
        return True
    if topic and topic in compact:
        return True
    return any(p.fullmatch(compact) for p in _GENERIC_CONCLUSION_PATTERNS)


def list_field(row: dict, field: str, label: str, problems: list[str]) -> list[str]:
    value = row.get(field)
    if value is None:
        return []
    if not isinstance(value, list):
        problems.append(f"{label}: {field} must be a list")
        return []
    return [str(v) for v in value]


def main() -> int:
    review_io.require_via_review_status("check_claim_assessments.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--assessments", required=True, type=Path)
    ap.add_argument("--source-index", type=Path)
    ap.add_argument("--absence-checks", type=Path)
    ap.add_argument(
        "--issues", type=Path,
        help="issues.json; issue_ids must be real issues that refer back to the assessment",
    )
    ap.add_argument(
        "--merged-observations", type=Path,
        help="merged_observations.json; a not_reported topic that SubAgents observed "
             "with spans must carry an override_reason",
    )
    args = ap.parse_args()

    data = json.loads(args.assessments.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        print("error: assessments top-level must be an object", file=sys.stderr)
        return 2
    assessments = data.get("claim_assessments", [])
    inventory = data.get("conclusion_inventory", [])
    consistency = data.get("consistency_assessments", [])
    recommendations = data.get("recommendation_assessments", [])
    source_ids = load_id_set(args.source_index, "spans", ("source_span_id", "span_id", "id"))
    absence_ids = load_id_set(args.absence_checks, "absence_checks", ("absence_check_id", "id"))

    problems: list[str] = []
    if not isinstance(inventory, list) or not inventory:
        problems.append("conclusion_inventory: required major-conclusion inventory is missing")
        inventory = [] if not isinstance(inventory, list) else inventory
    if not isinstance(consistency, list) or not consistency:
        problems.append("consistency_assessments: at least one cross-conclusion consistency assessment is required")
        consistency = [] if not isinstance(consistency, list) else consistency
    if not isinstance(assessments, list) or not assessments:
        problems.append("claim_assessments: at least one major-conclusion assessment is required")
        assessments = [] if not isinstance(assessments, list) else assessments
    if not isinstance(recommendations, list):
        problems.append("recommendation_assessments: must be a list")
        recommendations = []

    assessment_ids = {
        str(a.get("assessment_id")) for a in assessments
        if isinstance(a, dict) and a.get("assessment_id")
    }
    # topic each assessment actually assesses, for the cross-topic reuse check below.
    assessment_topic = {
        str(a.get("assessment_id")): a.get("topic") for a in assessments
        if isinstance(a, dict) and a.get("assessment_id")
    }

    inv_seen: set[str] = set()
    inventory_topics: set[str] = set()
    conclusion_ids: set[str] = set()
    for idx, row in enumerate(inventory):
        label = row.get("conclusion_id") or f"<conclusion_inventory[{idx}]>"
        if not require_fields(row, [
            "conclusion_id", "topic", "presence", "stated_conclusion",
        ], label, problems):
            continue
        if row["conclusion_id"] in inv_seen:
            problems.append(f"{label}: duplicate conclusion_id")
        inv_seen.add(row["conclusion_id"])
        conclusion_ids.add(str(row["conclusion_id"]))
        topic = row["topic"]
        inventory_topics.add(str(topic))
        if topic not in MAJOR_TOPICS:
            problems.append(f"{label}: topic {topic!r} invalid")
        presence = row["presence"]
        if presence not in CONCLUSION_PRESENCE:
            problems.append(f"{label}: presence {presence!r} invalid")
        spans = list_field(row, "source_span_ids", label, problems)
        absence = list_field(row, "absence_check_ids", label, problems)
        check_ids(label, "source_span_ids", spans, source_ids, problems)
        check_ids(label, "absence_check_ids", absence, absence_ids, problems)
        linked_assessments = list_field(row, "assessment_ids", label, problems)
        check_ids(label, "assessment_ids", linked_assessments, assessment_ids, problems)
        if presence == "reported":
            if not spans:
                problems.append(f"{label}: reported conclusion requires source_span_ids")
            if not linked_assessments:
                problems.append(f"{label}: reported conclusion requires assessment_ids")
            else:
                # A reported conclusion's own topic (persistence, c2_external, ...) must
                # have at least one assessment that actually assesses THAT topic. Linking
                # only another topic's assessment_id (e.g. reusing the "scope" assessment
                # for a "persistence" conclusion because it's non-empty) satisfies the
                # schema check above but leaves the conclusion itself never evaluated —
                # this is an ID/topic cross-check, not a wording check, so it cannot be
                # dodged by rephrasing text.
                known_linked = [a for a in linked_assessments if a in assessment_ids]
                if known_linked and all(
                    assessment_topic.get(a) not in (topic, "other") for a in known_linked
                ):
                    reused_topics = sorted({
                        str(assessment_topic.get(a)) for a in known_linked
                    })
                    problems.append(
                        f"{label}: assessment_ids {known_linked} are assessments of "
                        f"{reused_topics}, not of this conclusion's own topic {topic!r} — "
                        "a reported conclusion needs its own claim_assessments entry "
                        "(topic must match); reusing another topic's assessment_id does "
                        "not count as evaluating this conclusion"
                    )
            if _is_generic_conclusion_text(str(topic), str(row.get("stated_conclusion") or "")):
                problems.append(
                    f"{label}: stated_conclusion is too generic "
                    "(topic ラベルの言い換えではなく、対象ホスト・手法・時刻・確度を"
                    "含む具体的な結論を書いてください)"
                )
        elif presence == "not_reported":
            if not absence:
                problems.append(f"{label}: not_reported conclusion requires absence_check_ids")

    missing_topics = sorted(REQUIRED_INVENTORY_TOPICS - inventory_topics)
    if missing_topics:
        problems.append(
            "conclusion_inventory: required topics are missing "
            f"{missing_topics}; use not_reported/not_applicable when appropriate"
        )

    topic_rows: dict[str, list[dict]] = {}
    for row in inventory:
        if isinstance(row, dict) and row.get("topic") in REQUIRED_INVENTORY_TOPICS:
            topic_rows.setdefault(str(row["topic"]), []).append(row)
    for topic, rows in sorted(topic_rows.items()):
        if len(rows) > 1:
            problems.append(
                f"conclusion_inventory: topic {topic!r} appears in {len(rows)} rows "
                f"{[r.get('conclusion_id') for r in rows]} "
                f"(presence: {[r.get('presence') for r in rows]}) — each topic must appear "
                "exactly once"
            )

    if args.merged_observations and args.merged_observations.exists():
        merged, merged_error = load_json_safe(args.merged_observations)
        observed_topics: dict[str, list[str]] = {}
        if merged_error is None and isinstance(merged, dict):
            for obs in merged.get("conclusion_observations", []):
                if isinstance(obs, dict) and obs.get("topic") and obs.get("source_span_ids"):
                    observed_topics.setdefault(str(obs["topic"]), []).append(
                        str(obs.get("observation_id"))
                    )
        for row in inventory:
            if not isinstance(row, dict) or row.get("presence") != "not_reported":
                continue
            observed = observed_topics.get(str(row.get("topic")))
            if observed and not str(row.get("override_reason") or "").strip():
                problems.append(
                    f"{row.get('conclusion_id')}: topic {row.get('topic')!r} is not_reported, "
                    f"but SubAgent observations {observed[:5]} cite spans for it — "
                    "set presence to reported and use those spans, or give the reason the "
                    "observations do not count in override_reason"
                )

    placeholder_rows = [
        str(row.get(key) or f"<{name}[{i}]>")
        for name, key, rows in (
            ("conclusion_inventory", "conclusion_id", inventory),
            ("claim_assessments", "assessment_id", assessments),
            ("consistency_assessments", "consistency_id", consistency),
            ("recommendation_assessments", "recommendation_id", recommendations),
        )
        for i, row in enumerate(rows) if isinstance(row, dict)
        if SKELETON_PLACEHOLDER in json.dumps(row, ensure_ascii=False)
    ]
    if placeholder_rows:
        problems.append(
            f"still contains {SKELETON_PLACEHOLDER} in: {', '.join(placeholder_rows)} — "
            "雛形の未記入フィールド(review_verdict / *_assessment / reason 等)を、"
            "根拠 span を読んで実際の評価に置き換えてください"
        )

    seen: set[str] = set()
    for idx, row in enumerate(assessments):
        label = row.get("assessment_id") or f"<claim_assessments[{idx}]>"
        if not require_fields(row, [
            "assessment_id", "topic", "conclusion", "stated_confidence",
            "review_verdict", "reason",
        ], label, problems):
            continue
        if row["assessment_id"] in seen:
            problems.append(f"{label}: duplicate assessment_id")
        seen.add(row["assessment_id"])
        if row["topic"] not in MAJOR_TOPICS:
            problems.append(f"{label}: topic {row['topic']!r} invalid")
        if "limitations" in row and not isinstance(row["limitations"], (list, str)):
            problems.append(f"{label}: limitations must be a list of strings (or a string)")
        if row["stated_confidence"] not in STATED_CONFIDENCE:
            problems.append(f"{label}: stated_confidence {row['stated_confidence']!r} invalid")
        if row["review_verdict"] not in REVIEW_VERDICTS | {SKELETON_PLACEHOLDER}:
            problems.append(f"{label}: review_verdict {row['review_verdict']!r} invalid")
        spans = list_field(row, "source_span_ids", label, problems)
        absence = list_field(row, "absence_check_ids", label, problems)
        if not spans and not absence:
            problems.append(f"{label}: source_span_ids or absence_check_ids is required")
        check_ids(label, "source_span_ids", spans, source_ids, problems)
        check_ids(label, "absence_check_ids", absence, absence_ids, problems)
        if row["review_verdict"] in ("partially_supported", "unsupported"):
            issue_ids = list_field(row, "issue_ids", label, problems)
            if not issue_ids:
                problems.append(f"{label}: unsupported/partial assessment requires issue_ids")

    linked_from_inventory = {
        str(aid)
        for row in inventory if isinstance(row, dict)
        for aid in (row.get("assessment_ids") if isinstance(row.get("assessment_ids"), list) else [])
    }
    orphan_assessments = sorted(assessment_ids - linked_from_inventory)
    if orphan_assessments and inventory:
        problems.append(
            "claim_assessments: assessments not linked from conclusion_inventory "
            f"{orphan_assessments}"
        )

    consistency_seen: set[str] = set()
    for idx, row in enumerate(consistency):
        label = row.get("consistency_id") or f"<consistency_assessments[{idx}]>"
        if not require_fields(row, [
            "consistency_id", "related_conclusion_ids", "consistency_verdict",
            "reason",
        ], label, problems):
            continue
        if row["consistency_id"] in consistency_seen:
            problems.append(f"{label}: duplicate consistency_id")
        consistency_seen.add(row["consistency_id"])
        if row["consistency_verdict"] not in CONSISTENCY_VERDICTS | {SKELETON_PLACEHOLDER}:
            problems.append(
                f"{label}: consistency_verdict {row['consistency_verdict']!r} invalid"
            )
        related = list_field(row, "related_conclusion_ids", label, problems)
        if not isinstance(related, list) or len(related) < 2:
            problems.append(f"{label}: related_conclusion_ids must contain at least two IDs")
        check_ids(label, "related_conclusion_ids", related, conclusion_ids, problems)
        spans = list_field(row, "source_span_ids", label, problems)
        absence = list_field(row, "absence_check_ids", label, problems)
        if not spans and not absence:
            problems.append(f"{label}: source_span_ids or absence_check_ids is required")
        check_ids(label, "source_span_ids", spans, source_ids, problems)
        check_ids(label, "absence_check_ids", absence, absence_ids, problems)
        if row["consistency_verdict"] in ("minor_inconsistency", "major_inconsistency"):
            issue_ids = list_field(row, "issue_ids", label, problems)
            if not issue_ids:
                problems.append(f"{label}: inconsistency assessment requires issue_ids")

    rec_seen: set[str] = set()
    for idx, row in enumerate(recommendations):
        label = row.get("recommendation_id") or f"<recommendation_assessments[{idx}]>"
        if not require_fields(row, [
            "recommendation_id", "recommendation", "review_verdict",
            "linked_finding_ids", "reason",
        ], label, problems):
            continue
        if row["recommendation_id"] in rec_seen:
            problems.append(f"{label}: duplicate recommendation_id")
        rec_seen.add(row["recommendation_id"])
        if row["review_verdict"] not in REC_VERDICTS | {SKELETON_PLACEHOLDER}:
            problems.append(
                f"{label}: review_verdict {row['review_verdict']!r} invalid "
                f"(allowed for recommendations: {sorted(REC_VERDICTS)})"
            )
        linked = list_field(row, "linked_finding_ids", label, problems)
        unknown_links = [i for i in linked if i not in assessment_ids]
        if unknown_links:
            problems.append(
                f"{label}: linked_finding_ids not found: {unknown_links} "
                "— linked_finding_ids must reference claim_assessments[].assessment_id "
                "(ASM-*), not conclusion_inventory[].conclusion_id (CON-*)"
            )

    if args.issues and args.issues.exists():
        issues_data, issues_error = load_json_safe(args.issues)
        issue_list = (
            issues_data.get("issues") if isinstance(issues_data, dict) else issues_data
        ) if issues_error is None else None
        if isinstance(issue_list, list):
            refs: dict[str, set[str]] = {}
            for issue in issue_list:
                if not isinstance(issue, dict) or not issue.get("issue_id"):
                    continue
                refs[str(issue["issue_id"])] = {
                    *map(str, issue.get("assessment_ids") or []),
                    *map(str, issue.get("recommendation_ids") or []),
                }
            for array, id_field in (
                ("claim_assessments", "assessment_id"),
                ("consistency_assessments", "consistency_id"),
                ("recommendation_assessments", "recommendation_id"),
            ):
                for row in data.get(array, []) or []:
                    if not isinstance(row, dict) or not isinstance(row.get("issue_ids"), list):
                        continue
                    rid = str(row.get(id_field))
                    for issue_id in map(str, row["issue_ids"]):
                        if issue_id not in refs:
                            problems.append(
                                f"{rid}: issue_ids {issue_id!r} is not an issue in issues.json"
                            )

    result = {
        "conclusion_inventory": len(inventory),
        "consistency_assessments": len(consistency),
        "claim_assessments": len(assessments),
        "recommendation_assessments": len(recommendations),
        "problems": problems,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
