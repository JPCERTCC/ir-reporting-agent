#!/usr/bin/env python3
"""Create a claim_assessments.json skeleton from SubAgent conclusion observations.

The major-conclusion inventory is the part of a review that lost the most
information between the SubAgents and the final file: topics that SubAgents
had observed with spans (persistence, c2_external, ...) came out as
"not_reported", one topic appeared twice with contradicting presence, and one
assessment was reused for unrelated topics. All of that is mechanical
bookkeeping over ``conclusion_observations`` — not judgment — so this script
does it, and the Agent only writes the assessments.

What it derives (from merged_observations.json + source_index.json):

  * conclusion_inventory: exactly one row per required topic, in a fixed order.
      - a topic with SubAgent observations that carry real spans is "reported",
        with the observed spans / conclusion text / observation ids copied in
        and an assessment of its own (ASM-*, same topic) already linked
      - a topic no SubAgent observed is "not_reported" with ``ABS-CON-<topic>``
  * claim_assessments: one ASM per reported topic (topic matches by design)
  * recommendation_assessments: one REC when recommendations are reported
  * consistency_assessments: one CNS across the reported findings

What it leaves for the Agent (marked ``【要記入】``): the verdicts and the
written assessment — ``review_verdict`` and one ``reason`` per row (the
reason covers evidence, logic and confidence together). an optional
``limitations`` list (what the report admits it could not establish) may be
added; the table shows that column only when it is used.
check_claim_assessments.py rejects any row that still contains the marker.
Rows carry ``auto_filled`` naming the fields that were derived, so a human can
see what was machine-filled. A topic the Agent judges differently from the
observations must say why in ``override_reason``.

It refuses to overwrite an existing claim_assessments.json (use --force).

Usage:
    python init_claims_skeleton.py --review-dir reviews/Report/run [--force]
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import check_issues
import review_io

PLACEHOLDER = "【要記入】"
TOPICS = [
    "initial_access", "scope", "lateral_movement", "persistence", "c2_external",
    "exfiltration", "impact", "limitations", "recommendations",
]
# Weakest wording wins when observations disagree: a conclusion should not be
# presented as firmer than the least firm statement of it.
CONFIDENCE_STRENGTH = ["negative", "unknown", "possible", "highly_likely", "confirmed"]
MAX_TEXT = 500
MAX_SPANS = 10


def _load(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    data, error = review_io.load_json_safe(path)
    if error is not None:
        raise ValueError(f"{path}: {error}")
    return data


def _usable_spans(ids: list[str], spans: dict[str, dict]) -> list[str]:
    return [
        s for s in dict.fromkeys(ids)
        if s in spans and not check_issues._is_non_substantive_span(spans[s])
    ]


def _confidence(observations: list[dict]) -> str:
    seen = [
        o.get("confidence_language") for o in observations
        if o.get("confidence_language") in CONFIDENCE_STRENGTH
    ]
    if not seen:
        return "unknown"
    top = Counter(seen).most_common()
    best = max(c for _, c in top)
    tied = [v for v, c in top if c == best]
    return min(tied, key=CONFIDENCE_STRENGTH.index)


def _stated(observations: list[dict]) -> str:
    texts = list(dict.fromkeys(
        str(o.get("stated_conclusion") or "").strip()
        for o in observations if str(o.get("stated_conclusion") or "").strip()
    ))
    joined = " ／ ".join(texts)
    return joined if len(joined) <= MAX_TEXT else joined[: MAX_TEXT - 1] + "…"


def build_skeleton(merged: dict, spans: dict[str, dict]) -> dict[str, Any]:
    by_topic: dict[str, list[dict]] = {t: [] for t in TOPICS}
    for obs in merged.get("conclusion_observations", []):
        if isinstance(obs, dict) and obs.get("topic") in by_topic:
            by_topic[obs["topic"]].append(obs)

    inventory: list[dict] = []
    assessments: list[dict] = []
    con_of_topic: dict[str, str] = {}
    asm_of_topic: dict[str, str] = {}
    spans_of_topic: dict[str, list[str]] = {}

    for n, topic in enumerate(TOPICS, 1):
        obs = by_topic[topic]
        used = _usable_spans(
            [s for o in obs for s in (o.get("source_span_ids") or [])], spans
        )[:MAX_SPANS]
        con_id = f"CON-{n:03d}"
        con_of_topic[topic] = con_id
        if obs:
            asm_id = f"ASM-{len(assessments) + 1:03d}"
            asm_of_topic[topic] = asm_id
            spans_of_topic[topic] = used
            stated = _stated(obs)
            obs_ids = [str(o["observation_id"]) for o in obs if o.get("observation_id")]
            inventory.append({
                "conclusion_id": con_id, "topic": topic, "presence": "reported",
                "stated_conclusion": stated or PLACEHOLDER,
                "assessment_ids": [asm_id],
                "source_span_ids": used, "absence_check_ids": [],
                "source_observation_ids": obs_ids,
                "auto_filled": ["presence", "stated_conclusion", "assessment_ids",
                                "source_span_ids"],
            })
            assessments.append({
                "assessment_id": asm_id, "topic": topic,
                "conclusion": stated or PLACEHOLDER,
                "stated_confidence": _confidence(obs),
                "review_verdict": PLACEHOLDER, "reason": PLACEHOLDER,
                "source_span_ids": used, "issue_ids": [],
                "source_observation_ids": obs_ids,
                "auto_filled": ["topic", "conclusion", "stated_confidence", "source_span_ids"],
            })
        else:
            inventory.append({
                "conclusion_id": con_id, "topic": topic, "presence": "not_reported",
                "stated_conclusion": "", "assessment_ids": [],
                "source_span_ids": [], "absence_check_ids": [f"ABS-CON-{topic}"],
                "reason": "全 chunk の SubAgent が該当する主要結論を観測しなかった",
                "auto_filled": ["presence", "absence_check_ids", "reason"],
            })

    reported = [t for t in TOPICS if t in asm_of_topic]
    findings = [t for t in reported if t != "recommendations"]
    related = [con_of_topic[t] for t in findings]
    cns_spans = [s for t in findings for s in spans_of_topic.get(t, [])]
    absent = [t for t in TOPICS if t not in asm_of_topic]
    related_absence: list[str] = []
    while len(related) < 2 and absent:  # a consistency row needs two conclusions
        t = absent.pop(0)
        related.append(con_of_topic[t])
        related_absence.append(f"ABS-CON-{t}")
    consistency = [{
        "consistency_id": "CNS-001", "related_conclusion_ids": related,
        "consistency_verdict": PLACEHOLDER,
        "source_span_ids": list(dict.fromkeys(cns_spans))[:MAX_SPANS],
        "absence_check_ids": related_absence if not cns_spans else [],
        "reason": PLACEHOLDER,
        "auto_filled": ["related_conclusion_ids", "source_span_ids"],
    }]

    recommendations: list[dict] = []
    if "recommendations" in asm_of_topic:
        recommendations.append({
            "recommendation_id": "REC-001",
            "recommendation": next(
                (r["stated_conclusion"] for r in inventory if r["topic"] == "recommendations"),
                PLACEHOLDER,
            ),
            "linked_finding_ids": [asm_of_topic[t] for t in findings],
            "review_verdict": PLACEHOLDER, "reason": PLACEHOLDER,
            "source_span_ids": spans_of_topic.get("recommendations", []), "issue_ids": [],
            "auto_filled": ["recommendation", "linked_finding_ids", "source_span_ids"],
        })

    return {
        "conclusion_inventory": inventory,
        "consistency_assessments": consistency,
        "claim_assessments": assessments,
        "recommendation_assessments": recommendations,
    }


def main() -> int:
    review_io.require_via_review_status("init_claims_skeleton.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--review-dir", required=True, type=Path)
    ap.add_argument("--out", type=Path, help="default: <review-dir>/claim_assessments.json")
    ap.add_argument("--force", action="store_true", help="overwrite an existing file")
    args = ap.parse_args()

    out = args.out or args.review_dir / "claim_assessments.json"
    if out.exists() and not args.force:
        print(f"error: {out} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    try:
        merged = _load(args.review_dir / "merged_observations.json", None)
        source_index = _load(args.review_dir / "source_index.json", {})
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not isinstance(merged, dict):
        print("error: merged_observations.json not found or not an object", file=sys.stderr)
        return 2
    spans = {
        str(s.get("source_span_id") or s.get("span_id") or s.get("id")): s
        for s in source_index.get("spans", [])
        if isinstance(s, dict) and (s.get("source_span_id") or s.get("span_id") or s.get("id"))
    }
    data = build_skeleton(merged, spans)
    review_io.atomic_write_json(out, data)

    reported = [r["topic"] for r in data["conclusion_inventory"] if r["presence"] == "reported"]
    absent = [r["topic"] for r in data["conclusion_inventory"] if r["presence"] != "reported"]
    print(f"wrote claim_assessments skeleton to {out}")
    print(f"  reported (SubAgent 観測あり): {', '.join(reported) or '-'}")
    print(f"  not_reported (観測なし): {', '.join(absent) or '-'}")
    print(
        f"次: 各 assessment / consistency / recommendation の {PLACEHOLDER} を、"
        "根拠 span を読んで埋めて"
        "ください（review_verdict と reason は判断です）。not_reported の topic は、"
        "全 chunk の SubAgent が観測しなかったものとして扱い、報告書を検索し直しません。"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
