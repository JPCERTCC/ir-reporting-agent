#!/usr/bin/env python3
"""Group merged_observations.json by checklist_id / topic / related issue for judgment.

Filling results.json, issues.json, and claim_assessments.json requires an
Agent to actually read and weigh evidence — that is real judgment and this
skill does not automate it. But merged_observations.json is a *flat* list
(commonly 100+ rows across 6+ chunks and 50+ checklist items), and searching
that flat list by hand for "every observation about CUS-2.2-1" is a
mechanical chore, not judgment. Left with no scaffolding for that chore, an
Agent facing 100+ rows predictably writes a one-off aggregation script instead
of doing the judgment step at all — which is exactly the failure mode this
script exists to prevent.

This script does *only* the grouping. It does not choose a verdict, resolve a
conflict, write a rationale, or decide anything a human/Agent would need to
read the report to decide. Every group it emits still has to be read.

Usage:
    python aggregate_observations.py \
        --merged-observations merged_observations.json \
        --results results.json \
        --out aggregation_worksheet.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import review_io

REQUIRED_TOPICS = [
    "initial_access", "scope", "lateral_movement", "persistence",
    "c2_external", "exfiltration", "impact", "limitations", "recommendations",
]
# candidate_verdict values whose disagreement counts as a real conflict to flag.
# unknown/not_applicable disagreeing with met/partial/not_met is not a
# "contradiction" in the same sense — see review_model.md section 2 (conflicting observations).
CONFLICT_VERDICTS = {"met", "partial", "not_met"}


# Words in a checklist item that make it a "holds for everything" requirement
# (すべての… / 一貫して… / 各…). One chunk's hit does not prove those, so such
# items are never auto-suggested; the Agent decides them after reading.
UNIVERSAL_MARKERS = (
    "すべて", "全て", "全件", "全体", "各", "いずれも", "網羅", "一貫", "整合", "矛盾",
)


def _clip(text: str, n: int) -> str:
    t = " ".join(str(text or "").split())
    return t if len(t) <= n else t[: n - 1] + "…"


def build_suggestion(
    checklist_id: str,
    item_text: str,
    observations: list[dict[str, Any]],
    conflicting: bool,
    unknown_allowed: bool = False,
    conditional: bool = False,
    applies_to: str | None = None,
) -> dict[str, Any] | None:
    """Pre-filled candidate for results.json — only where SubAgents agree.

    Three cases produce a suggestion:

    * every observation says the same verdict (met / partial / not_met) and
      at least one cites a span
    * no observation at all for an item whose answer must come from the
      report itself (``unknown_allowed`` is false, not a conditional item):
      every chunk was read by a
      SubAgent (the coverage ledger guarantees it), and none found anything,
      so the item is not in the report. Nobody re-searches the report.
    * no observation at all for a ``pre_engagement`` item (an agreement made
      before the investigation): ``unknown`` with the out-of-report material to
      check, since no report can settle it
    * (nothing for conflicts, mixed verdicts, unknown observations, or any
      other zero-observation item that may need out-of-report material —
      those are the Agent's call)

    ``auto_applicable`` is False for a ``met`` on an item that reads as "all
    of X": one chunk's hit does not prove it holds everywhere.
    """
    if conflicting:
        return None
    if not observations:
        # A conditional item ("［依頼している場合］") may be not_applicable rather
        # than missing, and an unknown_allowed one may need out-of-report
        # material: both are the Agent's call.
        if conditional:
            return None
        if unknown_allowed:
            # Only agreements made before the investigation (scope, purpose,
            # reporting terms) can never be settled by reading the report:
            # they need the contract / agreement record. Other unknown_allowed
            # items may still be not_met, which is the Agent's call.
            if applies_to != "pre_engagement":
                return None
            return {
                "verdict": "unknown",
                "basis": "no_observation_pre_engagement",
                "source_span_ids": [],
                "absence_check_ids": [f"ABS-{checklist_id}"],
                "rationale": (
                    "調査前の合意事項に関する項目で、全 chunk を SubAgent が読み終えたが、"
                    "報告書本文にはこの内容の記載が観測されなかった。報告書外の資料での"
                    "確認が必要"
                ),
                "unknown_reason": "external_information_missing",
                "external_confirmation_needed": (
                    f"調査依頼書・契約書・事前合意記録など、「{_clip(item_text, 60)}」に関する"
                    "合意内容が分かる報告書外の資料"
                ),
                "auto_applicable": True,
                "not_auto_reason": None,
            }
        return {
            "verdict": "not_met",
            "basis": "no_observation",
            "source_span_ids": [],
            "absence_check_ids": [f"ABS-{checklist_id}"],
            "rationale": (
                "全 chunk を SubAgent が読み終えたが、この項目に該当する記載は"
                "どの chunk でも観測されなかった（未記載）"
            ),
            "auto_applicable": True,
            "not_auto_reason": None,
        }
    verdicts = {o.get("candidate_verdict") for o in observations}
    if len(verdicts) != 1 or next(iter(verdicts)) not in ("met", "partial", "not_met"):
        return None
    verdict = str(next(iter(verdicts)))
    spans: list[str] = []
    for o in observations:
        for sid in o.get("source_span_ids") or []:
            if sid not in spans:
                spans.append(sid)
    if not spans:
        return None
    marker = (
        next((m for m in UNIVERSAL_MARKERS if m in item_text), None)
        if verdict == "met" else None
    )
    rationales = list(dict.fromkeys(
        str(o.get("rationale") or "").strip() for o in observations
        if str(o.get("rationale") or "").strip()
    ))
    ids = [str(o.get("observation_id")) for o in observations if o.get("observation_id")]
    suggestion: dict[str, Any] = {
        "verdict": verdict,
        "basis": "unanimous_observations",
        "source_span_ids": spans[:6],
        "rationale": (
            f"SubAgent 観測 {len(observations)} 件がすべて {verdict} で一致"
            f"（{', '.join(ids[:4])}）。{' / '.join(rationales[:2])}"
        ).strip(),
        "auto_applicable": marker is None,
        "not_auto_reason": (
            f"項目文に「{marker}」を含み、全体について成り立つか確認が必要" if marker else None
        ),
    }
    if verdict == "not_met":
        suggestion["absence_check_ids"] = [f"ABS-{checklist_id}"]
    return suggestion


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    data, error = review_io.load_json_safe(path)
    if error is not None:
        raise ValueError(f"{path}: {error}")
    return data


def build_checklist_groups(
    results: list[dict[str, Any]],
    checklist_observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_id: dict[str, list[dict[str, Any]]] = {}
    for obs in checklist_observations:
        if not isinstance(obs, dict):
            continue
        cid = obs.get("checklist_id")
        if not cid:
            continue
        by_id.setdefault(str(cid), []).append({
            "chunk_id": obs.get("chunk_id"),
            "observation_id": obs.get("observation_id"),
            "candidate_verdict": obs.get("candidate_verdict"),
            "rationale": obs.get("rationale"),
            "source_span_ids": obs.get("source_span_ids", []),
            "absence_check_ids": obs.get("absence_check_ids", []),
            "confidence": obs.get("confidence"),
        })

    groups = []
    for row in results:
        if not isinstance(row, dict):
            continue
        cid = row.get("checklist_id") or row.get("id")
        if not cid:
            continue
        cid = str(cid)
        observations = by_id.get(cid, [])
        verdict_counts: dict[str, int] = {}
        for o in observations:
            v = o.get("candidate_verdict")
            if v:
                verdict_counts[v] = verdict_counts.get(v, 0) + 1
        conflicting = len(CONFLICT_VERDICTS & set(verdict_counts)) > 1
        groups.append({
            "checklist_id": cid,
            "item": row.get("item", ""),
            "level": row.get("level", "-"),
            "unknown_allowed": row.get("unknown_allowed", False),
            "current_verdict": row.get("verdict"),
            "observation_count": len(observations),
            "candidate_verdict_counts": verdict_counts,
            "conflicting": conflicting,
            "suggestion": build_suggestion(
                cid, str(row.get("item", "")), observations, conflicting,
                bool(row.get("unknown_allowed", False)),
                "場合］" in json.dumps(
                    [row.get("section", ""), row.get("item", "")], ensure_ascii=False),
                row.get("applies_to"),
            ),
            "observations": observations,
        })
    return groups


def build_topic_groups(
    conclusion_observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_topic: dict[str, list[dict[str, Any]]] = {t: [] for t in REQUIRED_TOPICS}
    other: list[dict[str, Any]] = []
    for obs in conclusion_observations:
        if not isinstance(obs, dict):
            continue
        topic = str(obs.get("topic") or "")
        entry = {
            "chunk_id": obs.get("chunk_id"),
            "observation_id": obs.get("observation_id"),
            "stated_conclusion": obs.get("stated_conclusion"),
            "source_span_ids": obs.get("source_span_ids", []),
            "confidence_language": obs.get("confidence_language"),
            "notes": obs.get("notes"),
        }
        if topic in by_topic:
            by_topic[topic].append(entry)
        else:
            other.append({**entry, "topic": topic or "(unspecified)"})

    groups = [
        {"topic": t, "observation_count": len(by_topic[t]), "observations": by_topic[t]}
        for t in REQUIRED_TOPICS
    ]
    if other:
        groups.append({
            "topic": "(other/unspecified)",
            "observation_count": len(other),
            "observations": other,
        })
    return groups


def build_issue_clusters(
    issue_observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Cluster by related_checklist_ids so duplicate findings from different
    chunks about the same item are pre-grouped as merge candidates. This does
    not decide they ARE duplicates — the Agent still reads and judges each
    cluster."""
    by_key: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for obs in issue_observations:
        if not isinstance(obs, dict):
            continue
        cids = obs.get("related_checklist_ids") or []
        key = tuple(sorted(str(c) for c in cids)) or ("(no checklist link)",)
        by_key.setdefault(key, []).append({
            "chunk_id": obs.get("chunk_id"),
            "observation_id": obs.get("observation_id"),
            "category": obs.get("category"),
            "severity_hint": obs.get("severity_hint"),
            "reason": obs.get("reason"),
            "source_span_ids": obs.get("source_span_ids", []),
            "suggested_revision": obs.get("suggested_revision"),
        })
    return [
        {"related_checklist_ids": list(key), "observation_count": len(rows), "observations": rows}
        for key, rows in sorted(by_key.items())
    ]


def build_open_questions(merged: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        q for q in merged.get("open_questions", [])
        if isinstance(q, dict)
    ]


def main() -> int:
    review_io.require_via_review_status("aggregate_observations.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--merged-observations", required=True, type=Path)
    ap.add_argument("--results", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    if not args.merged_observations.exists():
        print(f"error: not found: {args.merged_observations}", file=sys.stderr)
        return 2
    if not args.results.exists():
        print(f"error: not found: {args.results}", file=sys.stderr)
        return 2

    try:
        merged = _load_json(args.merged_observations, {})
        results_data = _load_json(args.results, {})
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    results = results_data.get("results", results_data if isinstance(results_data, list) else [])

    worksheet = {
        "schema_version": "1.0",
        "note": (
            "この worksheet は機械的なグルーピングだけを行う。verdict/rationale/"
            "category の判断はまだ含まれていない。各グループの observations を"
            "読んで判断すること。この worksheet を再生成しても judgment 側の"
            "ファイル(results.json 等)は変更されない。"
        ),
        "checklist_items": build_checklist_groups(
            results, merged.get("checklist_observations", [])
        ),
        "topics": build_topic_groups(merged.get("conclusion_observations", [])),
        "issue_clusters": build_issue_clusters(merged.get("issue_observations", [])),
        "open_questions": build_open_questions(merged),
    }

    review_io.atomic_write_json(args.out, worksheet)

    unfilled = sum(
        1 for c in worksheet["checklist_items"]
        if c["current_verdict"] is None
    )
    conflicts = sum(1 for c in worksheet["checklist_items"] if c["conflicting"])
    auto = sum(
        1 for c in worksheet["checklist_items"]
        if c["suggestion"] and c["suggestion"]["auto_applicable"] and c["current_verdict"] is None
    )
    print(
        f"wrote {len(worksheet['checklist_items'])} checklist groups "
        f"({unfilled} unfilled, {conflicts} conflicting, {auto} auto-suggestible), "
        f"{len(worksheet['topics'])} topic groups, "
        f"{len(worksheet['issue_clusters'])} issue clusters, "
        f"{len(worksheet['open_questions'])} open questions to {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
