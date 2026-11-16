#!/usr/bin/env python3
"""Create a grounded issues.json skeleton from a filled results.json.

Writing issues.json from scratch is where review runs lose the most time and
where they fail gates most often: every ``partial`` / ``not_met`` /
``unknown`` verdict needs a matching, *grounded* issue
(``source_span_ids`` / ``absence_check_ids`` / ``primary_location``), and
hand-writing them all in one go misses items or ungrounded fields. That in
turn pushes Agents to write one-off "fix_issues.py" scripts.

This script does the mechanical part only:

  * one issue per checklist item that needs one (quality shortfall on
    必須/推奨/未分類, optional shortfall, unknown → external_confirmation)
  * ``checklist_ids`` / ``status`` / grounding copied from results.json
    (span ids that check_issues would reject as non-substantive are dropped)
  * ``category`` / ``severity`` taken from the SubAgents' issue_observations
    for the same checklist item when there is one
  * ``source_observation_ids`` copied from merged_observations.json

It does NOT write the finding. Fields that need the Agent's judgment hold the
marker ``【要記入】`` and check_issues.py rejects any issue that still
contains it, so a skeleton can never pass a gate unreviewed.

It refuses to overwrite an existing issues.json (use --force).

Usage:
    python init_issues_skeleton.py --review-dir reviews/Report/run [--force]
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
DEFECT_LEVELS = ("必須", "推奨", "-")
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _load(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    data, error = review_io.load_json_safe(path)
    if error is not None:
        raise ValueError(f"{path}: {error}")
    return data


def _mode_of(rows: list[dict]) -> str:
    return check_issues.infer_mode(rows, "auto")


def _observation_hints(merged: dict) -> tuple[dict[str, dict], dict[str, list[str]]]:
    """Per checklist id: (dominant category/severity hint, observation ids)."""
    by_cid: dict[str, list[dict]] = {}
    for obs in merged.get("issue_observations", []):
        if not isinstance(obs, dict):
            continue
        for cid in obs.get("related_checklist_ids") or []:
            by_cid.setdefault(str(cid), []).append(obs)
    hints: dict[str, dict] = {}
    for cid, observations in by_cid.items():
        cats = Counter(
            o.get("category") for o in observations
            if o.get("category") in check_issues.CATEGORIES
        )
        sevs = [
            o.get("severity_hint") for o in observations
            if o.get("severity_hint") in SEVERITY_ORDER
        ]
        hints[cid] = {
            "category": cats.most_common(1)[0][0] if cats else None,
            # Most severe hint wins: dropping a serious finding is worse
            # than showing a slightly high default the Agent can lower.
            "severity": min(sevs, key=SEVERITY_ORDER.index) if sevs else None,
        }
    checklist_obs: dict[str, list[str]] = {}
    for obs in merged.get("checklist_observations", []):
        if isinstance(obs, dict) and obs.get("checklist_id") and obs.get("observation_id"):
            checklist_obs.setdefault(str(obs["checklist_id"]), []).append(obs["observation_id"])
    for cid, observations in by_cid.items():
        ids = checklist_obs.setdefault(cid, [])
        ids.extend(o["observation_id"] for o in observations if o.get("observation_id"))
    return hints, checklist_obs


def _question_issues(
    merged: dict, results_by_id: dict[str, dict], spans: dict[str, dict],
    known_ids: set[str],
) -> tuple[list[dict], list[str]]:
    """One external_confirmation issue per SubAgent open question.

    open_questions must be triaged (check_review_run.py); creating the issue
    here means the parent Agent cannot lose one, and the question text — the
    thing to confirm — is carried over verbatim.
    """
    issues: list[dict] = []
    notes: list[str] = []
    for q in merged.get("open_questions", []):
        if not isinstance(q, dict) or not q.get("question_id"):
            continue
        cids = [
            c for c in q.get("related_checklist_ids") or []
            if c in known_ids and (results_by_id.get(c) or {}).get("evaluation_scope")
            != "out_of_scope"
        ]
        if not cids:
            notes.append(
                f"{q['question_id']}: no related checklist id — add an issue for it "
                "yourself (or reference it from claim_assessments.json)"
            )
            continue
        span_ids = [
            s for s in dict.fromkeys(q.get("source_span_ids") or [])
            if s in spans and not check_issues._is_non_substantive_span(spans[s])
        ]
        question = str(q.get("question") or "").strip()
        why = str(q.get("reason") or "").strip()
        issues.append({
            "category": "external_confirmation",
            "severity": "info",
            "checklist_ids": cids,
            "source_span_ids": span_ids,
            "absence_check_ids": [] if span_ids else [f"ABS-{cids[0]}"],
            "reason": f"{question}（{why}）" if why else question,
            "suggested_revision": question,
            "source_observation_ids": [str(q["question_id"])],
            "auto_filled": ["category", "severity", "reason", "suggested_revision",
                            "source_span_ids", "source_observation_ids"],
        })
    return issues, notes


def build_skeleton(
    results: list[dict],
    level_of: dict[str, str],
    merged: dict,
    spans: dict[str, dict],
    text_of: dict[str, str] | None = None,
) -> tuple[list[dict], list[str]]:
    text_of = text_of or {}
    hints, observation_ids = _observation_hints(merged)
    issues: list[dict] = []
    notes: list[str] = []
    for row in results:
        if not isinstance(row, dict):
            continue
        cid = check_issues.result_id(row)
        verdict = row.get("verdict")
        if not cid or row.get("evaluation_scope") == "out_of_scope":
            continue
        level = level_of.get(cid, row.get("level", "-"))
        if verdict == "unknown":
            cls = "external_confirmation"
        elif verdict in ("partial", "not_met"):
            cls = "quality_defect" if level in DEFECT_LEVELS else "optional_enhancement"
        else:
            continue

        span_ids = [
            s for s in row.get("source_span_ids") or []
            if s in spans and not check_issues._is_non_substantive_span(spans[s])
        ]
        dropped = [s for s in row.get("source_span_ids") or [] if s not in span_ids]
        absence_ids = list(row.get("absence_check_ids") or [])
        if not span_ids and not absence_ids:
            absence_ids = [f"ABS-{cid}"]
        if dropped:
            notes.append(f"{cid}: dropped span ids that cannot ground an issue: {dropped}")

        hint = hints.get(cid, {})
        rationale = str(row.get("rationale") or "").strip()
        item = text_of.get(cid, "").strip()
        auto: list[str] = ["checklist_ids", "status", "source_span_ids"]
        if cls == "external_confirmation":
            category = "external_confirmation"
            severity = "info"
            confirm = str(row.get("external_confirmation_needed") or "").strip()
            reason = " ".join(
                p for p in (rationale, str(row.get("unknown_reason") or "").strip()) if p
            ) or PLACEHOLDER
            revision = confirm or PLACEHOLDER
            auto += ["category", "severity"]
        elif cls == "optional_enhancement":
            category = "optional_enhancement"
            severity = "low"
            reason = rationale or (
                f"任意項目「{item}」に対応する記載が不足している" if item else PLACEHOLDER
            )
            revision = (
                f"可能であれば「{item}」に対応する記載を追加する" if item else PLACEHOLDER
            )
            auto += ["category", "severity", "suggested_revision"]
        else:
            hinted = hint.get("category")
            category = (
                hinted if hinted in check_issues.CATEGORIES
                and hinted not in check_issues.NON_DEFECT_CATEGORIES
                else "missing_required_item"
            )
            severity = hint.get("severity") or "medium"
            reason = rationale or (
                f"チェック項目「{item}」を満たす記載が確認できない" if item else PLACEHOLDER
            )
            revision = (
                f"チェック項目「{item}」が求める内容を報告書に追記する" if item else PLACEHOLDER
            )
            auto += ["category", "severity", "suggested_revision"]
        if reason and reason != PLACEHOLDER and not rationale:
            auto.append("reason")
        # A not_met "missing item" is grounded on the absence record even when
        # related spans exist (check_issues requires it for that combination).
        if category == "missing_required_item" and verdict == "not_met" and not absence_ids:
            absence_ids = [f"ABS-{cid}"]

        issue: dict[str, Any] = {
            "category": category,
            "severity": severity,
            "checklist_ids": [cid],
            "status": verdict,
            "source_span_ids": span_ids,
            "absence_check_ids": absence_ids,
            "reason": reason,
            "suggested_revision": revision,
            "auto_filled": auto,
        }
        if observation_ids.get(cid):
            issue["source_observation_ids"] = observation_ids[cid]
        issues.append(issue)
    question_issues, question_notes = _question_issues(
        merged,
        {check_issues.result_id(r): r for r in results if isinstance(r, dict)},
        spans,
        set(level_of),
    )
    return issues + question_issues, notes + question_notes


def main() -> int:
    review_io.require_via_review_status("init_issues_skeleton.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--review-dir", required=True, type=Path)
    ap.add_argument("--skill-dir", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--out", type=Path, help="default: <review-dir>/issues.json")
    ap.add_argument("--force", action="store_true", help="overwrite an existing issues.json")
    args = ap.parse_args()

    out = args.out or args.review_dir / "issues.json"
    if out.exists() and not args.force:
        print(f"error: {out} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    try:
        results_data = _load(args.review_dir / "results.json", {})
        merged = _load(args.review_dir / "merged_observations.json", {})
        source_index = _load(args.review_dir / "source_index.json", {})
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rows = results_data.get("results", []) if isinstance(results_data, dict) else results_data
    if not rows:
        print("error: results.json has no rows", file=sys.stderr)
        return 2
    if any(isinstance(r, dict) and r.get("verdict") is None
           and r.get("evaluation_scope") != "out_of_scope" for r in rows):
        print("error: results.json still has unfilled verdicts; fill it first", file=sys.stderr)
        return 2

    items = check_issues.load_checklist_items(args.skill_dir, _mode_of(rows))
    level_of = {i["id"]: i.get("level", "-") for i in items}
    spans = {
        str(s.get("source_span_id") or s.get("span_id") or s.get("id")): s
        for s in source_index.get("spans", [])
        if isinstance(s, dict) and (s.get("source_span_id") or s.get("span_id") or s.get("id"))
    }
    text_of = {i["id"]: i.get("text", "") for i in items}
    issues, notes = build_skeleton(rows, level_of, merged, spans, text_of)
    review_io.atomic_write_json(out, {"issues": issues})

    todo = sum(1 for i in issues if PLACEHOLDER in str(i))
    print(f"wrote {len(issues)} issue skeletons to {out} ({todo} contain {PLACEHOLDER})")
    for note in notes:
        print(f"note: {note}")
    print(
        "次: 各 issue の auto_filled は機械的な既定値です。項目ごとに reason / "
        "suggested_revision / category / severity を、実際の観測と本文に合わせて見直して"
        f"ください（category は {', '.join(sorted(check_issues.CATEGORIES))} から選ぶ）。"
        f"{PLACEHOLDER} が残っている箇所は必ず記入します。複数項目を 1 つの指摘に統合する場合は"
        " checklist_ids に統合し、項目に紐づかない横断的な指摘"
        "（cross_section_inconsistency 等）は、"
        "根拠 span を付けて追加してください。"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
