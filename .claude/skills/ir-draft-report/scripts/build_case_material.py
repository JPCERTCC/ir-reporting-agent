#!/usr/bin/env python3
"""Assemble approved case material for report drafting.

Reads the approved claims, active evidence ledger, timeline, and gaps from a
case directory, assigns stable EV-### / GAP-### report aliases, and writes a
single reports/case_material.json that the ir-draft-report skill uses as the
sole source of facts for the draft. Excerpts are kept verbatim (line breaks
included) because chapter 4 quotes them as-is.

It then writes the draft skeleton (build_draft_skeleton.py) to
reports/draft_report.md unless a draft already exists.

Usage:
    python build_case_material.py --case-dir <case>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"warning: skipping malformed line in {path.name}")
    return records


def read_manifest(case_dir: Path) -> dict:
    path = case_dir / "manifest.yaml"
    try:
        import yaml  # provided by the ir_agent install

        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        print(f"warning: could not parse manifest.yaml ({exc})")
        return {}


def active_ledger(records: list[dict]) -> list[dict]:
    """Replicate the ledger's active view: drop withdrawn and superseded."""
    withdrawn = {r.get("evidence_id") for r in records if r.get("withdrawn")}
    superseded = {r.get("supersedes") for r in records if r.get("supersedes")}
    seen: set[str] = set()
    active = []
    for r in records:
        eid = r.get("evidence_id")
        if not eid or eid in withdrawn or eid in superseded or eid in seen:
            continue
        seen.add(eid)
        active.append(r)
    return active


def trim(value, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def verbatim(value) -> str:
    """Excerpts are quoted verbatim in chapter 4: keep line breaks, never cut."""
    return str(value or "").rstrip("\n")


def source_coverage(case_dir: Path) -> dict | None:
    """Which provided files reached the ledger (未提供/未抽出/未承認 の区別)."""
    try:
        from ir_agent.analysis.source_coverage import (
            UNUSED_STATUSES,
            load_source_coverage,
        )
    except ImportError:
        print("warning: ir_agent not importable; source_coverage omitted")
        return None
    report = load_source_coverage(case_dir)
    if not report.get("files"):
        return None
    return {
        "summary": report["summary"],
        "unused_files": [
            {
                "path": f["path"],
                "host": f["host"],
                "status": f["status"],
                "status_label": f["status_label"],
                "candidate_count": f["candidate_count"],
            }
            for f in report["files"]
            if f["status"] in UNUSED_STATUSES
        ],
        "missing_hosts": [h["host"] for h in report["missing_hosts"]],
    }


def build_material(case_dir: Path) -> dict:
    """The case material, derived only from the case's approved records.

    Deterministic, so check-draft can rebuild it and detect a hand-edited
    reports/case_material.json.
    """
    data = case_dir / "data"

    manifest = read_manifest(case_dir)
    ledger = active_ledger(read_jsonl(data / "evidence_ledger.jsonl"))
    claims = [
        c for c in read_jsonl(data / "claims.jsonl")
        if c.get("review_status") in ("approved", "edited")
    ]
    timeline = read_jsonl(data / "timeline.jsonl")
    gaps = read_jsonl(data / "gaps.jsonl")


    aliases = {
        entry["evidence_id"]: f"EV-{i:03d}" for i, entry in enumerate(ledger, 1)
    }

    def alias_list(ids: list) -> list[str]:
        return [aliases[eid] for eid in (ids or []) if eid in aliases]

    material = {
        "case": {
            "case_id": manifest.get("case_id", ""),
            "case_name": manifest.get("case_name", ""),
            "scope": manifest.get("scope", ""),
            "hosts": manifest.get("hosts", []),
            "time_range_utc": manifest.get("time_range", {}),
            "report_language": manifest.get("report_language", "ja"),
            "report_timezone": manifest.get("report_timezone", "UTC"),
        },
        "evidence_ledger": [
            {
                "report_evidence_id": aliases[e["evidence_id"]],
                "observed_fact": trim(e.get("observed_fact"), 400),
                "interpretation": trim(e.get("interpretation"), 300),
                "observed_fact_confidence": e.get("observed_fact_confidence"),
                "interpretation_confidence": e.get("interpretation_confidence"),
                "observed_event": {
                    k: v for k, v in (e.get("observed_event") or {}).items() if v
                },
                "source_refs": [
                    {
                        "source_path": r.get("source_path", ""),
                        "source_lines": r.get("source_lines", []),
                        "excerpt": verbatim(r.get("excerpt")),
                    }
                    for r in (e.get("source_refs") or [])
                ],
            }
            for e in ledger
        ],
        "approved_claims": [
            {
                "claim_id": c.get("claim_id"),
                "report_section": c.get("report_section"),
                "text": trim(c.get("approved_claim_text") or c.get("claim_text"), 400),
                "category": c.get("claim_category"),
                "confidence": c.get("confidence_level"),
                "supporting_evidence": alias_list(c.get("supporting_evidence")),
                "counter_evidence": alias_list(c.get("counter_evidence")),
                "limitations": [trim(x, 200) for x in (c.get("limitations") or [])[:4]],
                "missing_evidence": [
                    trim(x, 200) for x in (c.get("missing_evidence") or [])[:4]
                ],
                "attack_mappings": [
                    {
                        "tactic": m.get("tactic"),
                        "technique_id": m.get("technique_id"),
                        "technique_name": m.get("technique_name"),
                        "supporting_evidence": alias_list(
                            m.get("supporting_evidence")
                        ),
                    }
                    for m in (c.get("attack_mappings") or [])[:4]
                ],
                # Upstream-analysis provenance for grouped claims: why the
                # evidence items were combined, for the drafting narrative.
                "analysis_group_id": c.get("analysis_group_id"),
                "group_basis": trim(c.get("group_basis"), 300) or None,
                "related_entity_link_ids": c.get("related_entity_link_ids") or [],
            }
            for c in claims
        ],
        "timeline": [
            {
                "event_time": t.get("event_time"),
                "original_timestamp": t.get("original_timestamp"),
                "display_timezone": t.get("display_timezone"),
                "event_description": trim(t.get("event_description"), 200),
                "host": t.get("host"),
                "confidence": t.get("confidence"),
                "interpretation_confidence": t.get("interpretation_confidence"),
                "timestamp_type": t.get("timestamp_type"),
                "evidence_id": aliases.get(t.get("evidence_id"), None),
                # The excerpt line this row's time was read from (one row per
                # timestamped line of a multi-line evidence item).
                "source_line": t.get("source_line"),
                "source_text": trim(t.get("source_text"), 200) or None,
            }
            for t in timeline
        ],
        "gaps": [
            {
                "gap_id": g.get("gap_id"),
                "gap_type": g.get("gap_type"),
                "related_claim_id": g.get("related_claim_id"),
                "severity": g.get("severity"),
                "description": trim(g.get("description"), 300),
                "recommended_action": trim(g.get("recommended_action"), 250),
                "disposition": g.get("disposition"),
                "disposition_reason": trim(g.get("disposition_reason"), 200),
            }
            for g in sorted(
                gaps,
                key=lambda g: {"critical": 0, "major": 1, "minor": 2}.get(
                    g.get("severity"), 3
                ),
            )
        ],
        "source_coverage": source_coverage(case_dir),
        "alias_map": {v: k for k, v in aliases.items()},
        "notes": [
            "Use ONLY report_evidence_id values (EV-###) that exist in evidence_ledger.",
            "Do not invent facts, timestamps, hosts, tools, causes, or impact "
            "beyond this material.",
        ],
    }

    return material


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", required=True, type=Path)
    args = parser.parse_args()
    case_dir: Path = args.case_dir

    material = build_material(case_dir)
    ledger = material["evidence_ledger"]
    claims = material["approved_claims"]
    gaps = material["gaps"]
    if not ledger:
        print("error: no active evidence ledger entries — run promote-evidence first")
        return 2
    if not claims:
        print("warning: no approved claims found — the draft will be evidence-only")

    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / "case_material.json"
    out.write_text(
        json.dumps(material, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    from build_draft_skeleton import PLACEHOLDER, write_skeleton

    draft, created = write_skeleton(case_dir, material)
    print(
        f"written: {out}\n"
        f"evidence: {len(ledger)}  claims: {len(claims)}  "
        f"timeline: {len(material['timeline'])}  gaps: {len(gaps)}"
    )
    if created:
        count = draft.read_text(encoding="utf-8").count(PLACEHOLDER)
        print(f"skeleton: {draft}({PLACEHOLDER}】{count} 箇所を執筆してください)")
    else:
        print(f"skeleton: {draft} は既にあるため作成しませんでした"
              "(雛形から作り直す場合は退避してから再実行)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
