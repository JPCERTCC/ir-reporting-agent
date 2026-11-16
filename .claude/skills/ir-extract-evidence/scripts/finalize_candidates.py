#!/usr/bin/env python3
"""Validate and finalize agent-extracted evidence candidates.

Reads a raw extraction JSON produced by the ir-extract-evidence skill,
validates every candidate against the source chunks (verbatim excerpt,
line ranges, confidence enums), enriches it with source references and
artifact metadata, writes data/evidence_candidates.jsonl, and marks the
evidence_candidates_generated workflow phase.

Usage:
    python finalize_candidates.py --case-dir <case> --input <raw.json> [--append]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

CONFIDENCE_LEVELS = {"confirmed", "probable", "possible", "unknown", "not_observed"}

OBSERVED_EVENT_KEYS = [
    "event_type", "timestamp", "host", "user", "process_name", "command_line",
    "src_ip", "dst_ip", "file_path", "registry_key", "url", "domain", "hash",
    "raw_summary",
]

FORBIDDEN_FACT_TERMS = [
    "攻撃者", "不正アクセス", "侵害", "持ち出し", "窃取", "エクスフィル",
    "attacker", "unauthorized", "compromise", "exfiltrat", "data theft",
    "initial access",
]


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_chunk(chunks_dir: Path, chunk_id: str) -> dict | None:
    path = chunks_dir / f"{chunk_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def validate_candidate(
    cand: dict, chunk: dict, errors: list[str], warnings: list[str]
) -> bool:
    """Return True if the candidate passes hard validation."""
    ok = True
    start = int(chunk.get("start_line", 1))
    end = int(chunk.get("end_line", 1))
    content = chunk.get("content", "")

    excerpt = cand.get("excerpt", "")
    if not excerpt or not str(excerpt).strip():
        errors.append("empty excerpt")
        ok = False
    elif str(excerpt) not in content:
        errors.append("excerpt is not a verbatim substring of the chunk content")
        ok = False

    lines = cand.get("source_lines")
    if (
        not isinstance(lines, (list, tuple))
        or len(lines) != 2
        or not all(isinstance(v, int) for v in lines)
    ):
        errors.append(f"source_lines must be [start, end] integers, got {lines!r}")
        ok = False
    else:
        lo, hi = lines
        if lo > hi:
            errors.append(f"source_lines start {lo} > end {hi}")
            ok = False
        if lo < start or hi > end:
            errors.append(
                f"source_lines {lines} outside chunk range [{start}, {end}]"
            )
            ok = False

    for field in ("observed_fact", "interpretation"):
        if not str(cand.get(field, "")).strip():
            errors.append(f"missing {field}")
            ok = False

    for field in ("observed_fact_confidence", "interpretation_confidence"):
        value = cand.get(field)
        if value not in CONFIDENCE_LEVELS:
            errors.append(f"{field}={value!r} not in {sorted(CONFIDENCE_LEVELS)}")
            ok = False

    fact = str(cand.get("observed_fact", ""))
    hits = [t for t in FORBIDDEN_FACT_TERMS if t.lower() in fact.lower()]
    if hits:
        # Interpretation labels leaking into the observed fact is a soft
        # failure: flag it so the agent rewrites the fact, but keep going
        # through the remaining checks.
        errors.append(f"observed_fact contains interpretation terms: {hits}")
        ok = False

    for mapping in cand.get("attack_mapping_candidates", []) or []:
        for key in ("tactic", "technique_id", "technique_name", "confidence",
                    "mapping_reason"):
            if not str(mapping.get(key, "")).strip():
                errors.append(f"attack mapping missing {key}: {mapping}")
                ok = False
                break
        if mapping.get("confidence") not in CONFIDENCE_LEVELS:
            errors.append(f"attack mapping confidence invalid: {mapping.get('confidence')!r}")
            ok = False

    if cand.get("interpretation_confidence") == "confirmed":
        warnings.append(
            "interpretation_confidence=confirmed — make sure the artifact "
            "directly states this conclusion"
        )
    return ok


def build_record(cand: dict, chunk: dict, source_record: dict) -> dict:
    excerpt = str(cand["excerpt"])
    lines = [int(cand["source_lines"][0]), int(cand["source_lines"][1])]
    observed_event = {
        key: cand.get("observed_event", {}).get(key) for key in OBSERVED_EVENT_KEYS
    }
    return {
        "candidate_id": str(uuid.uuid4()),
        "source_refs": [
            {
                "source_ref_id": str(uuid.uuid4()),
                "source_file_id": chunk.get("source_file_id", ""),
                "source_path": source_record.get("path", ""),
                "source_lines": lines,
                "excerpt": excerpt,
                "excerpt_sha256": sha256_hex(excerpt),
                "parser_name": None,
                "parser_version": None,
                "source_artifact_id": source_record.get("artifact_id"),
                "source_artifact_version_id": source_record.get("artifact_version_id"),
                "source_ingest_run_id": source_record.get("ingest_run_id"),
            }
        ],
        "observed_event": observed_event,
        "observed_fact": str(cand["observed_fact"]),
        "interpretation": str(cand["interpretation"]),
        "observed_fact_confidence": cand["observed_fact_confidence"],
        "interpretation_confidence": cand["interpretation_confidence"],
        "attack_mapping_candidates": [
            {
                "tactic": m.get("tactic", ""),
                "technique_id": m.get("technique_id", ""),
                "technique_name": m.get("technique_name", ""),
                "confidence": m.get("confidence", "unknown"),
                "mapping_reason": m.get("mapping_reason", ""),
            }
            for m in (cand.get("attack_mapping_candidates") or [])
        ],
        "from_normalized_event_ids": [],
        "candidate_status": "candidate",
        "review_status": "pending",
    }


def mark_phase(case_dir: Path) -> None:
    state_path = case_dir / "workflow_state.json"
    phase = "evidence_candidates_generated"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(f"warning: could not read {state_path}; workflow phase not updated")
        return
    completed = state.get("completed_phases", [])
    if phase not in completed:
        completed.append(phase)
    state["completed_phases"] = completed
    state["current_phase"] = phase
    stale = state.get("stale_phases", [])
    state["stale_phases"] = [p for p in stale if p != phase]
    state["last_updated_at"] = datetime.now(timezone.utc).isoformat()
    state["last_updated_by"] = "ir-extract-evidence-skill"
    state_path.write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def uncovered_sources(chunks_dir: Path, candidates_path: Path) -> list[str]:
    """Source files that were chunked but are cited by no candidate."""
    cited: set[str] = set()
    if candidates_path.exists():
        for line in candidates_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            for ref in record.get("source_refs") or []:
                cited.add(str(ref.get("source_file_id", "")))
    sources: dict[str, str] = {}
    for chunk_path in chunks_dir.glob("*.json"):
        try:
            chunk = json.loads(chunk_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        file_id = str(chunk.get("source_file_id", ""))
        sources.setdefault(file_id, str(chunk.get("source_path") or file_id))
    return sorted(path for fid, path in sources.items() if fid not in cited)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path,
                        help="Raw extraction JSON from the agent")
    parser.add_argument("--append", action="store_true",
                        help="Append to evidence_candidates.jsonl instead of rewriting")
    args = parser.parse_args()

    case_dir: Path = args.case_dir
    chunks_dir = case_dir / "data" / "chunks"
    if not chunks_dir.exists():
        print(f"error: {chunks_dir} not found — run 'ir-agent ingest' first")
        return 2

    raw = json.loads(args.input.read_text(encoding="utf-8"))
    extractions = raw.get("extractions", raw) if isinstance(raw, dict) else raw
    if not isinstance(extractions, list):
        print("error: input must be a list or {'extractions': [...]}")
        return 2

    inventory: dict[str, dict] = {}
    inventory_path = case_dir / "data" / "file_inventory.json"
    if inventory_path.exists():
        try:
            data = json.loads(inventory_path.read_text(encoding="utf-8"))
            records = data.get("files", data) if isinstance(data, dict) else data
            for record in records or []:
                if isinstance(record, dict) and record.get("file_id"):
                    inventory[record["file_id"]] = record
        except (OSError, json.JSONDecodeError):
            print(f"warning: could not parse {inventory_path}")

    accepted: list[dict] = []
    rejected = 0
    for block in extractions:
        chunk_id = block.get("chunk_id", "")
        chunk = load_chunk(chunks_dir, chunk_id)
        if chunk is None:
            print(f"REJECTED all candidates for unknown chunk {chunk_id!r}")
            rejected += len(block.get("candidates", []))
            continue
        source_record = inventory.get(chunk.get("source_file_id", ""), {})
        for idx, cand in enumerate(block.get("candidates", [])):
            errors: list[str] = []
            warnings: list[str] = []
            if validate_candidate(cand, chunk, errors, warnings):
                accepted.append(build_record(cand, chunk, source_record))
                for w in warnings:
                    print(f"warning [{chunk_id}#{idx}]: {w}")
            else:
                rejected += 1
                for e in errors:
                    print(f"REJECTED [{chunk_id}#{idx}]: {e}")

    out_path = case_dir / "data" / "evidence_candidates.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"
    with out_path.open(mode, encoding="utf-8") as f:
        for record in accepted:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"\naccepted: {len(accepted)}  rejected: {rejected}")
    print(f"written: {out_path} ({'append' if args.append else 'rewrite'})")

    uncovered = uncovered_sources(chunks_dir, out_path)
    if uncovered:
        print(f"\nwarning: {len(uncovered)} chunked file(s) have no candidates "
              "(re-check them, or state why they hold nothing relevant):")
        for path in uncovered:
            print(f"  - {path}")

    if accepted:
        mark_phase(case_dir)
        print("workflow phase marked: evidence_candidates_generated")
    if rejected:
        print("fix rejected candidates in the raw JSON and rerun")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
