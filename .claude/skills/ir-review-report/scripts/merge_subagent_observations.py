#!/usr/bin/env python3
"""Merge chunk-level SubAgent observations and build a coverage ledger.

SubAgents write one JSON file per chunk. This script concatenates their
observations and records which core source spans were actually covered. It does
not decide final checklist verdicts or claim assessments.

Usage:
    python merge_subagent_observations.py \
        --observations-dir subagent_observations \
        --chunk-manifest review_chunks/chunk_manifest.json \
        --out merged_observations.json \
        --coverage-ledger coverage_ledger.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import review_io

OBSERVATION_LISTS = (
    "checklist_observations",
    "conclusion_observations",
    "issue_observations",
    "open_questions",
)
SUBSTANTIVE_OBSERVATION_LISTS = (
    "checklist_observations",
    "conclusion_observations",
    "issue_observations",
)
REQUIRED_OBSERVATION_KEYS = {
    "chunk_id",
    "review_mode",
    "covered_span_ids",
    *OBSERVATION_LISTS,
}
ALLOWED_OBSERVATION_KEYS = {
    "schema_version",
    "reviewed_at",
    "metadata",
    *REQUIRED_OBSERVATION_KEYS,
}
LEGACY_OR_UNSUPPORTED_KEYS = {
    "reviewed_span_ids",
    "checklist_relevant_observations",
    "potential_issues",
    "claim_extractions",
    "evidence_hits",
}
OPEN_QUESTION_REQUIRED_KEYS = {
    "question_id",
    "question",
    "reason",
    "source_span_ids",
}


_SPAN_ID_TYPO = re.compile(r"^SPN[\s,_:.\-]*([0-9A-Za-z]+)$")


def load_source_span_ids(path: Path) -> set[str] | None:
    """Span ids that exist in source_index.json (None when not supplied/unreadable)."""
    if not path or not path.exists():
        return None
    data, error = review_io.load_json_safe(path)
    if error is not None or not isinstance(data, dict):
        return None
    return {
        str(s.get("source_span_id") or s.get("span_id") or s.get("id"))
        for s in data.get("spans", [])
        if isinstance(s, dict) and (s.get("source_span_id") or s.get("span_id") or s.get("id"))
    }


def sanitize_span_ids(
    row: dict[str, Any], known: set[str], sanitized: list[dict[str, Any]],
) -> None:
    """Repair or drop source_span_ids that do not exist in source_index.json.

    A SubAgent occasionally mistypes an id (e.g. "SPN, 1b2ac..."). Letting it
    through only surfaces later, as a gate failure the parent Agent then
    "fixes" by whatever passes. Repairing the obvious typo and dropping the
    rest here keeps every downstream file on real spans; what was changed is
    recorded in the coverage ledger so nothing is silently lost. The
    SubAgent's own file is never modified.
    """
    spans = row.get("source_span_ids")
    if not isinstance(spans, list):
        return
    kept: list[str] = []
    for sid in spans:
        sid = str(sid)
        if sid in known:
            kept.append(sid)
            continue
        match = _SPAN_ID_TYPO.match(sid.strip())
        repaired = f"SPN-{match.group(1)}" if match else None
        if repaired and repaired in known:
            kept.append(repaired)
            sanitized.append({
                "observation_id": row.get("observation_id") or row.get("question_id"),
                "original": sid, "repaired_to": repaired,
            })
        else:
            sanitized.append({
                "observation_id": row.get("observation_id") or row.get("question_id"),
                "original": sid, "repaired_to": None,
            })
    row["source_span_ids"] = list(dict.fromkeys(kept))


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def read_observation(
    observations_dir: Path, chunk_id: str
) -> tuple[Path | None, dict[str, Any] | None, str | None]:
    """Find and load this chunk's observation file.

    Returns ``(path, data, error)``: ``error`` is set (and ``data`` is
    ``None``) when the file exists but is not valid JSON — a SubAgent's Write
    can slip on that occasionally — so the caller can report exactly why
    instead of letting json.JSONDecodeError crash the whole merge with a raw
    traceback and abort every other chunk's coverage along with it.
    """
    candidates = [
        observations_dir / f"{chunk_id}.json",
        observations_dir / f"{chunk_id.lower()}.json",
    ]
    numeric = chunk_id.split("-")[-1]
    candidates.append(observations_dir / f"chunk_{numeric}.json")
    for path in candidates:
        if path.exists():
            data, error = review_io.load_json_safe(path)
            if error is not None:
                return path, None, error
            if not isinstance(data, dict):
                return path, None, "内容が JSON object ではありません"
            return path, data, None
    return None, None, None


def normalize_span_ids(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(v) for v in values if str(v).strip()]


def validate_observation(
    *,
    path: Path,
    observation: dict[str, Any],
    chunk_id: str,
    mode: str | None,
    allowed_span_ids: set[str],
) -> list[str]:
    problems: list[str] = []
    keys = set(observation)
    missing = sorted(REQUIRED_OBSERVATION_KEYS - keys)
    if missing:
        problems.append(f"{path}: required keys missing: {', '.join(missing)}")

    unsupported = sorted(keys - ALLOWED_OBSERVATION_KEYS)
    if unsupported:
        problems.append(f"{path}: unsupported top-level keys: {', '.join(unsupported)}")

    legacy = sorted(keys & LEGACY_OR_UNSUPPORTED_KEYS)
    if legacy:
        problems.append(
            f"{path}: legacy/unsupported SubAgent schema keys are not allowed: "
            + ", ".join(legacy)
        )

    observed_chunk_id = str(observation.get("chunk_id") or "")
    if observed_chunk_id != chunk_id:
        problems.append(
            f"{path}: chunk_id {observed_chunk_id!r} does not match manifest {chunk_id!r}"
        )

    observed_mode = str(observation.get("review_mode") or "")
    if mode and observed_mode != mode:
        problems.append(
            f"{path}: review_mode {observed_mode!r} does not match manifest mode {mode!r}"
        )

    covered_raw = observation.get("covered_span_ids")
    if not isinstance(covered_raw, list):
        problems.append(f"{path}: covered_span_ids must be a non-empty list")
    else:
        covered_ids = normalize_span_ids(covered_raw)
        if not covered_ids:
            problems.append(f"{path}: covered_span_ids must be a non-empty list")
        unknown = sorted(set(covered_ids) - allowed_span_ids)
        if unknown:
            problems.append(
                f"{path}: covered_span_ids contains spans outside assigned/overlap spans: "
                + ", ".join(unknown[:10])
            )

    for key in OBSERVATION_LISTS:
        rows = observation.get(key)
        if not isinstance(rows, list):
            problems.append(f"{path}: {key} must be a list")
            continue
        bad_rows = [idx for idx, row in enumerate(rows, 1) if not isinstance(row, dict)]
        if bad_rows:
            problems.append(
                f"{path}: {key} entries must be JSON objects; bad row numbers: "
                + ", ".join(str(i) for i in bad_rows[:10])
            )
        if key == "open_questions":
            for idx, row in enumerate(rows, 1):
                if not isinstance(row, dict):
                    continue
                missing_question_keys = sorted(OPEN_QUESTION_REQUIRED_KEYS - set(row))
                if missing_question_keys:
                    problems.append(
                        f"{path}: open_questions row {idx} missing required keys: "
                        + ", ".join(missing_question_keys)
                    )
                if "source_span_ids" in row and not isinstance(row.get("source_span_ids"), list):
                    problems.append(
                        f"{path}: open_questions row {idx} source_span_ids must be a list"
                    )
                if "related_checklist_ids" in row and not isinstance(
                    row.get("related_checklist_ids"), list
                ):
                    problems.append(
                        f"{path}: open_questions row {idx} related_checklist_ids must be a list"
                    )

    return problems


def main() -> int:
    review_io.require_via_review_status("merge_subagent_observations.py")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations-dir", required=True, type=Path)
    parser.add_argument("--chunk-manifest", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--coverage-ledger", required=True, type=Path)
    parser.add_argument(
        "--source-index", type=Path,
        help="source_index.json; span ids in observations that do not exist are "
             "repaired (obvious typos) or dropped, and recorded in the ledger",
    )
    args = parser.parse_args()

    if not args.chunk_manifest.exists():
        print(f"error: chunk manifest not found: {args.chunk_manifest}", file=sys.stderr)
        return 2
    if not args.observations_dir.exists():
        print(f"error: observations dir not found: {args.observations_dir}", file=sys.stderr)
        return 2

    try:
        manifest = load_json(args.chunk_manifest)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    manifest_mode = manifest.get("mode")
    manifest_mode = str(manifest_mode) if manifest_mode else None
    merged: dict[str, Any] = {
        "schema_version": "1.0",
        "source_index_path": manifest.get("source_index_path"),
        "mode": manifest_mode,
        "chunks": [],
        "checklist_observations": [],
        "conclusion_observations": [],
        "issue_observations": [],
        "open_questions": [],
    }
    ledger_chunks: list[dict[str, Any]] = []
    all_core_ids: list[str] = []
    covered_core_ids: list[str] = []
    coverage_counter: Counter[str] = Counter()
    problems: list[str] = []
    known_spans = load_source_span_ids(args.source_index) if args.source_index else None
    sanitized_spans: list[dict[str, Any]] = []

    for chunk in manifest.get("chunks", []):
        if not isinstance(chunk, dict):
            continue
        chunk_id = str(chunk.get("chunk_id") or "")
        core_ids = normalize_span_ids(chunk.get("core_span_ids"))
        if not chunk_id:
            problems.append("manifest contains chunk without chunk_id")
            continue
        all_core_ids.extend(core_ids)
        path, observation, obs_error = read_observation(args.observations_dir, chunk_id)
        if observation is None:
            if obs_error is not None:
                problems.append(f"{chunk_id}: observation file is invalid ({obs_error}): {path}")
                status = "invalid_observation"
            else:
                problems.append(f"{chunk_id}: observation file is missing")
                status = "missing_observation"
            ledger_chunks.append({
                "chunk_id": chunk_id,
                "assigned_span_ids": core_ids,
                "covered_span_ids": [],
                "status": status,
                "observation_path": str(path) if path else None,
            })
            continue

        overlap_ids = normalize_span_ids(chunk.get("overlap_span_ids"))
        allowed_span_ids = set(core_ids) | set(overlap_ids)
        problems.extend(
            validate_observation(
                path=path,
                observation=observation,
                chunk_id=chunk_id,
                mode=manifest_mode,
                allowed_span_ids=allowed_span_ids,
            )
        )
        covered_ids = normalize_span_ids(observation.get("covered_span_ids"))
        covered_core = [sid for sid in covered_ids if sid in set(core_ids)]
        for sid in covered_core:
            coverage_counter[sid] += 1
        covered_core_ids.extend(covered_core)

        merged["chunks"].append({
            "chunk_id": chunk_id,
            "observation_path": str(path),
            "status": "completed",
        })
        for key in OBSERVATION_LISTS:
            rows = observation.get(key, [])
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, dict):
                        row = dict(row)
                        row.setdefault("chunk_id", chunk_id)
                        if known_spans is not None:
                            sanitize_span_ids(row, known_spans, sanitized_spans)
                        merged[key].append(row)

        missing_core = sorted(set(core_ids) - set(covered_core))
        ledger_chunks.append({
            "chunk_id": chunk_id,
            "assigned_span_ids": core_ids,
            "covered_span_ids": covered_core,
            "missing_assigned_span_ids": missing_core,
            "status": "completed" if not missing_core else "incomplete",
            "observation_path": str(path),
        })

    unique_core = sorted(set(all_core_ids))
    unique_covered = sorted(set(covered_core_ids))
    uncovered = sorted(set(unique_core) - set(unique_covered))
    duplicate = sorted([sid for sid, count in coverage_counter.items() if count > 1])
    has_substantive_observations = any(
        merged[key] for key in SUBSTANTIVE_OBSERVATION_LISTS
    )
    if not has_substantive_observations:
        problems.append(
            "no substantive observations were merged; SubAgent outputs must include "
            "at least one checklist_observations, conclusion_observations, or "
            "issue_observations entry"
        )
    ledger = {
        "schema_version": "1.0",
        "source_span_count": len(unique_core),
        "chunks": ledger_chunks,
        "uncovered_span_ids": uncovered,
        "duplicate_coverage_span_ids": duplicate,
        "coverage_complete": not uncovered and not any(
            c["status"] in ("missing_observation", "invalid_observation")
            for c in ledger_chunks
        ),
        "sanitized_span_ids": sanitized_spans,
        "problems": problems,
    }

    review_io.atomic_write_json(args.out, merged)
    review_io.atomic_write_json(args.coverage_ledger, ledger)

    print(
        f"merged {len(merged['chunks'])} observations; "
        f"coverage_complete={ledger['coverage_complete']}"
    )
    if sanitized_spans:
        dropped = sum(1 for x in sanitized_spans if x["repaired_to"] is None)
        print(
            f"note: {len(sanitized_spans)} invalid source_span_ids in observations "
            f"auto-handled ({len(sanitized_spans) - dropped} repaired, {dropped} dropped); "
            "see sanitized_span_ids in the coverage ledger"
        )
    if problems or not ledger["coverage_complete"]:
        print("error: SubAgent observation merge failed validation", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        if not ledger["coverage_complete"]:
            print("  - coverage_ledger.coverage_complete is false", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
