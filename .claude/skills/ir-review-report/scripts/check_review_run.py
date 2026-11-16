#!/usr/bin/env python3
"""Validate review-run artifact hygiene.

This check enforces the operational rules for ir-review-report:

* final_review.md is the only final review artifact.
* ad-hoc Python files are not created inside the review run directory.
* required machine-readable artifacts, including claim_assessments.json, exist.
* SubAgent chunk artifacts and coverage ledgers exist and are non-empty.
* SubAgent task files include the review chunk, checklist items, and output schema.
* every open_question a SubAgent raised is traceable into issues.json or
  claim_assessments.json (via source_observation_ids), not silently dropped.
* alternative checklist-result filenames are not left as review artifacts.
* unexpected intermediate/final files are not left in the review run directory.

It does not judge report quality. It prevents review runs from becoming a pile
of one-off evaluators and competing "final" Markdown files.

Usage:
    python check_review_run.py --review-dir reviews/ReportB/20260912-224117_codex
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import review_io

REQUIRED_FILES = {
    "claim_assessments.json",
    "coverage_summary.json",
    "coverage_ledger.json",
    "final_review.md",
    "issues.json",
    "issues_normalized.json",
    "mechanical_checks.json",
    "merged_observations.json",
    "normalized.txt",
    "results.json",
    "run_manifest.json",
    "source_index.json",
    "summary.json",
    "summary.md",
}

ALLOWED_FILES = REQUIRED_FILES | {
    "repair_instructions.json",
    "run_log.jsonl",
    "aggregation_worksheet.json",
    # Derived, read-only view of final_review.md (render_review_html.py).
    "final_review.html",
}
REQUIRED_DIRS = {
    "review_chunks",
    "subagent_tasks",
    "subagent_observations",
}
ALLOWED_DIRS = REQUIRED_DIRS

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

def _json_object(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _list_json_files(path: Path) -> list[Path]:
    return sorted(p for p in path.glob("*.json") if p.is_file())


def _validate_subagent_observation_schema(path: Path, problems: list[str]) -> None:
    data = _json_object(path)
    if data is None:
        problems.append(
            f"{path.relative_to(path.parents[1])}: SubAgent observation must be a JSON "
            f"object — {review_io.describe_json_problem(path)}"
        )
        return

    keys = set(data)
    missing = sorted(REQUIRED_OBSERVATION_KEYS - keys)
    if missing:
        problems.append(
            f"{path.name}: SubAgent observation required keys missing: "
            + ", ".join(missing)
        )

    unsupported = sorted(keys - ALLOWED_OBSERVATION_KEYS)
    if unsupported:
        problems.append(
            f"{path.name}: SubAgent observation has unsupported keys: "
            + ", ".join(unsupported)
        )

    legacy = sorted(keys & LEGACY_OR_UNSUPPORTED_KEYS)
    if legacy:
        problems.append(
            f"{path.name}: legacy/unsupported SubAgent schema keys are not allowed: "
            + ", ".join(legacy)
        )

    if not isinstance(data.get("covered_span_ids"), list) or not data.get("covered_span_ids"):
        problems.append(f"{path.name}: covered_span_ids must be a non-empty list")

    for key in OBSERVATION_LISTS:
        value = data.get(key)
        if not isinstance(value, list):
            problems.append(f"{path.name}: {key} must be a list")
            continue
        bad_rows = [
            idx for idx, row in enumerate(value, 1)
            if not isinstance(row, dict)
        ]
        if bad_rows:
            problems.append(
                f"{path.name}: {key} entries must be JSON objects; bad row numbers: "
                + ", ".join(str(i) for i in bad_rows[:10])
            )
        if key == "open_questions":
            for idx, row in enumerate(value, 1):
                if not isinstance(row, dict):
                    continue
                missing_question_keys = sorted(OPEN_QUESTION_REQUIRED_KEYS - set(row))
                if missing_question_keys:
                    problems.append(
                        f"{path.name}: open_questions row {idx} missing required keys: "
                        + ", ".join(missing_question_keys)
                    )
                if "source_span_ids" in row and not isinstance(row.get("source_span_ids"), list):
                    problems.append(
                        f"{path.name}: open_questions row {idx} source_span_ids must be a list"
                    )
                if "related_checklist_ids" in row and not isinstance(
                    row.get("related_checklist_ids"), list
                ):
                    problems.append(
                        f"{path.name}: open_questions row {idx} related_checklist_ids must be a list"
                    )


def _validate_subagent_task_schema(path: Path, problems: list[str]) -> None:
    data = _json_object(path)
    if data is None:
        problems.append(
            f"{path.name}: SubAgent task must be a JSON object — "
            f"{review_io.describe_json_problem(path)}"
        )
        return
    required = {
        "task_id",
        "chunk_id",
        "review_mode",
        "chunk",
        "checklist_items",
        "major_conclusion_review_focus",
        "output_schema",
        "instructions",
    }
    missing = sorted(required - set(data))
    if missing:
        problems.append(
            f"{path.name}: SubAgent task required keys missing: "
            + ", ".join(missing)
        )
    if not isinstance(data.get("chunk"), dict):
        problems.append(f"{path.name}: chunk must be a JSON object")
    if not isinstance(data.get("checklist_items"), list) or not data.get("checklist_items"):
        problems.append(f"{path.name}: checklist_items must be a non-empty list")
    else:
        bad_items = [
            idx for idx, row in enumerate(data["checklist_items"], 1)
            if not isinstance(row, dict) or not row.get("id") or not row.get("text")
        ]
        if bad_items:
            problems.append(
                f"{path.name}: checklist_items entries must contain id and text; "
                "bad row numbers: " + ", ".join(str(i) for i in bad_items[:10])
            )
    schema = data.get("output_schema")
    if not isinstance(schema, dict):
        problems.append(f"{path.name}: output_schema must be a JSON object")
    else:
        required_keys = schema.get("required_top_level_keys")
        if not isinstance(required_keys, list):
            problems.append(f"{path.name}: output_schema.required_top_level_keys must be a list")
        else:
            missing_schema_keys = sorted(REQUIRED_OBSERVATION_KEYS - set(map(str, required_keys)))
            if missing_schema_keys:
                problems.append(
                    f"{path.name}: output_schema.required_top_level_keys missing: "
                    + ", ".join(missing_schema_keys)
                )


def _collect_referenced_observation_ids(review_dir: Path) -> set[str]:
    """IDs any issue/claim row has claimed via its optional source_observation_ids.

    This is the only place open_questions (and issue_observations more
    generally) leave a trace once the parent Agent has triaged them into
    issues.json or claim_assessments.json — there is no separate ledger file.
    """
    referenced: set[str] = set()

    issues_path = review_dir / "issues.json"
    if issues_path.exists():
        data = json.loads(issues_path.read_text(encoding="utf-8")) if issues_path.stat().st_size else None
        rows = []
        if isinstance(data, dict):
            rows = data.get("issues", [])
        elif isinstance(data, list):
            rows = data
        for row in rows:
            if isinstance(row, dict):
                referenced.update(
                    str(v) for v in (row.get("source_observation_ids") or []) if v
                )

    claims_path = review_dir / "claim_assessments.json"
    if claims_path.exists():
        data = _json_object(claims_path)
        if isinstance(data, dict):
            for key in (
                "conclusion_inventory", "consistency_assessments",
                "claim_assessments", "recommendation_assessments",
            ):
                for row in data.get(key, []) or []:
                    if isinstance(row, dict):
                        referenced.update(
                            str(v) for v in (row.get("source_observation_ids") or []) if v
                        )
    return referenced


def _open_question_ids(merged: dict) -> list[str]:
    return [
        str(q.get("question_id"))
        for q in merged.get("open_questions", [])
        if isinstance(q, dict) and q.get("question_id")
    ]


def _scripts_targeting_run(review_dir: Path) -> list[Path]:
    """Python files in the repository root, ``reviews/`` or the case directory
    (the places one-off evaluators get dropped) that name this run's id.

    The repository root is the nearest ancestor holding ``.git``; without one,
    nothing is scanned. ``_scratch`` quarantine folders are not scanned.
    """
    resolved = review_dir.resolve()
    root = next((p for p in resolved.parents if (p / ".git").exists()), None)
    if root is None:
        return []
    run_id = resolved.name
    places = {root}
    for parent in resolved.parents:
        if parent == root:
            break
        if parent.name == "reviews":
            places.update({parent, parent.parent})
    hits: list[Path] = []
    for place in sorted(places):
        for path in sorted(place.glob("*.py")):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if run_id in text:
                hits.append(path.relative_to(root))
    return hits


def main() -> int:
    review_io.require_via_review_status("check_review_run.py")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-dir", required=True, type=Path)
    args = parser.parse_args()

    review_dir = args.review_dir
    problems: list[str] = []
    if not review_dir.exists() or not review_dir.is_dir():
        print(f"FAIL: review directory not found: {review_dir}")
        return 1

    for name in sorted(REQUIRED_FILES):
        if not (review_dir / name).exists():
            problems.append(f"required artifact missing: {name}")

    for name in sorted(REQUIRED_DIRS):
        path = review_dir / name
        if not path.exists() or not path.is_dir():
            problems.append(f"required review directory missing: {name}")

    unexpected_dirs = sorted(
        p.name for p in review_dir.iterdir()
        if p.is_dir() and not p.name.startswith(".") and p.name not in ALLOWED_DIRS
    )
    if unexpected_dirs:
        problems.append(
            "unexpected directories are not allowed in completed review run "
            "directories; keep only the standard directories: "
            + ", ".join(unexpected_dirs)
        )

    forbidden_result_files = sorted(
        p.name for p in review_dir.glob("results*.json") if p.name != "results.json"
    )
    if forbidden_result_files:
        problems.append(
            "alternative checklist-result files are not allowed in completed "
            "review run directories; consolidate into results.json: "
            + ", ".join(forbidden_result_files)
        )

    unexpected_files = sorted(
        p.name for p in review_dir.iterdir()
        if p.is_file() and not p.name.startswith(".") and p.name not in ALLOWED_FILES
    )
    if unexpected_files:
        problems.append(
            "unexpected files are not allowed in completed review run "
            "directories; keep only the standard artifact names: "
            + ", ".join(unexpected_files)
        )

    py_files = sorted(p.relative_to(review_dir) for p in review_dir.rglob("*.py"))
    if py_files:
        problems.append(
            "ad-hoc Python files are not allowed in review run directories: "
            + ", ".join(str(p) for p in py_files)
        )

    targeting = _scripts_targeting_run(review_dir)
    if targeting:
        problems.append(
            "ad-hoc Python files outside the review run directory reference this "
            "run (report-specific fixed mappings are not allowed; repair via "
            "repair_instructions.json / apply_suggested_results.py): "
            + ", ".join(str(p) for p in targeting)
        )

    markdown_finals = sorted(
        p.name for p in review_dir.glob("*final*review*.md")
        if p.name != "final_review.md"
    )
    if markdown_finals:
        problems.append(
            "final-review-like Markdown files are not allowed; use final_review.md only: "
            + ", ".join(markdown_finals)
        )

    claim_path = review_dir / "claim_assessments.json"
    if claim_path.exists():
        data = _json_object(claim_path)
        if data is None:
            problems.append(
                f"claim_assessments.json must be a JSON object — "
                f"{review_io.describe_json_problem(claim_path)}"
            )
        else:
            if not data.get("conclusion_inventory"):
                problems.append("claim_assessments.json must contain conclusion_inventory")
            if not data.get("consistency_assessments"):
                problems.append("claim_assessments.json must contain consistency_assessments")
            if not data.get("claim_assessments"):
                problems.append("claim_assessments.json must contain claim_assessments")

    chunk_dir = review_dir / "review_chunks"
    if chunk_dir.exists():
        if not (chunk_dir / "chunk_manifest.json").exists():
            problems.append("review_chunks/chunk_manifest.json is required")
        if not sorted(chunk_dir.glob("chunk_*.json")):
            problems.append("review_chunks must contain chunk_*.json files")

    task_dir = review_dir / "subagent_tasks"
    if task_dir.exists():
        if not (task_dir / "task_manifest.json").exists():
            problems.append("subagent_tasks/task_manifest.json is required")
        task_files = sorted(
            p for p in task_dir.glob("*.json")
            if p.name != "task_manifest.json"
        )
        if not task_files:
            problems.append("subagent_tasks must contain task JSON files")
        for path in task_files:
            _validate_subagent_task_schema(path, problems)

    observation_dir = review_dir / "subagent_observations"
    observation_files: list[Path] = []
    if observation_dir.exists():
        observation_files = _list_json_files(observation_dir)
        if not observation_files:
            problems.append("subagent_observations must contain at least one JSON file")
        for path in observation_files:
            _validate_subagent_observation_schema(path, problems)

    ledger_path = review_dir / "coverage_ledger.json"
    if ledger_path.exists():
        ledger = _json_object(ledger_path)
        if ledger is None:
            problems.append(
                f"coverage_ledger.json must be a JSON object — "
                f"{review_io.describe_json_problem(ledger_path)}"
            )
        else:
            if ledger.get("coverage_complete") is not True:
                problems.append("coverage_ledger.json must have coverage_complete: true")
            if ledger.get("uncovered_span_ids"):
                problems.append("coverage_ledger.json must not contain uncovered_span_ids")
            if ledger.get("problems"):
                problems.append("coverage_ledger.json must not contain problems")

    merged_path = review_dir / "merged_observations.json"
    if merged_path.exists():
        merged = _json_object(merged_path)
        if merged is None:
            problems.append(
                f"merged_observations.json must be a JSON object — "
                f"{review_io.describe_json_problem(merged_path)}"
            )
        else:
            if not merged.get("chunks"):
                problems.append("merged_observations.json must contain merged chunk records")
            for key in OBSERVATION_LISTS:
                if not isinstance(merged.get(key), list):
                    problems.append(f"merged_observations.json must contain list field {key}")
            if not any(merged.get(key) for key in SUBSTANTIVE_OBSERVATION_LISTS):
                problems.append(
                    "merged_observations.json has no substantive observations; "
                    "SubAgent outputs must be fixed before completion"
                )
            question_ids = _open_question_ids(merged)
            if question_ids:
                referenced = _collect_referenced_observation_ids(review_dir)
                untriaged = sorted(set(question_ids) - referenced)
                if untriaged:
                    problems.append(
                        "open_questions are not triaged: " + ", ".join(untriaged)
                        + " — merged_observations.json の open_questions は、"
                        "issues.json または claim_assessments.json のいずれかの行の "
                        "source_observation_ids でこの question_id を参照してください"
                        "（多くの場合 category: external_confirmation の issue になります）。"
                        "報告書全体を確認した結果、対応不要と判断した場合も、"
                        "その判断を記録した行から参照してください。黙って削除しない。"
                    )

    if problems:
        print(f"FAIL ({len(problems)}):")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("PASS: review run artifacts follow the ir-review-report rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
