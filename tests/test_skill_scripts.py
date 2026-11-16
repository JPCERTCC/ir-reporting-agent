"""Regression harness for the skill-bundled quality scripts.

The quality criteria live in the checklists and skill scripts under
.claude/skills/. The checklists are drafts that will be updated over time;
these tests pin down the behavioral contract so a checklist or script update
that breaks parsing, weakens detection, or introduces false positives is
caught by `pytest` immediately.

Fixtures:
  - fixtures/good_report.md    — a draft that satisfies the unified criteria
    (defang in prose, verbatim log excerpts in code blocks, contact section,
    access-warning notice, evidence IDs, hedged wording).
  - fixtures/flawed_report.md  — a short report violating most criteria.
  - fixtures/good_report_material.json — minimal case material (EV id list)
    for lint's evidence-ID resolution.
"""

from __future__ import annotations

import collections
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SKILLS = REPO / ".claude" / "skills"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

PARSE = SKILLS / "ir-review-report" / "scripts" / "parse_checklists.py"
INIT_RESULTS = SKILLS / "ir-review-report" / "scripts" / "init_results_template.py"
MECH = SKILLS / "ir-review-report" / "scripts" / "mechanical_checks.py"
COVER = SKILLS / "ir-review-report" / "scripts" / "check_coverage.py"
PREPARE = SKILLS / "ir-review-report" / "scripts" / "prepare_report.py"
BUILD_INDEX = SKILLS / "ir-review-report" / "scripts" / "build_source_index.py"
ASSESS = SKILLS / "ir-review-report" / "scripts" / "check_claim_assessments.py"
RENDER = SKILLS / "ir-review-report" / "scripts" / "render_review.py"
CHECK_RUN = SKILLS / "ir-review-report" / "scripts" / "check_review_run.py"
REVIEW_STATUS = SKILLS / "ir-review-report" / "scripts" / "review_status.py"
AGGREGATE = SKILLS / "ir-review-report" / "scripts" / "aggregate_observations.py"
ISSUES_SKELETON = SKILLS / "ir-review-report" / "scripts" / "init_issues_skeleton.py"
APPLY_SUGGESTED = SKILLS / "ir-review-report" / "scripts" / "apply_suggested_results.py"
ISSUE_CATEGORIES = {
    "evidence_integrity", "unsupported_claim", "certainty_inconsistency",
    "cross_section_inconsistency", "missing_required_item", "countermeasure_mapping",
    "format_or_usability", "external_confirmation", "optional_enhancement",
}
CLAIMS_SKELETON = SKILLS / "ir-review-report" / "scripts" / "init_claims_skeleton.py"
PREFILL_SPANS = SKILLS / "ir-review-report" / "scripts" / "prefill_result_spans.py"
ABSENCE_GROUNDING = SKILLS / "ir-review-report" / "scripts" / "check_absence_grounding.py"
RENDER_HTML = SKILLS / "ir-review-report" / "scripts" / "render_review_html.py"
CREATE_CHUNKS = SKILLS / "ir-review-report" / "scripts" / "create_review_chunks.py"
CREATE_TASKS = SKILLS / "ir-review-report" / "scripts" / "create_subagent_tasks.py"
MERGE_OBS = SKILLS / "ir-review-report" / "scripts" / "merge_subagent_observations.py"
MAKE_REPAIR = SKILLS / "ir-review-report" / "scripts" / "make_repair_instructions.py"
LINT = SKILLS / "ir-draft-report" / "scripts" / "lint_draft.py"
LINT_JA = SKILLS / "ir-draft-report" / "scripts" / "lint_ja_style.py"

# Stable IDs are derived from the explicit checklist item numbers.
SERIOUS_CHECK_ID = "REP-3.5-3"   # 直接証拠がない事項を断定していないか
OPTIONAL_CHECK_ID = "REP-2-1"    # 証拠保全記録(任意)
UNKNOWN_CHECK_ID = "REP-1-2"     # 調査目的の合意(報告書外確認になり得る)


def run(script: Path, *args: str, direct: bool = False,
        cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run a skill script the way review_status.py would (``direct=True`` runs it
    the way an Agent typing the command would, without that permission)."""
    env = dict(os.environ)
    if direct:
        env.pop("IR_REVIEW_VIA_STATUS", None)
    else:
        env["IR_REVIEW_VIA_STATUS"] = "1"
    return subprocess.run(
        [sys.executable, str(script), *args], capture_output=True, text=True,
        env=env, cwd=str(cwd) if cwd else None,
    )


@pytest.fixture(scope="module")
def items() -> list[dict]:
    proc = run(PARSE, "--mode", "both")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)["items"]


@pytest.fixture(scope="module")
def all_ids(items) -> list[str]:
    return [i["id"] for i in items]


# ---------------------------------------------------------------------------
# parse_checklists.py — the checklists stay machine-readable as they evolve
# ---------------------------------------------------------------------------


class TestParseChecklists:
    def test_both_sources_present_with_substance(self, items):
        by_source = {s: [i for i in items if i["source"] == s]
                     for s in ("customer", "reporter")}
        assert len(by_source["customer"]) >= 10
        assert len(by_source["reporter"]) >= 30

    def test_ids_unique_and_well_formed(self, items):
        ids = [i["id"] for i in items]
        assert len(ids) == len(set(ids))
        assert all(i["id"].startswith(("CUS-", "REP-")) for i in items)

    def test_every_item_has_section_and_text(self, items):
        assert all(i["section"].strip() and i["text"].strip() for i in items)

    def test_levels_are_valid_and_mandatory_items_exist(self, items):
        assert all(i["level"] in ("必須", "推奨", "任意", "-") for i in items)
        assert any(i["level"] == "必須" for i in items)

    def test_explicit_item_numbers_become_stable_ids(self, items):
        by_id = {i["id"]: i for i in items}
        assert by_id["CUS-2.3-2"]["text"] == "各IoCについて、種別、値、概要、確認箇所が記載されているか"
        assert by_id[SERIOUS_CHECK_ID]["level"] == "必須"
        assert by_id[OPTIONAL_CHECK_ID]["level"] == "任意"

    def test_new_review_metadata_fields_are_emitted(self, items):
        target = items[0]
        assert target["requirement_level"] in {
            "mandatory", "recommended", "optional", "unspecified"
        }
        assert isinstance(target["section_path"], list)
        assert target["applies_to"] in {
            "report_content", "pre_engagement", "investigation_process",
            "evidence_handling", "delivery",
        }
        assert isinstance(target["evaluable_from_report"], bool)
        assert isinstance(target["unknown_allowed"], bool)
        if target["evaluable_from_report"]:
            assert target["unknown_allowed"] is False

    @pytest.mark.parametrize("mode,source,prefix", [
        ("customer", "customer", "CUS-"),
        ("reporter", "reporter", "REP-"),
    ])
    def test_mode_filters_to_one_checklist(self, mode, source, prefix):
        proc = run(PARSE, "--mode", mode)
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)
        assert data["metadata"]["mode"] == mode
        assert data["items"]
        assert {i["source"] for i in data["items"]} == {source}
        assert all(i["id"].startswith(prefix) for i in data["items"])


class TestInitResultsTemplate:
    @pytest.mark.parametrize("mode,prefix", [
        ("customer", "CUS-"),
        ("reporter", "REP-"),
    ])
    def test_generates_one_mode_unscored_template(self, tmp_path, mode, prefix):
        out = tmp_path / "results.json"
        proc = run(INIT_RESULTS, "--mode", mode, "--out", str(out))
        assert proc.returncode == 0, proc.stderr
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["metadata"]["mode"] == mode
        results = data["results"]
        assert results
        assert all(r["checklist_id"].startswith(prefix) for r in results)
        assert all(r["verdict"] is None for r in results)
        assert all("rationale" in r for r in results)
        assert all("unknown_allowed" in r for r in results)
        assert all("source_span_ids" in r for r in results)
        assert all("absence_check_ids" in r for r in results)

    def test_template_is_not_a_completed_review(self, tmp_path):
        out = tmp_path / "results.json"
        proc = run(INIT_RESULTS, "--mode", "customer", "--out", str(out))
        assert proc.returncode == 0, proc.stderr
        proc = run(COVER, "--mode", "customer", "--results", str(out))
        assert proc.returncode == 1
        assert "invalid verdict None" in proc.stdout


class TestSubAgentWorkflowScripts:
    def _source_index(self, tmp_path: Path) -> Path:
        report = tmp_path / "normalized.txt"
        report.write_text(
            "# 1. 調査概要\n"
            "調査目的を記載しています。\n\n"
            "# 2. エグゼクティブサマリー\n"
            "VPN アカウントの悪用が初期侵入経路の可能性があります。\n\n"
            "# 3. 調査結果\n"
            "情報持ち出しは確認できませんでした。\n\n"
            "# 4. 推奨対策\n"
            "MFA の強化を推奨します。\n",
            encoding="utf-8",
        )
        source = tmp_path / "source_index.json"
        proc = run(BUILD_INDEX, "--source", str(report), "--out", str(source))
        assert proc.returncode == 0, proc.stderr
        return source

    def test_create_review_chunks_covers_every_span_once_as_core(self, tmp_path):
        source = self._source_index(tmp_path)
        out_dir = tmp_path / "review_chunks"
        proc = run(
            CREATE_CHUNKS,
            "--source-index", str(source),
            "--out-dir", str(out_dir),
            "--mode", "customer",
            "--max-spans", "2",
            "--overlap-spans", "1",
        )
        assert proc.returncode == 0, proc.stderr
        manifest = json.loads((out_dir / "chunk_manifest.json").read_text(encoding="utf-8"))
        source_data = json.loads(source.read_text(encoding="utf-8"))
        core_ids = [
            sid
            for chunk in manifest["chunks"]
            for sid in chunk["core_span_ids"]
        ]
        source_ids = [s["source_span_id"] for s in source_data["spans"]]
        assert sorted(core_ids) == sorted(source_ids)
        assert len(core_ids) == len(set(core_ids))
        assert (out_dir / "chunk_001.json").exists()

    def test_create_subagent_tasks_include_chunk_checklist_and_schema(self, tmp_path):
        source = self._source_index(tmp_path)
        chunks = tmp_path / "review_chunks"
        proc = run(
            CREATE_CHUNKS,
            "--source-index", str(source),
            "--out-dir", str(chunks),
            "--mode", "customer",
            "--max-spans", "99",
        )
        assert proc.returncode == 0, proc.stderr
        tasks = tmp_path / "subagent_tasks"
        proc = run(
            CREATE_TASKS,
            "--chunk-dir", str(chunks),
            "--out-dir", str(tasks),
            "--mode", "customer",
        )
        assert proc.returncode == 0, proc.stderr
        manifest = json.loads((tasks / "task_manifest.json").read_text(encoding="utf-8"))
        task_path = tasks / manifest["tasks"][0]["path"]
        task = json.loads(task_path.read_text(encoding="utf-8"))
        assert task["chunk"]["chunk_id"] == manifest["tasks"][0]["chunk_id"]
        assert task["checklist_items"]
        assert all(row["id"].startswith("CUS-") for row in task["checklist_items"])
        assert "covered_span_ids" in task["output_schema"]["required_top_level_keys"]
        assert "reviewed_span_ids" in task["output_schema"]["forbidden_top_level_keys"]

        # SubAgent must know where to write, and the parent gets the task path.
        expected_output = tmp_path / "subagent_observations" / f"{task['chunk_id']}.json"
        assert task["observation_output_path"] == str(expected_output)
        assert manifest["tasks"][0]["observation_output_path"] == str(expected_output)
        assert manifest["tasks"][0]["task_path"] == str(task_path)
        assert any(str(expected_output) in line for line in task["instructions"])

        # The SubAgent must be told the review purpose, its partial view, and verdict rules.
        ctx = task["review_context"]
        assert "チェックリスト" in ctx["purpose"]
        assert "chunk" in ctx["your_role"]
        assert any("unknown_allowed" in rule for rule in ctx["verdict_rules"])
        assert any("記載がない項目" in rule for rule in ctx["verdict_rules"])

        # Allowed values must match references/json_contracts.md.
        allowed = task["output_schema"]["allowed_values"]
        assert "lateral_movement" in allowed["topic"]
        assert "highly_likely" in allowed["confidence_language"]
        assert "evidence_integrity" in allowed["category"]
        assert "critical" in allowed["severity_hint"]

    def test_merge_subagent_observations_builds_coverage_ledger(self, tmp_path):
        source = self._source_index(tmp_path)
        chunks = tmp_path / "review_chunks"
        proc = run(
            CREATE_CHUNKS,
            "--source-index", str(source),
            "--out-dir", str(chunks),
            "--mode", "customer",
            "--max-spans", "99",
        )
        assert proc.returncode == 0, proc.stderr
        manifest = json.loads((chunks / "chunk_manifest.json").read_text(encoding="utf-8"))
        chunk = manifest["chunks"][0]
        obs_dir = tmp_path / "subagent_observations"
        obs_dir.mkdir()
        (obs_dir / f"{chunk['chunk_id']}.json").write_text(
            json.dumps({
                "chunk_id": chunk["chunk_id"],
                "review_mode": "customer",
                "covered_span_ids": chunk["core_span_ids"],
                "checklist_observations": [
                    {
                        "observation_id": "OBS-001",
                        "checklist_id": "CUS-1.1",
                        "candidate_verdict": "met",
                        "source_span_ids": [chunk["core_span_ids"][0]],
                    }
                ],
                "conclusion_observations": [],
                "issue_observations": [],
                "open_questions": [],
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        merged = tmp_path / "merged_observations.json"
        ledger = tmp_path / "coverage_ledger.json"
        proc = run(
            MERGE_OBS,
            "--observations-dir", str(obs_dir),
            "--chunk-manifest", str(chunks / "chunk_manifest.json"),
            "--out", str(merged),
            "--coverage-ledger", str(ledger),
        )
        assert proc.returncode == 0, proc.stderr
        ledger_data = json.loads(ledger.read_text(encoding="utf-8"))
        merged_data = json.loads(merged.read_text(encoding="utf-8"))
        assert ledger_data["coverage_complete"] is True
        assert not ledger_data["uncovered_span_ids"]
        assert merged_data["checklist_observations"][0]["chunk_id"] == chunk["chunk_id"]

    def test_malformed_observation_file_does_not_crash_the_merge(self, tmp_path):
        # Regression test: a SubAgent's Write can slip and leave invalid JSON.
        # Before this fix, that raised an uncaught json.JSONDecodeError from
        # inside the per-chunk loop — a raw Python traceback that aborted the
        # merge entirely, losing every other chunk's valid coverage along
        # with it, instead of a clean per-chunk problem.
        source = self._source_index(tmp_path)
        chunks = tmp_path / "review_chunks"
        assert run(
            CREATE_CHUNKS, "--source-index", str(source), "--out-dir", str(chunks),
            "--mode", "customer", "--max-spans", "2", "--overlap-spans", "0",
        ).returncode == 0
        manifest = json.loads((chunks / "chunk_manifest.json").read_text(encoding="utf-8"))
        assert len(manifest["chunks"]) >= 2
        obs_dir = tmp_path / "subagent_observations"
        obs_dir.mkdir()
        good_chunk = manifest["chunks"][0]
        bad_chunk = manifest["chunks"][1]
        (obs_dir / f"{good_chunk['chunk_id']}.json").write_text(json.dumps({
            "chunk_id": good_chunk["chunk_id"], "review_mode": "customer",
            "covered_span_ids": good_chunk["core_span_ids"],
            "checklist_observations": [{
                "observation_id": "OBS-001", "checklist_id": "CUS-1.1",
                "candidate_verdict": "met", "source_span_ids": [good_chunk["core_span_ids"][0]],
            }],
            "conclusion_observations": [], "issue_observations": [], "open_questions": [],
        }, ensure_ascii=False), encoding="utf-8")
        (obs_dir / f"{bad_chunk['chunk_id']}.json").write_text(
            '{"chunk_id": "' + bad_chunk["chunk_id"] + '",}',  # trailing comma
            encoding="utf-8",
        )
        proc = run(
            MERGE_OBS,
            "--observations-dir", str(obs_dir),
            "--chunk-manifest", str(chunks / "chunk_manifest.json"),
            "--out", str(tmp_path / "merged_observations.json"),
            "--coverage-ledger", str(tmp_path / "coverage_ledger.json"),
        )
        # A clean, structured failure — not a crash.
        assert proc.returncode == 1
        assert "Traceback" not in proc.stderr
        assert bad_chunk["chunk_id"] in proc.stderr
        assert "invalid" in proc.stderr
        # The good chunk's observation must still have been merged.
        merged_data = json.loads((tmp_path / "merged_observations.json").read_text(encoding="utf-8"))
        assert merged_data["checklist_observations"][0]["chunk_id"] == good_chunk["chunk_id"]
        ledger_data = json.loads((tmp_path / "coverage_ledger.json").read_text(encoding="utf-8"))
        bad_ledger_entry = next(
            c for c in ledger_data["chunks"] if c["chunk_id"] == bad_chunk["chunk_id"]
        )
        assert bad_ledger_entry["status"] == "invalid_observation"
        assert ledger_data["coverage_complete"] is False

    def test_merge_subagent_observations_rejects_legacy_schema(self, tmp_path):
        source = self._source_index(tmp_path)
        chunks = tmp_path / "review_chunks"
        proc = run(
            CREATE_CHUNKS,
            "--source-index", str(source),
            "--out-dir", str(chunks),
            "--mode", "customer",
            "--max-spans", "99",
        )
        assert proc.returncode == 0, proc.stderr
        manifest = json.loads((chunks / "chunk_manifest.json").read_text(encoding="utf-8"))
        chunk = manifest["chunks"][0]
        obs_dir = tmp_path / "subagent_observations"
        obs_dir.mkdir()
        (obs_dir / f"{chunk['chunk_id']}.json").write_text(
            json.dumps({
                "chunk_id": chunk["chunk_id"],
                "review_mode": "customer",
                "reviewed_span_ids": chunk["core_span_ids"],
                "checklist_relevant_observations": [],
                "potential_issues": [],
                "claim_extractions": [],
                "evidence_hits": [],
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        proc = run(
            MERGE_OBS,
            "--observations-dir", str(obs_dir),
            "--chunk-manifest", str(chunks / "chunk_manifest.json"),
            "--out", str(tmp_path / "merged_observations.json"),
            "--coverage-ledger", str(tmp_path / "coverage_ledger.json"),
        )
        assert proc.returncode == 1
        assert "legacy/unsupported SubAgent schema keys" in proc.stderr
        assert "required keys missing" in proc.stderr

    def test_merge_subagent_observations_rejects_empty_substantive_observations(self, tmp_path):
        source = self._source_index(tmp_path)
        chunks = tmp_path / "review_chunks"
        proc = run(
            CREATE_CHUNKS,
            "--source-index", str(source),
            "--out-dir", str(chunks),
            "--mode", "customer",
            "--max-spans", "99",
        )
        assert proc.returncode == 0, proc.stderr
        manifest = json.loads((chunks / "chunk_manifest.json").read_text(encoding="utf-8"))
        chunk = manifest["chunks"][0]
        obs_dir = tmp_path / "subagent_observations"
        obs_dir.mkdir()
        (obs_dir / f"{chunk['chunk_id']}.json").write_text(
            json.dumps({
                "chunk_id": chunk["chunk_id"],
                "review_mode": "customer",
                "covered_span_ids": chunk["core_span_ids"],
                "checklist_observations": [],
                "conclusion_observations": [],
                "issue_observations": [],
                "open_questions": [],
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        proc = run(
            MERGE_OBS,
            "--observations-dir", str(obs_dir),
            "--chunk-manifest", str(chunks / "chunk_manifest.json"),
            "--out", str(tmp_path / "merged_observations.json"),
            "--coverage-ledger", str(tmp_path / "coverage_ledger.json"),
        )
        assert proc.returncode == 1
        assert "no substantive observations" in proc.stderr

    def test_merge_subagent_observations_rejects_string_open_questions(self, tmp_path):
        source = self._source_index(tmp_path)
        chunks = tmp_path / "review_chunks"
        proc = run(
            CREATE_CHUNKS,
            "--source-index", str(source),
            "--out-dir", str(chunks),
            "--mode", "customer",
            "--max-spans", "99",
        )
        assert proc.returncode == 0, proc.stderr
        manifest = json.loads((chunks / "chunk_manifest.json").read_text(encoding="utf-8"))
        chunk = manifest["chunks"][0]
        obs_dir = tmp_path / "subagent_observations"
        obs_dir.mkdir()
        (obs_dir / f"{chunk['chunk_id']}.json").write_text(
            json.dumps({
                "chunk_id": chunk["chunk_id"],
                "review_mode": "customer",
                "covered_span_ids": chunk["core_span_ids"],
                "checklist_observations": [
                    {
                        "observation_id": "OBS-001",
                        "checklist_id": "CUS-1.1",
                        "candidate_verdict": "met",
                        "source_span_ids": [chunk["core_span_ids"][0]],
                    }
                ],
                "conclusion_observations": [],
                "issue_observations": [],
                "open_questions": ["追加確認事項"],
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        proc = run(
            MERGE_OBS,
            "--observations-dir", str(obs_dir),
            "--chunk-manifest", str(chunks / "chunk_manifest.json"),
            "--out", str(tmp_path / "merged_observations.json"),
            "--coverage-ledger", str(tmp_path / "coverage_ledger.json"),
        )
        assert proc.returncode == 1
        assert "open_questions entries must be JSON objects" in proc.stderr

    def test_make_repair_instructions_normalizes_common_claim_failure(self, tmp_path):
        stdout = tmp_path / "gate.out"
        stdout.write_text(
            "CON-001: reported conclusion requires source_span_ids\n"
            "ASM-001: review_verdict 'aligned' invalid\n",
            encoding="utf-8",
        )
        out = tmp_path / "repair_instructions.json"
        proc = run(
            MAKE_REPAIR,
            "--gate", "check_claim_assessments.py",
            "--stdout", str(stdout),
            "--review-dir", str(tmp_path),
            "--out", str(out),
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["repairs"]
        assert any(r["target_file"] == "claim_assessments.json" for r in data["repairs"])
        assert any(r["allowed_values"] for r in data["repairs"])

    def test_make_repair_instructions_extracts_problems_from_json_blob(self, tmp_path):
        # check_claim_assessments.py (and check_coverage.py's summary output)
        # print one pretty-printed JSON object with a top-level "problems"
        # list, not one problem per plain-text line. Splitting that on
        # newlines yields JSON syntax noise ("{", "\"claim_assessments\": 1,")
        # instead of the actual problems, so this must be unwrapped first.
        stdout = tmp_path / "gate.out"
        stdout.write_text(json.dumps({
            "conclusion_inventory": 1,
            "consistency_assessments": 1,
            "claim_assessments": 1,
            "recommendation_assessments": 0,
            "problems": [
                "CON-001: not_reported conclusion requires absence_check_ids",
                "ASM-001: source_span_ids or absence_check_ids is required",
                "CNS-001: related_conclusion_ids must contain at least two IDs",
            ],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        out = tmp_path / "repair_instructions.json"
        proc = run(
            MAKE_REPAIR,
            "--gate", "check_claim_assessments.py",
            "--stdout", str(stdout),
            "--review-dir", str(tmp_path),
            "--out", str(out),
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(out.read_text(encoding="utf-8"))
        problems = {r["problem"] for r in data["repairs"]}
        # every repair must be one of the three real problems verbatim, never
        # a fragment of the surrounding JSON syntax
        assert problems == {
            "CON-001: not_reported conclusion requires absence_check_ids",
            "ASM-001: source_span_ids or absence_check_ids is required",
            "CNS-001: related_conclusion_ids must contain at least two IDs",
        }
        assert len(data["repairs"]) == 3

    def test_make_repair_instructions_gives_specific_fix_for_non_substantive_span(self, tmp_path):
        # Regression test for a real failure: an issue was grounded in a page
        # marker / confidentiality-footer span (correctly rejected by
        # check_issues.py's _is_non_substantive_span), but the old generic
        # "ground it somehow" instruction gave the Agent nothing actionable
        # and it FAILed the same gate three times in a row. The message
        # contains "ground" AND "source_span_ids", so it must be classified
        # by the specific branch, not fall through to the generic one.
        stdout = tmp_path / "gate.out"
        stdout.write_text(
            "ISS-001: non-substantive source_span_ids ['SPN-88cf39d40bdf'] "
            "cannot be used as issue grounding\n",
            encoding="utf-8",
        )
        out = tmp_path / "repair_instructions.json"
        proc = run(
            MAKE_REPAIR,
            "--gate", "check_issues.py",
            "--stdout", str(stdout),
            "--review-dir", str(tmp_path),
            "--out", str(out),
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data["repairs"]) == 1
        instruction = data["repairs"][0]["instruction"]
        # must not be the generic catch-all — that's what caused the loop
        assert "接地できない一般論の指摘は削除してください" not in instruction
        # must point at the one place the real grounding already lives
        assert "merged_observations.json" in instruction
        assert "checklist_observations" in instruction


# ---------------------------------------------------------------------------
# mechanical_checks.py — detection stays strong, false positives stay out
# ---------------------------------------------------------------------------

FLAW_KEYS = {
    "timezone_declared", "defang_ioc", "ioc_access_warning",
    "contact_point", "evidence_ids", "limitations_stated", "overclaim",
}


class TestMechanicalChecks:
    @staticmethod
    def _checks(report: Path) -> dict[str, str]:
        proc = run(MECH, "--report", str(report))
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)
        return {c["key"]: c["status"] for c in data["checks"]}

    def test_flawed_report_triggers_all_core_warnings(self):
        status = self._checks(FIXTURES / "flawed_report.md")
        warned = {k for k, s in status.items() if s == "warn"}
        assert FLAW_KEYS <= warned, f"missing detections: {FLAW_KEYS - warned}"

    def test_good_report_has_no_false_positives(self):
        status = self._checks(FIXTURES / "good_report.md")
        false_pos = {k for k in FLAW_KEYS if status.get(k) == "warn"}
        assert not false_pos, f"false positives on compliant report: {false_pos}"

    def test_raw_iocs_in_code_blocks_are_not_flagged(self, tmp_path):
        # Verbatim log excerpts keep raw IoCs; prose must stay clean.
        report = tmp_path / "r.md"
        report.write_text(
            "タイムゾーンは JST です。攻撃元は 198[.]51[.]100[.]77 です。\n"
            "攻撃関連のIPへはアクセスしないでください。問い合わせ先: SOC。\n"
            "証拠ID: EV-001。ログ欠損のため確認できない事項があります。\n\n"
            "```text\n2026-05-01 conn from 198.51.100.77 to 203.0.113.88\n```\n",
            encoding="utf-8",
        )
        status = self._checks(report)
        assert status["defang_ioc"] == "pass"

    def test_negated_assertion_is_not_an_overclaim(self, tmp_path):
        report = tmp_path / "r.md"
        report.write_text("データの窃取(受領)の成立は断定しません。\n", encoding="utf-8")
        assert self._checks(report)["overclaim"] == "pass"


# ---------------------------------------------------------------------------
# check_coverage.py — every checklist item must carry a valid verdict
# ---------------------------------------------------------------------------


class TestCheckCoverage:
    @staticmethod
    def _run(tmp_path: Path, results: list[dict]) -> subprocess.CompletedProcess:
        f = tmp_path / "results.json"
        f.write_text(json.dumps({"results": results}, ensure_ascii=False))
        return run(COVER, "--results", str(f))

    def test_full_coverage_passes(self, tmp_path, all_ids):
        results = [{"id": i, "verdict": "met"} for i in all_ids]
        assert self._run(tmp_path, results).returncode == 0

    def test_unknown_is_rejected_for_report_content_items(self, tmp_path, items):
        target = next(i for i in items if not i["unknown_allowed"])
        results = [{"id": i["id"], "verdict": "met"} for i in items]
        for row in results:
            if row["id"] == target["id"]:
                row["verdict"] = "unknown"
        proc = self._run(tmp_path, results)
        assert proc.returncode == 1
        assert "unknown is not allowed" in proc.stdout

    def test_missing_item_fails(self, tmp_path, all_ids):
        results = [{"id": i, "verdict": "met"} for i in all_ids[:-1]]
        proc = self._run(tmp_path, results)
        assert proc.returncode == 1
        assert "missing verdict" in proc.stdout

    def test_invalid_verdict_fails(self, tmp_path, all_ids):
        results = [{"id": i, "verdict": "met"} for i in all_ids]
        results[0]["verdict"] = "bogus"
        assert self._run(tmp_path, results).returncode == 1

    def test_not_met_requires_finding(self, tmp_path, all_ids):
        results = [{"id": i, "verdict": "met"} for i in all_ids]
        results[0] = {"id": all_ids[0], "verdict": "not_met", "finding": ""}
        proc = self._run(tmp_path, results)
        assert proc.returncode == 1
        assert "finding" in proc.stdout

    def test_new_schema_unknown_requires_reason(self, tmp_path, items):
        target = next(i for i in items if i["unknown_allowed"])
        results = [{"checklist_id": i["id"], "verdict": "met"} for i in items]
        for row in results:
            if row["checklist_id"] == target["id"]:
                row["verdict"] = "unknown"
        proc = self._run(tmp_path, results)
        assert proc.returncode == 1
        assert "unknown_reason" in proc.stdout

    def test_not_met_absence_requires_absence_id(self, tmp_path, all_ids):
        results = [{"checklist_id": i, "verdict": "met"} for i in all_ids]
        results[0] = {
            "checklist_id": all_ids[0],
            "verdict": "not_met",
            "rationale": "報告書に未記載です",
        }
        proc = self._run(tmp_path, results)
        assert proc.returncode == 1
        assert "absence_check_ids" in proc.stdout

    def test_out_of_scope_is_explicit_and_unscored(self, tmp_path, all_ids):
        results = [{"checklist_id": i, "verdict": "met"} for i in all_ids]
        results[0] = {
            "checklist_id": all_ids[0],
            "evaluation_scope": "out_of_scope",
            "verdict": None,
            "rationale": "別紙未提供のため本レビュー対象外",
        }
        summary = tmp_path / "summary.json"
        f = tmp_path / "results.json"
        f.write_text(json.dumps({"results": results}, ensure_ascii=False))
        proc = run(COVER, "--results", str(f), "--summary-json", str(summary))
        assert proc.returncode == 0, proc.stdout
        assert summary.exists()

    def test_customer_mode_does_not_require_reporter_items(self, tmp_path, items):
        customer = [i for i in items if i["source"] == "customer"]
        results = [{"id": i["id"], "verdict": "met"} for i in customer]
        f = tmp_path / "results.json"
        f.write_text(json.dumps({"results": results}, ensure_ascii=False))
        proc = run(COVER, "--mode", "customer", "--results", str(f))
        assert proc.returncode == 0, proc.stdout

    def test_reporter_mode_rejects_customer_items(self, tmp_path, items):
        reporter = [i for i in items if i["source"] == "reporter"]
        customer = next(i for i in items if i["source"] == "customer")
        results = [{"id": i["id"], "verdict": "met"} for i in reporter]
        results.append({"id": customer["id"], "verdict": "met"})
        f = tmp_path / "results.json"
        f.write_text(json.dumps({"results": results}, ensure_ascii=False))
        proc = run(COVER, "--mode", "reporter", "--results", str(f))
        assert proc.returncode == 1
        assert "unknown checklist id" in proc.stdout


# ---------------------------------------------------------------------------
# prepare_report.py — format auto-detection and normalization
# ---------------------------------------------------------------------------


class TestPrepareReport:
    def test_text_passthrough(self, tmp_path):
        out = tmp_path / "n.txt"
        proc = run(PREPARE, "--report", str(FIXTURES / "flawed_report.md"),
                   "--out", str(out))
        assert proc.returncode == 0
        assert "インシデント調査報告書" in out.read_text(encoding="utf-8")

    def test_docx_extraction_with_stdlib(self, tmp_path):
        doc = (
            '<?xml version="1.0"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/'
            'wordprocessingml/2006/main"><w:body>'
            "<w:p><w:r><w:t>調査報告書</w:t></w:r></w:p>"
            "<w:tbl><w:tr><w:tc><w:p><w:r><w:t>証拠ID</w:t></w:r></w:p></w:tc>"
            "<w:tc><w:p><w:r><w:t>EV-001</w:t></w:r></w:p></w:tc></w:tr></w:tbl>"
            "</w:body></w:document>"
        )
        docx = tmp_path / "sample.docx"
        with zipfile.ZipFile(docx, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", doc)
        out = tmp_path / "n.txt"
        proc = run(PREPARE, "--report", str(docx), "--out", str(out))
        assert proc.returncode == 0, proc.stderr
        text = out.read_text(encoding="utf-8")
        assert "調査報告書" in text and "EV-001" in text

    def test_unextractable_pdf_exits_3_with_guidance(self, tmp_path):
        pdf = tmp_path / "scan.pdf"
        pdf.write_bytes(b"%PDF-1.4\n%binary-only\n%%EOF")
        proc = run(PREPARE, "--report", str(pdf), "--out", str(tmp_path / "n.txt"))
        assert proc.returncode == 3
        assert "pdf" in proc.stderr.lower()

    def test_font_garbage_pdf_exits_3_not_success(self, tmp_path):
        # Some PDFs make the stdlib extractor return megabytes of embedded-font
        # data: lots of Latin-1 high bytes that clear the length threshold but
        # are not report text. That must fail plausibility, not exit 0.
        garbage = bytes(b for b in range(0xA0, 0xFF)) * 20  # no ()\ bytes
        body = b"stream\n(" + garbage + b") Tj\nendstream\n"
        pdf = tmp_path / "fontdata.pdf"
        pdf.write_bytes(b"%PDF-1.4\n" + body + b"%%EOF")
        proc = run(PREPARE, "--report", str(pdf), "--out", str(tmp_path / "n.txt"))
        assert proc.returncode == 3
        assert "plausible" in proc.stderr

    def test_plausible_stdlib_pdf_extraction_passes(self, tmp_path):
        line = b"(Incident investigation report for FS01, evidence E-101. ) Tj\n"
        body = b"stream\n" + line * 10 + b"endstream\n"
        pdf = tmp_path / "plain.pdf"
        pdf.write_bytes(b"%PDF-1.4\n" + body + b"%%EOF")
        out = tmp_path / "n.txt"
        proc = run(PREPARE, "--report", str(pdf), "--out", str(out))
        assert proc.returncode == 0, proc.stderr
        assert "E-101" in out.read_text(encoding="utf-8")

    def test_pypdf_preferred_when_available(self, tmp_path):
        pytest.importorskip("pypdf")
        import pypdf  # noqa: F401  (guard above ensures availability)
        from pypdf import PdfWriter

        pdf = tmp_path / "real.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        with pdf.open("wb") as fh:
            writer.write(fh)
        # A blank page extracts no text → plausibility fails → exit 3 (never
        # a garbage exit 0); with text-bearing PDFs pypdf output is used and
        # page markers are emitted (covered indirectly by extract_pdf_pypdf).
        proc = run(PREPARE, "--report", str(pdf), "--out", str(tmp_path / "n.txt"))
        assert proc.returncode == 3

    def test_missing_input_exits_2(self, tmp_path):
        proc = run(PREPARE, "--report", str(tmp_path / "nope.md"))
        assert proc.returncode == 2


# ---------------------------------------------------------------------------
# build_source_index.py — findings can point at real source spans
# ---------------------------------------------------------------------------


class TestBuildSourceIndex:
    def test_spans_have_stable_ids_and_values(self, tmp_path):
        report = tmp_path / "normalized.txt"
        report.write_text(
            "# 報告書\n\n"
            "根拠は E-101 で、接続元は 203.0.113.10 です。\n\n"
            "```text\nEventID=4624 AccountName=alice\n```\n",
            encoding="utf-8",
        )
        out = tmp_path / "source_index.json"
        proc = run(BUILD_INDEX, "--source", str(report), "--out", str(out))
        assert proc.returncode == 0, proc.stderr
        data = json.loads(out.read_text())
        assert data["spans"]
        assert all(s["source_span_id"].startswith("SPN-") for s in data["spans"])
        values = {(v["kind"], v["value"]) for s in data["spans"] for v in s["values"]}
        assert ("evidence_id", "E-101") in values
        assert ("ip", "203.0.113.10") in values
        assert any(s["kind"] == "code_block" for s in data["spans"])


# ---------------------------------------------------------------------------
# lint_ja_style.py — advisory Japanese-style linter (ja_writing_norms.md)
# ---------------------------------------------------------------------------


class TestLintJaStyle:
    @staticmethod
    def _checks(path: Path) -> dict[str, dict]:
        proc = run(LINT_JA, "--file", str(path))
        # Advisory: exits 0 whether or not warnings were found.
        assert proc.returncode == 0, proc.stderr
        return {c["key"]: c for c in json.loads(proc.stdout)["checks"]}

    def test_llm_phrases_duplicates_dashes_connectors_detected(self, tmp_path):
        doc = tmp_path / "bad.md"
        doc.write_text(
            "# x\n\n"
            "重要なのは、対策を多角的に掘り下げることであり、監視は不可欠と言えるでしょう。\n\n"
            "また、認証ログを確認しました。\n\n"
            "また、通信ログを確認しました。\n\n"
            "また、端末の調査を実施しました。\n\n"
            "本件では——結果として——複数の侵害が確認されました。\n\n"
            "同一の通信が複数回確認されており、追加の調査が必要です。\n\n"
            "同一の通信が複数回確認されており、追加の調査が必要です。\n",
            encoding="utf-8",
        )
        checks = self._checks(doc)
        assert checks["llm_phrases"]["status"] == "warn"
        assert {"重要なのは", "掘り下げ", "不可欠", "多角的"} <= {
            s.split(" ")[0] for s in checks["llm_phrases"]["samples"]
        }
        assert checks["duplicate_sentence"]["status"] == "warn"
        assert checks["dash_usage"]["status"] == "warn"
        assert checks["connector_chains"]["status"] == "warn"

    def test_long_sentence_threshold(self, tmp_path):
        doc = tmp_path / "long.md"
        doc.write_text("調査の結果" + "経緯と対応を整理し" * 30 + "ました。\n",
                       encoding="utf-8")
        assert self._checks(doc)["long_sentence"]["status"] == "warn"
        proc = run(LINT_JA, "--file", str(doc), "--max-sentence", "500")
        data = {c["key"]: c for c in json.loads(proc.stdout)["checks"]}
        assert data["long_sentence"]["status"] == "pass"

    def test_code_blocks_and_tables_excluded(self, tmp_path):
        doc = tmp_path / "quoted.md"
        doc.write_text(
            "調査結果を示します。\n\n"
            "```text\n重要なのは——非常に長いログ行 極めて 多角的\n```\n\n"
            "| 項目 | 内容 |\n|---|---|\n| 所見 | " + "あ" * 300 + " |\n",
            encoding="utf-8",
        )
        checks = self._checks(doc)
        assert checks["llm_phrases"]["status"] == "pass"
        assert checks["dash_usage"]["status"] == "pass"
        assert checks["long_sentence"]["status"] == "pass"

    def test_draft_watermark_dash_is_exempt(self, tmp_path):
        doc = tmp_path / "wm.md"
        doc.write_text("【ドラフト — 最終版ではありません】\n\n本文です。\n",
                       encoding="utf-8")
        assert self._checks(doc)["dash_usage"]["status"] == "pass"

    def test_good_report_fixture_has_no_style_false_positives(self):
        # long_sentence is deliberately not asserted: dense IR sentences with
        # evidence IDs can exceed the advisory limit even in a good draft.
        checks = self._checks(FIXTURES / "good_report.md")
        for key in ("llm_phrases", "duplicate_sentence", "dash_usage",
                    "connector_chains"):
            assert checks[key]["status"] == "pass", (key, checks[key]["samples"])


# ---------------------------------------------------------------------------
# lint_draft.py — the unified drafting standard
# ---------------------------------------------------------------------------


class TestLintDraft:
    @pytest.fixture()
    def case_dir(self, tmp_path) -> Path:
        case = tmp_path / "case"
        (case / "reports").mkdir(parents=True)
        draft = case / "reports" / "draft_report.md"
        shutil.copy(FIXTURES / "good_report.md", draft)
        shutil.copy(FIXTURES / "good_report_material.json",
                    case / "reports" / "case_material.json")
        # The lint rejects generation dates far from the run date, so pin
        # the fixture's date fields to today to keep the test date-independent.
        from datetime import date

        text = draft.read_text(encoding="utf-8")
        draft.write_text(
            text.replace("2026-07-09", date.today().isoformat()),
            encoding="utf-8",
        )
        return case

    @staticmethod
    def _mutate(case_dir: Path, old: str, new: str) -> None:
        p = case_dir / "reports" / "draft_report.md"
        text = p.read_text(encoding="utf-8")
        assert old in text, f"mutation anchor not found: {old!r}"
        p.write_text(text.replace(old, new), encoding="utf-8")

    def test_compliant_draft_passes(self, case_dir):
        proc = run(LINT, "--case-dir", str(case_dir))
        assert proc.returncode == 0, proc.stdout

    def test_missing_watermark_fails(self, case_dir):
        self._mutate(case_dir, "【ドラフト — 最終版ではありません】", "")
        assert run(LINT, "--case-dir", str(case_dir)).returncode == 1

    def test_raw_ioc_in_prose_fails(self, case_dir):
        self._mutate(case_dir, "## 3. 調査結果",
                     "## 3. 調査結果\n\n攻撃元は 198.51.100.77 でした。")
        proc = run(LINT, "--case-dir", str(case_dir))
        assert proc.returncode == 1
        assert "defang" in proc.stdout

    def test_unknown_evidence_id_fails(self, case_dir):
        self._mutate(case_dir, "（証拠ID: EV-001", "（証拠ID: EV-999, EV-001")
        proc = run(LINT, "--case-dir", str(case_dir))
        assert proc.returncode == 1
        assert "EV-999" in proc.stdout

    def test_missing_contact_section_fails(self, case_dir):
        self._mutate(case_dir, "### 本報告書に関する問い合わせ先",
                     "### 連絡窓口について")
        assert run(LINT, "--case-dir", str(case_dir)).returncode == 1

    def test_meta_narration_fails(self, case_dir):
        self._mutate(case_dir, "## 3. 調査結果",
                     "## 3. 調査結果\n\n提供された証拠を精読した結果、侵入が確認されました。")
        assert run(LINT, "--case-dir", str(case_dir)).returncode == 1


# ---------------------------------------------------------------------------
# check_evidence_ids.py — deterministic evidence-ID consistency
# ---------------------------------------------------------------------------

EIDS = SKILLS / "ir-review-report" / "scripts" / "check_evidence_ids.py"
CLAIMS = SKILLS / "ir-review-report" / "scripts" / "check_claims.py"

EID_REPORT = """# 報告書

## 1.6 調査対象・提供データ(証拠一覧)

| 証拠ID | ファイル名 | ハッシュ値 |
|---|---|---|
| E-101 | vpn.log | aaa |
| E-102 | fw.csv | bbb |
| E-103 | edr.csv | ccc |
| E-105 | mft.csv | ddd |
| E-105 | mft2.csv | eee |
| E-107 | disk.img | fff |
| E-115-01 | p1.pcap | 1 |
| E-115-02 | p2.pcap | 2 |
| E-115-03 | p3.pcap | 3 |
| E-115-04 | p4.pcap | 4 |

## 3. 調査結果

侵入は E-101 と Ｅ－１０２ から確認。空白入り E - 102 も参照。
PDF改行分割: 根拠は E-1
03 のログ。範囲: E-115-01～E-115-04 を確認。
未定義参照: 根拠は E-109 です。
"""


class TestCheckEvidenceIds:
    @pytest.fixture()
    def result(self, tmp_path) -> dict:
        report = tmp_path / "r.md"
        report.write_text(EID_REPORT, encoding="utf-8")
        proc = run(EIDS, "--report", str(report))
        assert proc.returncode == 1  # problems exist by design
        return json.loads(proc.stdout)

    def test_undefined_reference_is_a_problem(self, result):
        ids = [p["id"] for p in result["problems"]["undefined_references"]]
        assert ids == ["E-109"]

    def test_conflicting_definition_is_a_problem(self, result):
        ids = [p["id"] for p in result["problems"]["conflicting_definitions"]]
        assert ids == ["E-105"]

    def test_notation_variants_are_normalized(self, result):
        # Full-width, spaced, PDF-linebreak, and range forms all resolve to
        # canonical IDs; E-102 and E-103 must appear as references.
        refs = set()
        for p in result["problems"]["undefined_references"]:
            refs.add(p["id"])
        # E-102/E-103 referenced and defined → not in problems
        assert "E-102" not in refs and "E-103" not in refs
        variants = {v["normalized"] for v in result["info"]["notation_variants"]}
        assert "E-102" in variants  # "E - 102"
        assert {"E-115-01", "E-115-04"} <= variants  # range expansion

    def test_unreferenced_and_gaps_are_info_not_problems(self, result):
        assert "E-107" in result["info"]["unreferenced_defined"]
        assert result["info"]["numbering_gaps"]
        problem_ids = {
            p["id"]
            for kind in result["problems"].values()
            for p in kind
        }
        assert "E-107" not in problem_ids

    def test_clean_report_exits_zero(self, tmp_path):
        report = tmp_path / "ok.md"
        report.write_text(
            "## 証拠一覧\n\n| 証拠ID | ファイル |\n|---|---|\n| E-001 | a.log |\n\n"
            "## 結果\n\nE-001 を確認。\n",
            encoding="utf-8",
        )
        assert run(EIDS, "--report", str(report)).returncode == 0


# ---------------------------------------------------------------------------
# check_claims.py — claim-to-evidence machine checks
# ---------------------------------------------------------------------------


class TestCheckClaims:
    @staticmethod
    def _claim(cid, certainty, ev, ctype="finding", section="3.1", obj="initial_access"):
        return {
            "claim_id": cid,
            "location": {"section": section, "page": 1, "table": None},
            "subject": "svc-backup", "predicate": "was_used_for", "object": obj,
            "certainty": certainty, "time": None, "evidence_ids": ev,
            "quote": "引用文", "claim_type": ctype,
        }

    def _run(self, tmp_path, claims, defined=("E-101",)):
        cfile = tmp_path / "claims.json"
        cfile.write_text(json.dumps({"claims": claims}, ensure_ascii=False))
        efile = tmp_path / "eids.json"
        efile.write_text(json.dumps({"defined_ids": list(defined)}))
        proc = run(CLAIMS, "--claims", str(cfile), "--evidence-json", str(efile))
        return proc, json.loads(proc.stdout)

    def test_confirmed_finding_without_evidence_is_problem(self, tmp_path):
        proc, out = self._run(tmp_path, [self._claim("CLM-1", "confirmed", [])])
        assert proc.returncode == 1
        assert any("without supporting evidence" in p for p in out["problems"])

    def test_undefined_evidence_citation_is_problem(self, tmp_path):
        proc, out = self._run(tmp_path, [self._claim("CLM-1", "possible", ["E-999"])])
        assert proc.returncode == 1
        assert any("E-999" in p for p in out["problems"])

    def test_certainty_conflict_is_warning_not_problem(self, tmp_path):
        claims = [
            self._claim("CLM-1", "confirmed", ["E-101"], section="3.2"),
            self._claim("CLM-2", "possible", ["E-101"], section="3.1"),
        ]
        proc, out = self._run(tmp_path, claims)
        assert proc.returncode == 0  # warnings only
        assert out["certainty_conflicts"]
        assert any("certainty conflict" in w for w in out["warnings"])

    def test_unlinked_recommendation_is_warning(self, tmp_path):
        proc, out = self._run(
            tmp_path,
            [self._claim("CLM-1", "confirmed", [], ctype="recommendation",
                         obj="reset_credentials")],
        )
        assert proc.returncode == 0
        assert any("not linked" in w for w in out["warnings"])

    def test_invalid_claim_type_is_problem(self, tmp_path):
        proc, out = self._run(
            tmp_path,
            [self._claim("CLM-1", "confirmed", ["E-101"], ctype="unsupported_type")],
        )
        assert proc.returncode == 1
        assert any("claim_type" in p and "invalid" in p for p in out["problems"])

    def test_unknown_related_claim_id_is_problem(self, tmp_path):
        claim = self._claim("CLM-1", "confirmed", ["E-101"], ctype="recommendation")
        claim["related_claim_ids"] = ["CLM-NOPE"]
        proc, out = self._run(tmp_path, [claim])
        assert proc.returncode == 1
        assert any("related_claim_ids" in p for p in out["problems"])


class TestClaimAssessments:
    REQUIRED_TOPICS = [
        "initial_access",
        "scope",
        "lateral_movement",
        "persistence",
        "c2_external",
        "exfiltration",
        "impact",
        "limitations",
        "recommendations",
    ]

    def _valid_payload(self, assessment: dict | None = None) -> dict:
        base_assessment = {
            "assessment_id": "ASM-001",
            "topic": "initial_access",
            "conclusion": "VPNから侵入したと記載されています。",
            "stated_confidence": "confirmed",
            "review_verdict": "supported",
            "support_summary": "根拠の記載に対応しています。",
            "evidence_assessment": "証拠IDと本文記載で追跡できます。",
            "logic_assessment": "証拠から結論への推論に大きな飛躍はありません。",
            "confidence_assessment": "確度表現は本文の根拠と整合します。",
            "limitations": [],
            "reason": "テスト用の主要結論評価です。",
            "suggested_revision": "なし",
            "source_span_ids": ["SPN-1"],
            "issue_ids": [],
        }
        if assessment:
            base_assessment.update(assessment)

        inventory = [{
            "conclusion_id": "CON-001",
            "topic": "initial_access",
            "presence": "reported",
            "stated_conclusion": base_assessment["conclusion"],
            "assessment_ids": [base_assessment["assessment_id"]],
            "source_span_ids": ["SPN-1"],
            "absence_check_ids": [],
            "reason": "本文に初期侵入の主要結論が記載されています。",
        }]
        for idx, topic in enumerate(self.REQUIRED_TOPICS[1:], start=2):
            inventory.append({
                "conclusion_id": f"CON-{idx:03d}",
                "topic": topic,
                "presence": "not_applicable",
                "stated_conclusion": "本テストでは対象外です。",
                "assessment_ids": [],
                "source_span_ids": [],
                "absence_check_ids": [],
                "reason": "スキーマ確認用の対象外項目です。",
            })

        return {
            "conclusion_inventory": inventory,
            "consistency_assessments": [{
                "consistency_id": "CNS-001",
                "related_conclusion_ids": ["CON-001", "CON-002"],
                "consistency_verdict": "consistent",
                "source_span_ids": ["SPN-1"],
                "absence_check_ids": [],
                "reason": "主要結論間に矛盾はありません。",
                "suggested_revision": "なし",
            }],
            "claim_assessments": [base_assessment],
            "recommendation_assessments": [],
        }

    def test_at_least_one_claim_assessment_is_required(self, tmp_path):
        af = tmp_path / "assessments.json"
        af.write_text(json.dumps({
            "conclusion_inventory": [],
            "consistency_assessments": [],
            "claim_assessments": [],
            "recommendation_assessments": [],
        }, ensure_ascii=False))
        proc = run(ASSESS, "--assessments", str(af))
        assert proc.returncode == 1
        assert "at least one" in proc.stdout

    def test_reported_conclusion_cannot_reuse_another_topics_assessment(self, tmp_path):
        # Regression test for a real incident: 4 "reported" conclusions
        # (persistence / c2_external / lateral_movement / limitations) all
        # pointed assessment_ids at the "scope" assessment, which never
        # discusses them at all. The old check only verified the assessment_id
        # existed somewhere, not that it actually assessed this conclusion's
        # own topic, so this passed silently.
        payload = self._valid_payload()
        for row in payload["conclusion_inventory"]:
            if row["topic"] == "persistence":
                row["presence"] = "reported"
                row["stated_conclusion"] = "UNS40-76でスケジュールタスクによる永続化が確認された"
                row["assessment_ids"] = ["ASM-001"]  # ASM-001 only assesses initial_access
                row["source_span_ids"] = ["SPN-1"]
        af = tmp_path / "assessments.json"
        af.write_text(json.dumps(payload, ensure_ascii=False))
        proc = run(ASSESS, "--assessments", str(af))
        assert proc.returncode == 1
        assert "CON-004" in proc.stdout  # persistence is the 4th REQUIRED_TOPICS entry
        assert "not of this conclusion's own topic 'persistence'" in proc.stdout

        # A dedicated, on-topic assessment fixes it.
        payload["claim_assessments"].append({
            **payload["claim_assessments"][0],
            "assessment_id": "ASM-002", "topic": "persistence",
        })
        for row in payload["conclusion_inventory"]:
            if row["topic"] == "persistence":
                row["assessment_ids"] = ["ASM-002"]
        af.write_text(json.dumps(payload, ensure_ascii=False))
        proc2 = run(ASSESS, "--assessments", str(af))
        assert proc2.returncode == 0, proc2.stdout

    @pytest.mark.parametrize("generic_text", [
        "報告書にinitial_accessに関する記載がある",  # raw topic identifier leaking into prose
        "初期侵入について記載されている",
        "初期侵入に関する記載があります",
    ])
    def test_generic_stated_conclusion_is_rejected(self, tmp_path, generic_text):
        # Regression test for a real failure mode: the Agent restated the
        # topic label instead of the actual finding (host, technique, time,
        # confidence), and nothing caught it.
        assessments = self._valid_payload()
        assessments["conclusion_inventory"][0]["stated_conclusion"] = generic_text
        af = tmp_path / "assessments.json"
        af.write_text(json.dumps(assessments, ensure_ascii=False))
        proc = run(ASSESS, "--assessments", str(af))
        assert proc.returncode == 1
        assert "stated_conclusion is too generic" in proc.stdout

    def test_concrete_stated_conclusion_passes(self, tmp_path):
        assessments = self._valid_payload()
        assessments["conclusion_inventory"][0]["stated_conclusion"] = (
            "Citrix NetScalerの脆弱性悪用によりUNS40-76へ初期侵入された可能性が高い。"
        )
        af = tmp_path / "assessments.json"
        af.write_text(json.dumps(assessments, ensure_ascii=False))
        sf = tmp_path / "source_index.json"
        sf.write_text(json.dumps({"spans": [{"source_span_id": "SPN-1"}]}))
        proc = run(ASSESS, "--assessments", str(af), "--source-index", str(sf))
        assert proc.returncode == 0, proc.stdout

    def test_assessment_requires_grounding_and_known_links(self, tmp_path):
        assessments = self._valid_payload({
            "review_verdict": "unsupported",
            "support_summary": "根拠の記載が不足しています。",
            "evidence_assessment": "証拠IDだけでは断定には不足しています。",
            "logic_assessment": "断定までの推論に飛躍があります。",
            "confidence_assessment": "confirmed は強すぎます。",
            "reason": "証拠IDだけでVPN侵入を断定しています。",
            "suggested_revision": "可能性表現に修正します。",
            "issue_ids": ["ISS-aaaaaaaa"],
        })
        assessments["recommendation_assessments"] = [{
                "recommendation_id": "REC-001",
                "recommendation": "MFAを導入します。",
                "review_verdict": "mapped",
                "linked_finding_ids": ["ASM-001"],
                "reason": "初期侵入の評価に対応しています。",
                "suggested_revision": "なし",
        }]
        af = tmp_path / "assessments.json"
        af.write_text(json.dumps(assessments, ensure_ascii=False))
        sf = tmp_path / "source_index.json"
        sf.write_text(json.dumps({"spans": [{"source_span_id": "SPN-1"}]}))
        proc = run(ASSESS, "--assessments", str(af), "--source-index", str(sf))
        assert proc.returncode == 0, proc.stdout

    def test_partial_assessment_requires_issue_ids(self, tmp_path):
        assessments = self._valid_payload({
            "topic": "scope",
            "conclusion": "侵害範囲は端末1台です。",
            "stated_confidence": "confirmed",
            "review_verdict": "partially_supported",
            "support_summary": "一部根拠があります。",
            "evidence_assessment": "一部の根拠に限定されています。",
            "logic_assessment": "他端末調査との対応が不足しています。",
            "confidence_assessment": "confirmed は強すぎます。",
            "reason": "他端末調査との対応が不足しています。",
            "suggested_revision": "範囲の制約を明記します。",
            "issue_ids": [],
        })
        af = tmp_path / "assessments.json"
        af.write_text(json.dumps(assessments, ensure_ascii=False))
        proc = run(ASSESS, "--assessments", str(af))
        assert proc.returncode == 1
        assert "issue_ids" in proc.stdout

    def test_inventory_requires_all_major_topics(self, tmp_path):
        assessments = self._valid_payload()
        assessments["conclusion_inventory"] = assessments["conclusion_inventory"][:1]
        af = tmp_path / "assessments.json"
        af.write_text(json.dumps(assessments, ensure_ascii=False))
        proc = run(ASSESS, "--assessments", str(af))
        assert proc.returncode == 1
        assert "required topics are missing" in proc.stdout


# ---------------------------------------------------------------------------
# check_coverage.py — scoring per the review policy
# ---------------------------------------------------------------------------


class TestCoverageScoring:
    def test_unknown_and_na_excluded_from_denominator(self, tmp_path, items):
        must = [i for i in items if i["level"] == "必須"]
        external_must = [i for i in must if i["unknown_allowed"]]
        assert len(must) >= 3
        assert len(external_must) >= 2
        results = []
        # First must item met, second unknown, third not_applicable;
        # everything else met.
        specials = {
            external_must[0]["id"]: "unknown",
            external_must[1]["id"]: "not_applicable",
        }
        for i in items:
            results.append({"id": i["id"],
                            "verdict": specials.get(i["id"], "met")})
        f = tmp_path / "results.json"
        f.write_text(json.dumps({"results": results}, ensure_ascii=False))
        summary = tmp_path / "summary.json"
        proc = run(COVER, "--results", str(f), "--summary-json", str(summary))
        assert proc.returncode == 0, proc.stdout
        s = json.loads(summary.read_text())
        must_score = s["scores"]["必須"]
        assert must_score["denominator"] == len(must) - 2
        assert must_score["met"] == len(must) - 2
        assert must_score["unknown"] == 1
        # unknown goes to the external-confirmation bucket, not defects.
        assert external_must[0]["id"] in s["buckets"]["external_confirmation_needed"]
        assert external_must[0]["id"] not in s["buckets"]["quality_defects"]

    def test_optional_shortfall_is_suggestion_not_defect(self, tmp_path, items):
        optional = [i for i in items if i["level"] == "任意"]
        assert optional
        target = optional[0]["id"]
        results = [
            {"id": i["id"],
             "verdict": "not_met" if i["id"] == target else "met",
             "finding": "任意項目の欠落" if i["id"] == target else ""}
            for i in items
        ]
        f = tmp_path / "results.json"
        f.write_text(json.dumps({"results": results}, ensure_ascii=False))
        summary = tmp_path / "summary.json"
        proc = run(COVER, "--results", str(f), "--summary-json", str(summary))
        assert proc.returncode == 0, proc.stdout
        s = json.loads(summary.read_text())
        assert target in s["buckets"]["improvement_suggestions"]
        assert target not in s["buckets"]["quality_defects"]


# ---------------------------------------------------------------------------
# §5-§15: certainty model, cross-section checks, issues pipeline, FP reduction
# ---------------------------------------------------------------------------

ISSUES = SKILLS / "ir-review-report" / "scripts" / "check_issues.py"
COMPARE = SKILLS / "ir-review-report" / "scripts" / "compare_runs.py"
VENDOR = FIXTURES / "sample_vendor_report.md"


def _import_module(path: Path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestCertaintyClassification:
    """§確度の正規化 — 5-level mapping of Japanese report phrasing."""

    @pytest.fixture(scope="class")
    def cc(self):
        return _import_module(SKILLS / "ir-review-report" / "scripts" / "check_claims.py")

    @pytest.mark.parametrize("text,expected", [
        ("アカウントが使用されたことを確認した", "confirmed"),
        ("侵入経路を特定した", "confirmed"),
        ("VPN経由で行われた可能性が高い", "highly_likely"),
        ("強く疑われる挙動です", "highly_likely"),
        ("外部送信の可能性がある", "possible"),
        ("悪用の疑いがある", "possible"),
        ("原因は断定できない", "unknown"),
        ("侵入経路は確認できなかったため不明", "unknown"),
        ("外部送信の痕跡は確認されなかった", "negative"),
        ("マルウェアは検出されなかった", "negative"),
    ])
    def test_phrase_mapping(self, cc, text, expected):
        assert cc.classify_certainty(text) == expected

    def test_negation_wins_over_confirmed(self, cc):
        # 「確認されなかった」 contains 「確認され」 — negative must win.
        assert cc.classify_certainty("確認されなかった") == "negative"

    def test_legacy_aliases_normalized(self, cc):
        assert cc.normalize_certainty("probable") == "highly_likely"
        assert cc.normalize_certainty("not_observed") == "negative"


class TestClaimCrossSection:
    """§5/§6 — summary-vs-body strength and appendix-only assertions."""

    @staticmethod
    def _claim(cid, zone, section, certainty, ev, subject="mal", obj="noopdoor"):
        return {
            "claim_id": cid,
            "location": {"section": section, "page": 1, "table": None, "zone": zone},
            "subject": subject, "predicate": "is", "object": obj,
            "certainty": certainty, "time": None, "evidence_ids": ev,
            "quote": "引用", "claim_type": "finding",
        }

    def _warnings(self, tmp_path, claims):
        f = tmp_path / "claims.json"
        f.write_text(json.dumps({"claims": claims}, ensure_ascii=False))
        proc = run(SKILLS / "ir-review-report" / "scripts" / "check_claims.py",
                   "--claims", str(f))
        return proc, json.loads(proc.stdout)["warnings"]

    def test_summary_stronger_than_body_is_flagged(self, tmp_path):
        claims = [
            self._claim("C1", "summary", "2. サマリー", "confirmed", ["E-1"]),
            self._claim("C2", "body", "3.5", "possible", ["E-1"]),
        ]
        proc, warnings = self._warnings(tmp_path, claims)
        assert any("summary stronger than body" in w for w in warnings)

    def test_appendix_only_assertion_is_flagged(self, tmp_path):
        claims = [self._claim("C1", "attack_mapping", "付録B", "possible", [],
                              obj="dga")]
        proc, warnings = self._warnings(tmp_path, claims)
        assert any("appendix-only assertion" in w for w in warnings)

    def test_body_backed_assertion_not_flagged_appendix_only(self, tmp_path):
        claims = [
            self._claim("C1", "attack_mapping", "付録B", "possible", [], obj="dga"),
            self._claim("C2", "body", "3.5", "possible", [], obj="dga"),
        ]
        proc, warnings = self._warnings(tmp_path, claims)
        assert not any("appendix-only" in w for w in warnings)

    def test_summary_only_assertion_is_flagged(self, tmp_path):
        # A finding that appears only in the executive summary, with no
        # body/table/appendix counterpart, must be flagged.
        claims = [self._claim("C1", "summary", "2. エグゼクティブサマリー",
                              "confirmed", ["E-1"], obj="exfiltration")]
        proc, warnings = self._warnings(tmp_path, claims)
        assert any("summary-only assertion" in w for w in warnings)

    def test_summary_with_body_counterpart_not_flagged(self, tmp_path):
        claims = [
            self._claim("C1", "summary", "2. サマリー", "possible", ["E-1"],
                        obj="exfiltration"),
            self._claim("C2", "body", "3.6", "possible", ["E-1"],
                        obj="exfiltration"),
        ]
        proc, warnings = self._warnings(tmp_path, claims)
        assert not any("summary-only" in w for w in warnings)


class TestCheckIssues:
    """§9-§11: issue schema, severity policy, code-generated summary."""

    @pytest.fixture()
    def results_file(self, tmp_path, items):
        specials = {
            SERIOUS_CHECK_ID: "partial",
            OPTIONAL_CHECK_ID: "not_met",
            UNKNOWN_CHECK_ID: "unknown",
        }
        results = [{"id": i["id"], "verdict": specials.get(i["id"], "met"),
                    "finding": "x" if specials.get(i["id"]) else ""}
                   for i in items]
        f = tmp_path / "results.json"
        f.write_text(json.dumps({"results": results}, ensure_ascii=False))
        return f

    @staticmethod
    def _issue(category, severity, cids, status, quotes=True):
        return {
            "category": category, "severity": severity, "checklist_ids": cids,
            "status": status, "primary_location": "3.2",
            "quotes": [{"location": "3.2", "text": "引用文"}] if quotes else [],
            "reason": "理由", "suggested_revision": "修正案", "confidence": 0.9,
        }

    def _run(self, tmp_path, results_file, issues, extra=()):
        f = tmp_path / "issues.json"
        f.write_text(json.dumps({"issues": issues}, ensure_ascii=False))
        return run(ISSUES, "--issues", str(f), "--results", str(results_file), *extra)

    def test_valid_issues_pass_and_headline_reflects_serious(
            self, tmp_path, results_file):
        issues = [
            self._issue("certainty_inconsistency", "high",
                        [SERIOUS_CHECK_ID], "partial"),
            # results_file always marks UNKNOWN_CHECK_ID as verdict "unknown",
            # which now requires a matching external_confirmation issue too.
            self._issue("external_confirmation", "medium",
                        [UNKNOWN_CHECK_ID], "unknown"),
        ]
        summary = tmp_path / "summary.json"
        proc = self._run(tmp_path, results_file, issues,
                         ("--summary-out", str(summary)))
        assert proc.returncode == 0, proc.stdout
        s = json.loads(summary.read_text())
        # サマリーと個別指摘の矛盾禁止: high certainty_inconsistency が
        # 存在するとき「重大な指摘なし」とは言えない。
        assert s["serious_findings"]
        assert "重大な指摘あり" in s["headline"]
        assert s["issue_counts"]["by_severity"]["high"] == 1

    def test_quality_shortfalls_require_issue_entries(self, tmp_path, results_file):
        # Cover the unknown-verdict item so this test isolates the
        # quality-defect check specifically (that's a separate requirement,
        # tested in test_unknown_status_requires_external_confirmation).
        issues = [self._issue("external_confirmation", "medium",
                              [UNKNOWN_CHECK_ID], "unknown")]
        proc = self._run(tmp_path, results_file, issues)
        assert proc.returncode == 1
        assert "missing quality-defect issues" in proc.stdout
        assert SERIOUS_CHECK_ID in proc.stdout
        # Optional shortfalls and external-confirmation items are not quality
        # defects, so the failure must be about the serious checklist item.
        assert OPTIONAL_CHECK_ID not in proc.stdout
        assert UNKNOWN_CHECK_ID not in proc.stdout

    def test_quotes_required(self, tmp_path, results_file):
        issues = [self._issue("missing_required_item", "medium",
                              [SERIOUS_CHECK_ID], "partial", quotes=False)]
        proc = self._run(tmp_path, results_file, issues)
        assert proc.returncode == 1
        assert "quotes is empty" in proc.stdout

    def test_optional_item_cannot_be_high(self, tmp_path, results_file):
        issues = [self._issue("optional_enhancement", "high",
                              [OPTIONAL_CHECK_ID], "not_met")]
        proc = self._run(tmp_path, results_file, issues)
        assert proc.returncode == 1
        assert "optional_enhancement" in proc.stdout

    def test_unknown_status_requires_external_confirmation(
            self, tmp_path, results_file):
        issues = [self._issue("missing_required_item", "medium",
                              [UNKNOWN_CHECK_ID], "unknown")]
        proc = self._run(tmp_path, results_file, issues)
        assert proc.returncode == 1
        assert "external_confirmation" in proc.stdout

    def test_unknown_verdict_with_no_issue_at_all_fails(self, tmp_path, results_file):
        # Regression test for a real bug: results.json had 11 unknown verdicts
        # while issues.json had zero external_confirmation issues, and nothing
        # caught it — the final summary said "unknown: 11" and "external
        # confirmation needed: 0" in the same document. A quality-defect issue
        # for the serious item alone must not be enough to pass.
        issues = [self._issue("certainty_inconsistency", "high",
                              [SERIOUS_CHECK_ID], "partial")]
        proc = self._run(tmp_path, results_file, issues)
        assert proc.returncode == 1
        assert "missing external_confirmation issues" in proc.stdout
        assert UNKNOWN_CHECK_ID in proc.stdout

    def test_unknown_verdict_covered_by_external_confirmation_issue_passes(
            self, tmp_path, results_file):
        issues = [
            self._issue("certainty_inconsistency", "high",
                        [SERIOUS_CHECK_ID], "partial"),
            self._issue("external_confirmation", "medium",
                        [UNKNOWN_CHECK_ID], "unknown"),
        ]
        proc = self._run(tmp_path, results_file, issues)
        assert proc.returncode == 0, proc.stdout

    def test_source_observation_ids_must_be_a_list(self, tmp_path, results_file):
        issue = self._issue("certainty_inconsistency", "high",
                            [SERIOUS_CHECK_ID], "partial")
        issue["source_observation_ids"] = "OBS-CHK-001-001"  # not a list
        proc = self._run(tmp_path, results_file, [issue])
        assert proc.returncode == 1
        assert "source_observation_ids must be a list" in proc.stdout

    def test_status_must_match_results_verdict(self, tmp_path, results_file):
        issues = [self._issue("missing_required_item", "medium",
                              [SERIOUS_CHECK_ID], "not_met")]  # results say partial
        proc = self._run(tmp_path, results_file, issues)
        assert proc.returncode == 1
        assert "contradicts" in proc.stdout

    def test_stable_ids_and_deterministic_summary(self, tmp_path, results_file):
        issues = [
            self._issue(
                "certainty_inconsistency", "high", [SERIOUS_CHECK_ID], "partial"
            ),
            self._issue(
                "external_confirmation", "medium", [UNKNOWN_CHECK_ID], "unknown"
            ),
        ]
        outs = []
        for n in (1, 2):
            out = tmp_path / f"norm{n}.json"
            summary = tmp_path / f"sum{n}.json"
            proc = self._run(tmp_path, results_file, issues,
                             ("--out", str(out), "--summary-out", str(summary)))
            assert proc.returncode == 0, proc.stdout
            outs.append((out.read_text(), summary.read_text()))
        # 同一入力 → 同一の正規化 issues と同一の集計(§13/§15)。
        assert outs[0] == outs[1]
        ids = [i["issue_id"] for i in json.loads(outs[0][0])["issues"]]
        assert all(i.startswith("ISS-") for i in ids)
        assert len(ids) == len(set(ids))

    def test_strict_grounding_requires_source_span_or_absence(self, tmp_path, results_file):
        issues = [self._issue("certainty_inconsistency", "high",
                              [SERIOUS_CHECK_ID], "partial")]
        proc = self._run(tmp_path, results_file, issues, ("--strict-grounding",))
        assert proc.returncode == 1
        assert "strict grounding" in proc.stdout

    def test_source_span_ids_are_validated_when_index_is_supplied(self, tmp_path, results_file):
        issue = self._issue("certainty_inconsistency", "high",
                            [SERIOUS_CHECK_ID], "partial")
        issue["source_span_ids"] = ["SPN-known"]
        source_index = tmp_path / "source_index.json"
        source_index.write_text(json.dumps({"spans": [{"source_span_id": "SPN-other"}]}))
        proc = self._run(
            tmp_path, results_file, [issue],
            ("--source-index", str(source_index), "--strict-grounding"),
        )
        assert proc.returncode == 1
        assert "unknown source_span_ids" in proc.stdout

    def test_non_substantive_source_span_is_rejected(self, tmp_path, results_file):
        issue = self._issue("certainty_inconsistency", "high",
                            [SERIOUS_CHECK_ID], "partial")
        issue["source_span_ids"] = ["SPN-page"]
        source_index = tmp_path / "source_index.json"
        source_index.write_text(json.dumps({
            "spans": [{
                "source_span_id": "SPN-page",
                "kind": "paragraph",
                "text": "===== [page 1] =====",
                "values": [],
            }]
        }, ensure_ascii=False))
        proc = self._run(
            tmp_path, results_file, [issue],
            ("--source-index", str(source_index), "--strict-grounding"),
        )
        assert proc.returncode == 1
        assert "non-substantive source_span_ids" in proc.stdout

    def test_missing_required_not_met_requires_absence_check(self, tmp_path, results_file):
        issue = self._issue("missing_required_item", "medium",
                            [OPTIONAL_CHECK_ID], "not_met")
        proc = self._run(tmp_path, results_file, [issue])
        assert proc.returncode == 1
        assert "absence_check_ids" in proc.stdout


class TestCompareRuns:
    def test_identical_runs_have_no_diff(self, tmp_path):
        issues = {"issues": [{"issue_id": "ISS-1", "severity": "high",
                              "status": "partial", "category": "x", "reason": "r"}]}
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_text(json.dumps(issues))
        b.write_text(json.dumps(issues))
        out = json.loads(run(COMPARE, "--a", str(a), "--b", str(b)).stdout)
        assert out["issues"]["added_in_b"] == []
        assert out["issues"]["removed_in_b"] == []
        assert out["issues"]["changed"] == []

    def test_changed_severity_is_reported(self, tmp_path):
        base = {"issue_id": "ISS-1", "severity": "high", "status": "partial",
                "category": "x", "reason": "r"}
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_text(json.dumps({"issues": [base]}))
        b.write_text(json.dumps({"issues": [dict(base, severity="low")]}))
        out = json.loads(run(COMPARE, "--a", str(a), "--b", str(b)).stdout)
        assert out["issues"]["changed"] == ["ISS-1"]


class TestGuidanceExclusion:
    """§7 — authoring guidance must not be flagged as overclaims/IoCs."""

    @staticmethod
    def _checks(report: Path) -> dict[str, dict]:
        proc = run(MECH, "--report", str(report))
        data = json.loads(proc.stdout)
        return {c["key"]: c for c in data["checks"]}

    def test_guidance_and_purpose_not_overclaimed(self, tmp_path):
        report = tmp_path / "r.md"
        report.write_text(
            "## 調査目的\n\n情報漏えいが発生したかを確認します。\n\n"
            "## 3. 結果\n\n本節では、情報漏えいの調査結果を記載します。\n"
            "> 例: 攻撃者はデータを窃取しました。\n"
            "外部送信の痕跡は確認されませんでした。\n",
            encoding="utf-8",
        )
        assert self._checks(report)["overclaim"]["status"] == "pass"

    def test_real_overclaim_outside_guidance_still_detected(self, tmp_path):
        report = tmp_path / "r.md"
        report.write_text(
            "## 3. 結果\n\n情報漏えいが発生しました。\n", encoding="utf-8")
        assert self._checks(report)["overclaim"]["status"] == "warn"

    def test_reference_urls_not_defang_flagged(self, tmp_path):
        report = tmp_path / "r.md"
        report.write_text(
            "## 参考文献\n\n- https://www.jpcert.or.jp/research/example.html\n",
            encoding="utf-8",
        )
        assert self._checks(report)["defang_ioc"]["status"] == "pass"

    def test_invalid_octet_concatenation_not_flagged(self, tmp_path):
        report = tmp_path / "r.md"
        # Table-layout concatenation producing a >255 octet must be ignored.
        report.write_text("## 3. 結果\n\n値: 10.0.1.5203 のような連結。\n",
                          encoding="utf-8")
        assert self._checks(report)["defang_ioc"]["status"] == "pass"


class TestVendorReportIntegration:
    """§14 — the fixture embeds should-detect and must-not-detect patterns."""

    EIDS_SCRIPT = SKILLS / "ir-review-report" / "scripts" / "check_evidence_ids.py"

    @pytest.fixture(scope="class")
    def eids(self) -> dict:
        proc = run(self.EIDS_SCRIPT, "--report", str(VENDOR))
        return json.loads(proc.stdout)

    def test_undefined_e109_detected(self, eids):
        ids = [p["id"] for p in eids["problems"]["undefined_references"]]
        assert ids == ["E-109"]

    def test_unreferenced_and_gap_are_not_problems(self, eids):
        # E-105/E-107 defined but uncited; E-104/E-106 are numbering gaps.
        assert "E-105" in eids["info"]["unreferenced_defined"]
        problem_ids = {p["id"] for kind in eids["problems"].values() for p in kind}
        assert "E-105" not in problem_ids and "E-107" not in problem_ids
        assert eids["info"]["numbering_gaps"]

    def test_guidance_and_hedged_sentences_not_overclaimed(self):
        proc = run(MECH, "--report", str(VENDOR))
        checks = {c["key"]: c for c in json.loads(proc.stdout)["checks"]}
        samples = " ".join(checks["overclaim"]["samples"])
        # ガイダンス(調査目的・注記の例文)は検出されない
        assert "確認することです" not in samples
        assert "サンプルとして示しています" not in samples
        # ヘッジ済みの本文(「断定はできません」「不明です」)も過検出しない
        assert "断定はできません" not in samples
        assert "不明です" not in samples

    def test_unhedged_body_assertion_is_detected(self, tmp_path):
        # The semantic port→HTTPS claim is left to the LLM; a bare un-hedged
        # stage-term assertion in the body is the mechanical signal.
        report = tmp_path / "r.md"
        report.write_text(
            "## 3. 結果\n\n攻撃者により情報が窃取されました。\n", encoding="utf-8")
        proc = run(MECH, "--report", str(report))
        checks = {c["key"]: c for c in json.loads(proc.stdout)["checks"]}
        assert checks["overclaim"]["status"] == "warn"


class TestRenderReviewErrorHandling:
    """render_review.py reads 6 JSON inputs. A malformed one used to raise an
    uncaught json.JSONDecodeError — a bare traceback with no indication of
    which of the 6 files was broken. It must instead name the file."""

    def test_malformed_input_names_the_broken_file(self, tmp_path):
        good = tmp_path / "good.json"
        good.write_text("{}", encoding="utf-8")
        bad = tmp_path / "summary.json"
        bad.write_text('{"a": 1,}', encoding="utf-8")  # trailing comma
        claims = tmp_path / "claims.json"
        claims.write_text(json.dumps({"claim_assessments": [{"x": 1}]}), encoding="utf-8")
        proc = run(
            RENDER,
            "--issues", str(good), "--summary", str(bad), "--results", str(good),
            "--claim-assessments", str(claims), "--out", str(tmp_path / "out.md"),
        )
        assert proc.returncode == 2
        assert "Traceback" not in proc.stderr
        assert str(bad) in proc.stderr
        assert "JSON 構文エラー" in proc.stderr


# ---------------------------------------------------------------------------
# check_review_doc.py — the review document must be self-consistent
# ---------------------------------------------------------------------------

REVIEW_DOC = SKILLS / "ir-review-report" / "scripts" / "check_review_doc.py"


class TestCheckReviewDoc:
    @pytest.fixture()
    def artifacts(self, tmp_path, items):
        """Build issues/summary via check_issues, plus a compliant doc."""
        specials = {
            SERIOUS_CHECK_ID: "partial",
            OPTIONAL_CHECK_ID: "not_met",
            UNKNOWN_CHECK_ID: "unknown",
        }
        results = [{"id": i["id"], "verdict": specials.get(i["id"], "met"),
                    "finding": "x" if specials.get(i["id"]) else ""}
                   for i in items]
        rf = tmp_path / "results.json"
        rf.write_text(json.dumps({"results": results}, ensure_ascii=False))
        issues = [
            {"category": "certainty_inconsistency", "severity": "high",
             "checklist_ids": [SERIOUS_CHECK_ID], "status": "partial",
             "primary_location": "3.2",
             "quotes": [{"location": "3.2", "text": "断定表現"}],
             "reason": "確度不整合", "suggested_revision": "修正", "confidence": 0.9},
            {"category": "optional_enhancement", "severity": "low",
             "checklist_ids": [OPTIONAL_CHECK_ID], "status": "not_met",
             "primary_location": "付録E",
             "quotes": [{"location": "付録E", "text": "写真なし"}],
             "reason": "任意項目", "suggested_revision": "写真添付", "confidence": 0.8},
            {"category": "external_confirmation", "severity": "medium",
             "checklist_ids": [UNKNOWN_CHECK_ID], "status": "unknown",
             "primary_location": "1章",
             "quotes": [{"location": "1章", "text": "(記載なし)"}],
             "reason": "合意は報告書外", "suggested_revision": "合意文書で確認",
             "confidence": 0.9},
        ]
        isf = tmp_path / "issues.json"
        isf.write_text(json.dumps({"issues": issues}, ensure_ascii=False))
        norm = tmp_path / "norm.json"
        summary = tmp_path / "summary.json"
        md = tmp_path / "summary.md"
        proc = run(ISSUES, "--issues", str(isf), "--results", str(rf),
                   "--out", str(norm), "--summary-out", str(summary),
                   "--markdown-out", str(md))
        assert proc.returncode == 0, proc.stdout
        norm_issues = json.loads(norm.read_text())["issues"]
        ids = {i["category"]: i["issue_id"] for i in norm_issues}
        doc = "\n".join([
            "# 報告書レビュー結果", "",
            md.read_text(encoding="utf-8"),
            "## 指摘事項", "",
            f"- 確度不整合の指摘({ids['certainty_inconsistency']})", "",
            "## 改善提案(任意項目)", "",
            f"- 写真を添付する({ids['optional_enhancement']})", "",
            "## 被害組織が追加確認すべき事項", "",
            f"- 合意文書と突き合わせる({ids['external_confirmation']})", "",
        ])
        docf = tmp_path / "review.md"
        docf.write_text(doc, encoding="utf-8")
        source = tmp_path / "normalized.txt"
        source.write_text("断定表現\n写真なし\n合意は報告書外\n", encoding="utf-8")
        assessments = tmp_path / "claim_assessments.json"
        inventory = [{
            "conclusion_id": "CON-001",
            "topic": "initial_access",
            "presence": "reported",
            "stated_conclusion": "初期侵入に関する主要結論",
            "assessment_ids": ["ASM-001"],
            "source_span_ids": ["SPN-1"],
            "absence_check_ids": [],
            "reason": "本文に初期侵入の結論が記載されています。",
        }]
        for idx, topic in enumerate([
            "scope",
            "lateral_movement",
            "persistence",
            "c2_external",
            "exfiltration",
            "impact",
            "limitations",
            "recommendations",
        ], start=2):
            inventory.append({
                "conclusion_id": f"CON-{idx:03d}",
                "topic": topic,
                "presence": "not_applicable",
                "stated_conclusion": "本テストでは対象外です。",
                "assessment_ids": [],
                "source_span_ids": [],
                "absence_check_ids": [],
                "reason": "スキーマ確認用の対象外項目です。",
            })
        assessments.write_text(json.dumps({
            "conclusion_inventory": inventory,
            "consistency_assessments": [{
                "consistency_id": "CNS-001",
                "related_conclusion_ids": ["CON-001", "CON-002"],
                "consistency_verdict": "consistent",
                "source_span_ids": ["SPN-1"],
                "absence_check_ids": [],
                "reason": "主要結論間に矛盾はありません。",
                "suggested_revision": "なし",
            }],
            "claim_assessments": [{
                "assessment_id": "ASM-001",
                "topic": "initial_access",
                "conclusion": "初期侵入に関する主要結論",
                "stated_confidence": "possible",
                "review_verdict": "supported",
                "support_summary": "本文上の記載に対応しています。",
                "evidence_assessment": "証拠IDと本文記載で追跡できます。",
                "logic_assessment": "証拠から結論への推論に大きな飛躍はありません。",
                "confidence_assessment": "possible は根拠の限定と整合します。",
                "limitations": [],
                "reason": "テスト用の最小評価です。",
                "suggested_revision": "なし",
                "source_span_ids": ["SPN-1"],
            }],
            "recommendation_assessments": [],
        }, ensure_ascii=False))
        return {"doc": docf, "norm": norm, "summary": summary, "ids": ids,
                "text": doc, "results": rf, "source": source,
                "assessments": assessments}

    def _run(self, artifacts, doc_text=None):
        docf = artifacts["doc"]
        if doc_text is not None:
            docf.write_text(doc_text, encoding="utf-8")
        return run(REVIEW_DOC, "--review", str(docf),
                   "--issues", str(artifacts["norm"]),
                   "--summary", str(artifacts["summary"]))

    def test_compliant_document_passes(self, artifacts):
        proc = self._run(artifacts)
        assert proc.returncode == 0, proc.stdout

    def test_missing_summary_line_fails(self, artifacts):
        text = artifacts["text"].replace("全チェック項目の判定分布", "判定分布(改変)")
        proc = self._run(artifacts, text)
        assert proc.returncode == 1
        assert "転記されていない" in proc.stdout

    def test_dropped_issue_fails(self, artifacts):
        iid = artifacts["ids"]["certainty_inconsistency"]
        text = artifacts["text"].replace(iid, "")
        proc = self._run(artifacts, text)
        assert proc.returncode == 1
        assert "記載がない" in proc.stdout

    def test_phantom_issue_id_fails(self, artifacts):
        text = artifacts["text"] + "\nサマリー限定の主張(ISS-deadbeef)\n"
        proc = self._run(artifacts, text)
        assert proc.returncode == 1
        assert "存在しない ID" in proc.stdout

    def test_external_item_outside_its_section_fails(self, artifacts):
        # The external issue id appears in the doc but NOT inside the
        # 追加確認 section → counts would drift from the section items.
        iid = artifacts["ids"]["external_confirmation"]
        text = artifacts["text"].replace(
            f"- 合意文書と突き合わせる({iid})", "- (項目を独断で削除)")
        # Mention the id under a different section so only the bucket-section
        # containment check can catch the drift.
        text += f"\n\n## AI レビューの限界\n\n参考: {iid} は本文で言及。\n"
        proc = self._run(artifacts, text)
        assert proc.returncode == 1
        assert "セクション内に記載がない" in proc.stdout

    def test_fixed_renderer_output_passes_extended_validation(self, artifacts, tmp_path):
        rendered = tmp_path / "rendered.md"
        proc = run(
            RENDER,
            "--issues", str(artifacts["norm"]),
            "--summary", str(artifacts["summary"]),
            "--results", str(artifacts["results"]),
            "--claim-assessments", str(artifacts["assessments"]),
            "--out", str(rendered),
        )
        assert proc.returncode == 0, proc.stderr
        check = run(
            REVIEW_DOC,
            "--review", str(rendered),
            "--issues", str(artifacts["norm"]),
            "--summary", str(artifacts["summary"]),
            "--results", str(artifacts["results"]),
            "--source", str(artifacts["source"]),
            "--rendered", str(rendered),
        )
        assert check.returncode == 0, check.stdout
        text = rendered.read_text(encoding="utf-8")
        assert "## 4. 主要結論の妥当性" in text
        assert "### 4.1 主要結論の棚卸し" in text
        assert "### 4.2 主要結論間の整合性" in text
        assert "### 4.3 各主要結論の妥当性" in text
        assert "## 付録A. チェックリスト全項目結果" in text
        # unknown-verdict checklist rows must be listed under the external
        # confirmation section on their own, independent of issues.json wording.
        assert "### 8.2 unknown 判定の項目" in text
        assert UNKNOWN_CHECK_ID in text.split("### 8.2", 1)[1].split("##", 1)[0]

    def test_quote_not_in_source_fails_when_source_is_supplied(self, artifacts):
        missing_source = artifacts["doc"].parent / "missing_source.txt"
        missing_source.write_text("別の本文です。\n", encoding="utf-8")
        proc = run(
            REVIEW_DOC,
            "--review", str(artifacts["doc"]),
            "--issues", str(artifacts["norm"]),
            "--summary", str(artifacts["summary"]),
            "--source", str(missing_source),
        )
        assert proc.returncode == 1
        assert "引用がレビュー対象" in proc.stdout


class TestCheckReviewRun:
    REQUIRED = [
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
    ]

    def _make_run_dir(self, tmp_path: Path) -> Path:
        d = tmp_path / "reviews" / "ReportB" / "20260912-224117_codex"
        d.mkdir(parents=True)
        for name in self.REQUIRED:
            path = d / name
            if name.endswith(".json"):
                content = (
                    {
                        "conclusion_inventory": [{}],
                        "consistency_assessments": [{}],
                        "claim_assessments": [{}],
                    }
                    if name == "claim_assessments.json" else {}
                )
                if name == "coverage_ledger.json":
                    content = {
                        "coverage_complete": True,
                        "uncovered_span_ids": [],
                        "problems": [],
                    }
                elif name == "merged_observations.json":
                    content = {
                        "chunks": [{"chunk_id": "CHK-001"}],
                        "checklist_observations": [{"checklist_id": "CUS-1.1"}],
                        "conclusion_observations": [],
                        "issue_observations": [],
                        "open_questions": [],
                    }
                path.write_text(json.dumps(content, ensure_ascii=False), encoding="utf-8")
            else:
                path.write_text("x", encoding="utf-8")
        chunks = d / "review_chunks"
        chunks.mkdir()
        (chunks / "chunk_manifest.json").write_text(
            json.dumps({"chunks": [{"chunk_id": "CHK-001"}]}, ensure_ascii=False),
            encoding="utf-8",
        )
        (chunks / "chunk_001.json").write_text("{}", encoding="utf-8")
        tasks = d / "subagent_tasks"
        tasks.mkdir()
        (tasks / "task_manifest.json").write_text(
            json.dumps({
                "schema_version": "1.0",
                "review_mode": "customer",
                "tasks": [
                    {
                        "task_id": "TASK-CHK-001",
                        "chunk_id": "CHK-001",
                        "path": "CHK-001.json",
                        "checklist_item_count": 1,
                    }
                ],
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        (tasks / "CHK-001.json").write_text(
            json.dumps({
                "task_id": "TASK-CHK-001",
                "chunk_id": "CHK-001",
                "review_mode": "customer",
                "chunk": {
                    "chunk_id": "CHK-001",
                    "review_mode": "customer",
                    "core_span_ids": ["SPN-001"],
                    "spans": [],
                },
                "checklist_items": [
                    {"id": "CUS-1.1", "text": "問い合わせ先が記載されているか"}
                ],
                "major_conclusion_review_focus": ["主要結論を抽出する"],
                "output_schema": {
                    "required_top_level_keys": [
                        "chunk_id",
                        "review_mode",
                        "covered_span_ids",
                        "checklist_observations",
                        "conclusion_observations",
                        "issue_observations",
                        "open_questions",
                    ],
                    "forbidden_top_level_keys": ["reviewed_span_ids"],
                },
                "instructions": ["出力スキーマに従って観測結果を作成する"],
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        observations = d / "subagent_observations"
        observations.mkdir()
        (observations / "CHK-001.json").write_text(
            json.dumps({
                "chunk_id": "CHK-001",
                "review_mode": "customer",
                "covered_span_ids": ["SPN-001"],
                "checklist_observations": [{"checklist_id": "CUS-1.1"}],
                "conclusion_observations": [],
                "issue_observations": [],
                "open_questions": [],
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        return d

    def test_clean_review_run_passes(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 0, proc.stdout

    def test_run_log_jsonl_is_allowed(self, tmp_path):
        # review_status.py appends one line per invocation to run_log.jsonl
        # for cross-turn attempt tracking; it must not be flagged as an
        # unexpected leftover file.
        d = self._make_run_dir(tmp_path)
        (d / "run_log.jsonl").write_text(
            '{"ts": "2026-01-01T00:00:00Z", "event": "status", "stage": "complete", "ok": true}\n',
            encoding="utf-8",
        )
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 0, proc.stdout

    def _add_open_question(self, d: Path, question_id: str = "Q-CHK-001-001") -> None:
        merged_path = d / "merged_observations.json"
        merged = json.loads(merged_path.read_text(encoding="utf-8"))
        merged["open_questions"] = [{
            "question_id": question_id,
            "question": "被害組織に確認すべき事項。",
            "reason": "chunk内の記載だけでは判定できない。",
            "source_span_ids": [],
        }]
        merged_path.write_text(json.dumps(merged, ensure_ascii=False), encoding="utf-8")

    def test_untriaged_open_question_fails(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        self._add_open_question(d)
        # issues.json stays empty — the open_question is never referenced.
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "open_questions are not triaged" in proc.stdout
        assert "Q-CHK-001-001" in proc.stdout

    def test_open_question_triaged_via_issue_passes(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        self._add_open_question(d)
        (d / "issues.json").write_text(json.dumps({"issues": [{
            "issue_id": "ISS-00000001",
            "category": "external_confirmation",
            "severity": "medium",
            "checklist_ids": [],
            "reason": "test",
            "suggested_revision": "",
            "source_observation_ids": ["Q-CHK-001-001"],
        }]}), encoding="utf-8")
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 0, proc.stdout

    def test_open_question_triaged_via_claim_assessment_passes(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        self._add_open_question(d)
        claims_path = d / "claim_assessments.json"
        claims = json.loads(claims_path.read_text(encoding="utf-8"))
        claims["conclusion_inventory"] = [{"source_observation_ids": ["Q-CHK-001-001"]}]
        claims_path.write_text(json.dumps(claims, ensure_ascii=False), encoding="utf-8")
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 0, proc.stdout

    def test_aggregation_worksheet_json_is_allowed(self, tmp_path):
        # review_status.py regenerates this after every successful merge.
        d = self._make_run_dir(tmp_path)
        (d / "aggregation_worksheet.json").write_text(
            json.dumps({"checklist_items": [], "topics": [], "issue_clusters": [], "open_questions": []}),
            encoding="utf-8",
        )
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 0, proc.stdout

    def test_ad_hoc_python_fails(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        (d / "checklist_evaluator.py").write_text("print('bad')\n", encoding="utf-8")
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "ad-hoc Python" in proc.stdout

    def test_competing_final_review_fails(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        (d / "comprehensive_final_review.md").write_text("x", encoding="utf-8")
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "final_review.md only" in proc.stdout

    def test_alternative_result_artifacts_fail(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        (d / "results_partial.json").write_text('{"results": []}', encoding="utf-8")
        (d / "results_final.json").write_text('{"results": []}', encoding="utf-8")
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "alternative checklist-result files" in proc.stdout

    def test_unexpected_review_artifacts_fail(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        (d / "progress_summary.md").write_text("intermediate note", encoding="utf-8")
        (d / "claim_assessments_v2.json").write_text("{}", encoding="utf-8")
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "unexpected files" in proc.stdout

    def test_legacy_subagent_observation_schema_fails(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        (d / "subagent_observations" / "CHK-001.json").write_text(
            json.dumps({
                "chunk_id": "CHK-001",
                "review_mode": "customer",
                "reviewed_span_ids": ["SPN-001"],
                "checklist_relevant_observations": [],
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "legacy/unsupported SubAgent schema keys" in proc.stdout

    def test_malformed_json_names_the_actual_problem(self, tmp_path):
        # Regression test: "must be a JSON object" alone doesn't say whether
        # it's a syntax error, an empty file, or the wrong top-level type —
        # exactly the ambiguity that turned one real claim_assessments.json
        # bug into a 10+ turn debugging loop. The message must name the
        # actual cause.
        d = self._make_run_dir(tmp_path)
        (d / "subagent_observations" / "CHK-001.json").write_text(
            '{"chunk_id": "CHK-001",}',  # trailing comma
            encoding="utf-8",
        )
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "JSON 構文エラー" in proc.stdout

        (d / "coverage_ledger.json").write_text("", encoding="utf-8")
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "ファイルが空です" in proc.stdout

    def test_subagent_task_without_checklist_fails(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        task = json.loads((d / "subagent_tasks" / "CHK-001.json").read_text(encoding="utf-8"))
        task["checklist_items"] = []
        (d / "subagent_tasks" / "CHK-001.json").write_text(
            json.dumps(task, ensure_ascii=False),
            encoding="utf-8",
        )
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "checklist_items must be a non-empty list" in proc.stdout

    def test_string_open_questions_fail(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        observation = json.loads(
            (d / "subagent_observations" / "CHK-001.json").read_text(encoding="utf-8")
        )
        observation["open_questions"] = ["追加確認事項"]
        (d / "subagent_observations" / "CHK-001.json").write_text(
            json.dumps(observation, ensure_ascii=False),
            encoding="utf-8",
        )
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "open_questions entries must be JSON objects" in proc.stdout

    def test_empty_merged_observations_fail(self, tmp_path):
        d = self._make_run_dir(tmp_path)
        (d / "merged_observations.json").write_text(
            json.dumps({
                "chunks": [{"chunk_id": "CHK-001"}],
                "checklist_observations": [],
                "conclusion_observations": [],
                "issue_observations": [],
                "open_questions": [],
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        proc = run(CHECK_RUN, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "no substantive observations" in proc.stdout


class TestReviewStatus:
    """review_status.py must always point at a concrete next command, and
    must detect partially-completed SubAgent work without needing the
    merge gate to fail first (that's the "Agent writes its own script
    because it lost track of the pipeline" failure mode this script exists
    to prevent)."""

    def test_empty_dir_points_at_prepare_report(self, tmp_path):
        d = tmp_path / "run"
        d.mkdir()
        proc = run(REVIEW_STATUS, "--review-dir", str(d))
        assert proc.returncode == 1
        assert "normalized.txt" in proc.stdout
        assert "prepare_report.py" in proc.stdout

    def test_missing_review_dir_fails(self, tmp_path):
        proc = run(REVIEW_STATUS, "--review-dir", str(tmp_path / "missing"))
        assert proc.returncode == 2
        assert "not found" in proc.stderr

    def _built_pipeline(self, tmp_path: Path, max_spans: int | None = None) -> Path:
        """Build a review run through the chunk/task stage (no observations
        yet), mirroring what the customer/reporter SKILL.md steps 1-5 do."""
        d = tmp_path / "run"
        d.mkdir()
        report = d / "normalized.txt"
        report.write_text(
            "# 1. 調査概要\n調査目的を記載しています。\n\n"
            "# 2. エグゼクティブサマリー\nVPN アカウントの悪用が疑われます。\n",
            encoding="utf-8",
        )
        source = d / "source_index.json"
        assert run(BUILD_INDEX, "--source", str(report), "--out", str(source)).returncode == 0
        (d / "run_manifest.json").write_text(
            json.dumps({
                "run_id": "test", "review_mode": "customer",
                "report_path": "Report.pdf", "model": "test",
            }),
            encoding="utf-8",
        )
        (d / "mechanical_checks.json").write_text("{}", encoding="utf-8")
        assert run(
            INIT_RESULTS, "--mode", "customer", "--out", str(d / "results.json"),
        ).returncode == 0
        chunk_args = ["--max-spans", str(max_spans)] if max_spans else []
        assert run(
            CREATE_CHUNKS, "--source-index", str(source),
            "--out-dir", str(d / "review_chunks"), "--mode", "customer", *chunk_args,
        ).returncode == 0
        assert run(
            CREATE_TASKS, "--chunk-dir", str(d / "review_chunks"),
            "--out-dir", str(d / "subagent_tasks"), "--mode", "customer",
        ).returncode == 0
        return d

    def test_reports_pending_subagent_chunks_without_running_merge(self, tmp_path):
        d = self._built_pipeline(tmp_path)
        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert proc.returncode == 1
        assert not (d / "merged_observations.json").exists()
        manifest = json.loads((d / "subagent_tasks" / "task_manifest.json").read_text(encoding="utf-8"))
        for task in manifest["tasks"]:
            assert task["chunk_id"] in proc.stdout
            assert task["task_path"] in proc.stdout

    def test_advances_past_subagent_stage_once_observations_are_written(self, tmp_path):
        d = self._built_pipeline(tmp_path)
        manifest = json.loads((d / "subagent_tasks" / "task_manifest.json").read_text(encoding="utf-8"))
        for idx, task in enumerate(manifest["tasks"]):
            task_data = json.loads(Path(task["task_path"]).read_text(encoding="utf-8"))
            core_ids = task_data["chunk"]["core_span_ids"]
            # merge_subagent_observations.py requires at least one substantive
            # observation across all chunks; give the first chunk a real one.
            checklist_observations = []
            if idx == 0:
                checklist_observations = [{
                    "observation_id": f"OBS-{task['chunk_id']}-001",
                    "checklist_id": "CUS-2-9",
                    "candidate_verdict": "met",
                    "rationale": "test",
                    "source_span_ids": [core_ids[0]],
                    "absence_check_ids": [],
                    "confidence": 0.9,
                }]
            obs = {
                "schema_version": "1.0",
                "chunk_id": task["chunk_id"],
                "review_mode": "customer",
                "covered_span_ids": core_ids,
                "checklist_observations": checklist_observations,
                "conclusion_observations": [],
                "issue_observations": [],
                "open_questions": [],
            }
            out_path = Path(task["observation_output_path"])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(obs, ensure_ascii=False), encoding="utf-8")

        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert (d / "merged_observations.json").exists()
        assert "results.json" in proc.stdout
        # must have moved past both the chunk/task stage and the SubAgent
        # observation stage, not just report them as still pending
        assert "SubAgent 観測 + coverage 統合" not in proc.stdout.rsplit("NEXT STEP", 1)[-1]

    def test_aggregation_worksheet_failure_is_not_silently_ignored(self, tmp_path):
        # Regression test: review_status.py used to discard
        # aggregate_observations.py's exit code entirely, so a corrupt
        # results.json (its second input) made merge report success while
        # the worksheet silently failed to (re)generate — the next stage
        # would then either point at a stale worksheet or one that never
        # existed, with no indication anything went wrong.
        d = self._built_pipeline(tmp_path)
        manifest = json.loads((d / "subagent_tasks" / "task_manifest.json").read_text(encoding="utf-8"))
        for task in manifest["tasks"]:
            task_data = json.loads(Path(task["task_path"]).read_text(encoding="utf-8"))
            core_ids = task_data["chunk"]["core_span_ids"]
            obs = {
                "schema_version": "1.0", "chunk_id": task["chunk_id"], "review_mode": "customer",
                "covered_span_ids": core_ids,
                "checklist_observations": [{
                    "observation_id": f"OBS-{task['chunk_id']}-001", "checklist_id": "CUS-2-9",
                    "candidate_verdict": "met", "rationale": "test",
                    "source_span_ids": [core_ids[0]], "absence_check_ids": [], "confidence": 0.9,
                }],
                "conclusion_observations": [], "issue_observations": [], "open_questions": [],
            }
            out_path = Path(task["observation_output_path"])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(obs, ensure_ascii=False), encoding="utf-8")

        (d / "results.json").write_text('{"results": [}', encoding="utf-8")  # corrupt

        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert proc.returncode == 1
        assert (d / "merged_observations.json").exists()  # merge itself still succeeded
        assert "aggregation_worksheet.json の生成に失敗" in proc.stdout
        assert "JSON 構文エラー" in proc.stdout

    def test_results_filled_stage_points_at_worksheet_not_raw_merge(self, tmp_path):
        # Regression test: an Agent facing 100+ flat merged_observations.json
        # rows with only prose guidance wrote its own aggregation script
        # instead of doing the judgment step. review_status.py must instead
        # point at the pre-grouped worksheet and explicitly say not to write
        # a new grouping script.
        d = self._built_pipeline(tmp_path, max_spans=2)  # force 2 chunks from 4 spans
        manifest = json.loads((d / "subagent_tasks" / "task_manifest.json").read_text(encoding="utf-8"))
        assert len(manifest["tasks"]) >= 2
        for idx, task in enumerate(manifest["tasks"][:2]):
            task_data = json.loads(Path(task["task_path"]).read_text(encoding="utf-8"))
            core_ids = task_data["chunk"]["core_span_ids"]
            # Both chunks observe the same checklist item with conflicting verdicts.
            verdict = "met" if idx == 0 else "not_met"
            obs = {
                "schema_version": "1.0",
                "chunk_id": task["chunk_id"],
                "review_mode": "customer",
                "covered_span_ids": core_ids,
                "checklist_observations": [{
                    "observation_id": f"OBS-{task['chunk_id']}-001",
                    "checklist_id": "CUS-2-9",
                    "candidate_verdict": verdict,
                    "rationale": "test",
                    "source_span_ids": [core_ids[0]],
                    "absence_check_ids": [],
                    "confidence": 0.7,
                }],
                "conclusion_observations": [],
                "issue_observations": [],
                "open_questions": [],
            }
            out_path = Path(task["observation_output_path"])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(obs, ensure_ascii=False), encoding="utf-8")
        for task in manifest["tasks"][2:]:
            obs = {
                "schema_version": "1.0", "chunk_id": task["chunk_id"], "review_mode": "customer",
                "covered_span_ids": json.loads(Path(task["task_path"]).read_text(encoding="utf-8"))
                    ["chunk"]["core_span_ids"],
                "checklist_observations": [], "conclusion_observations": [],
                "issue_observations": [], "open_questions": [],
            }
            out_path = Path(task["observation_output_path"])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(obs, ensure_ascii=False), encoding="utf-8")

        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        worksheet_path = d / "aggregation_worksheet.json"
        assert worksheet_path.exists()
        # the Agent is given the per-item view itself, not a file to dig through
        assert "表示・集計用のスクリプトを書いたりしません" in proc.stdout
        assert "■ CUS-2-9" in proc.stdout and "※食い違い" in proc.stdout

        worksheet = json.loads(worksheet_path.read_text(encoding="utf-8"))
        assert len(worksheet["checklist_items"]) == 57  # every item, not just observed ones
        cus29 = next(c for c in worksheet["checklist_items"] if c["checklist_id"] == "CUS-2-9")
        assert cus29["conflicting"] is True
        assert cus29["candidate_verdict_counts"] == {"met": 1, "not_met": 1}
        assert len(cus29["observations"]) == 2

    def test_logs_each_invocation_for_cross_turn_attempt_tracking(self, tmp_path):
        d = tmp_path / "run"
        d.mkdir()
        run(REVIEW_STATUS, "--review-dir", str(d))
        run(REVIEW_STATUS, "--review-dir", str(d))
        log_path = d / "run_log.jsonl"
        assert log_path.exists()
        lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        assert len(lines) == 2
        assert all(entry["event"] == "status" for entry in lines)

    def test_wrong_claim_field_names_are_named_in_next_step(self, tmp_path):
        """Regression test for a real incident: an Agent wrote
        "individual_claim_assessments" / "countermeasure_assessments" instead
        of "claim_assessments" / "recommendation_assessments", and the old
        generic "不足: claim_assessments.json (4配列)" message cost it 10+
        turns re-reading a syntactically-valid file it couldn't see was wrong.
        The message must name the present keys, the missing/empty required
        ones, and flag the unrecognized keys as likely typos."""
        d = self._built_pipeline(tmp_path)
        manifest = json.loads((d / "subagent_tasks" / "task_manifest.json").read_text(encoding="utf-8"))
        for task in manifest["tasks"]:
            task_data = json.loads(Path(task["task_path"]).read_text(encoding="utf-8"))
            core_ids = task_data["chunk"]["core_span_ids"]
            obs = {
                "schema_version": "1.0", "chunk_id": task["chunk_id"], "review_mode": "customer",
                "covered_span_ids": core_ids,
                "checklist_observations": [{
                    "observation_id": f"OBS-{task['chunk_id']}-001", "checklist_id": "CUS-2-9",
                    "candidate_verdict": "met", "rationale": "test",
                    "source_span_ids": [core_ids[0]], "absence_check_ids": [], "confidence": 0.9,
                }],
                "conclusion_observations": [], "issue_observations": [], "open_questions": [],
            }
            out_path = Path(task["observation_output_path"])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(obs, ensure_ascii=False), encoding="utf-8")
        run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")

        results = json.loads((d / "results.json").read_text(encoding="utf-8"))
        for row in results["results"]:
            row["verdict"] = "met" if not row.get("unknown_allowed") else "not_applicable"
            row["rationale"] = "test"
        (d / "results.json").write_text(json.dumps(results, ensure_ascii=False), encoding="utf-8")
        (d / "issues.json").write_text(json.dumps({"issues": []}), encoding="utf-8")

        # The real-world bug, reproduced verbatim: wrong field names.
        (d / "claim_assessments.json").write_text(json.dumps({
            "conclusion_inventory": [{"conclusion_id": "CON-001"}],
            "consistency_assessments": [],
            "individual_claim_assessments": [{"assessment_id": "ASM-001"}],
            "countermeasure_assessments": [],
        }), encoding="utf-8")

        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert "individual_claim_assessments" in proc.stdout
        assert "countermeasure_assessments" in proc.stdout
        assert "claim_assessments" in proc.stdout  # the correct name is shown too
        assert "recommendation_assessments" in proc.stdout
        assert "フィールド名を間違えている可能性" in proc.stdout

    def test_full_pipeline_reaches_done_and_persists_real_gate_artifacts(self, tmp_path):
        """Regression guard: the gate stage must write coverage_summary.json,
        issues_normalized.json, summary.json, summary.md and final_review.md
        into the real review dir (not a throwaway tempdir) — otherwise
        check_review_run.py fails forever and DONE is unreachable."""
        d = self._built_pipeline(tmp_path)
        manifest = json.loads((d / "subagent_tasks" / "task_manifest.json").read_text(encoding="utf-8"))
        for idx, task in enumerate(manifest["tasks"]):
            task_data = json.loads(Path(task["task_path"]).read_text(encoding="utf-8"))
            core_ids = task_data["chunk"]["core_span_ids"]
            checklist_observations = []
            if idx == 0:
                checklist_observations = [{
                    "observation_id": f"OBS-{task['chunk_id']}-001",
                    "checklist_id": "CUS-2-9",
                    "candidate_verdict": "met",
                    "rationale": "test",
                    "source_span_ids": [core_ids[0]],
                    "absence_check_ids": [],
                    "confidence": 0.9,
                }]
            obs = {
                "schema_version": "1.0",
                "chunk_id": task["chunk_id"],
                "review_mode": "customer",
                "covered_span_ids": core_ids,
                "checklist_observations": checklist_observations,
                "conclusion_observations": [],
                "issue_observations": [],
                "open_questions": [],
            }
            out_path = Path(task["observation_output_path"])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(obs, ensure_ascii=False), encoding="utf-8")

        # Run once so review_status.py performs the merge and reports the
        # results-filled stage; then fill results/issues/claims by hand,
        # exactly as the SKILL.md tells the Agent to do at that point.
        run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")

        source = json.loads((d / "source_index.json").read_text(encoding="utf-8"))
        real_span = source["spans"][0]["source_span_id"]

        results = json.loads((d / "results.json").read_text(encoding="utf-8"))
        unknown_ids = []
        for row in results["results"]:
            if row.get("unknown_allowed"):
                row["verdict"] = "unknown"
                row["unknown_reason"] = "external_information_missing"
                row["external_confirmation_needed"] = "test"
                unknown_ids.append(row["checklist_id"])
            else:
                row["verdict"] = "met"
                row["source_span_ids"] = [real_span]
            row["rationale"] = "test"
        (d / "results.json").write_text(json.dumps(results, ensure_ascii=False), encoding="utf-8")

        # Every unknown-verdict item now requires a matching external_confirmation
        # issue (otherwise "unknown: N" / "external confirmation needed: 0" would
        # contradict each other in the final summary) — bundle them into one issue.
        (d / "issues.json").write_text(json.dumps({"issues": [{
            "category": "external_confirmation",
            "severity": "medium",
            "checklist_ids": unknown_ids,
            "status": "unknown",
            "source_span_ids": [real_span],
            "absence_check_ids": [],
            "reason": "test: 報告書外資料の確認が必要",
            "suggested_revision": "",
        }]}), encoding="utf-8")

        topics = [
            "initial_access", "scope", "lateral_movement", "persistence",
            "c2_external", "exfiltration", "impact", "limitations", "recommendations",
        ]
        claims = {
            "conclusion_inventory": [
                {
                    "conclusion_id": "CON-001", "topic": topics[0], "presence": "reported",
                    "stated_conclusion": "test", "assessment_ids": ["ASM-001"],
                    "source_span_ids": [real_span], "absence_check_ids": [], "reason": "test",
                },
                *[
                    {
                        "conclusion_id": f"CON-{i:03d}", "topic": t, "presence": "not_reported",
                        "stated_conclusion": "", "assessment_ids": [], "source_span_ids": [],
                        "absence_check_ids": [f"ABS-CON-{t}"], "reason": "not reported",
                    }
                    for i, t in enumerate(topics[1:], 2)
                ],
            ],
            "consistency_assessments": [{
                "consistency_id": "CNS-001", "related_conclusion_ids": ["CON-001", "CON-002"],
                "consistency_verdict": "not_assessable", "source_span_ids": [],
                "absence_check_ids": [f"ABS-CON-{topics[1]}"], "reason": "test",
                "suggested_revision": "",
            }],
            "claim_assessments": [{
                "assessment_id": "ASM-001", "topic": topics[0], "conclusion": "test",
                "stated_confidence": "unknown", "review_verdict": "not_assessable",
                "support_summary": "", "evidence_assessment": "", "logic_assessment": "",
                "confidence_assessment": "", "limitations": [], "reason": "test",
                "suggested_revision": "", "source_span_ids": [real_span],
                "absence_check_ids": [], "issue_ids": [],
            }],
            "recommendation_assessments": [],
        }
        (d / "claim_assessments.json").write_text(json.dumps(claims, ensure_ascii=False), encoding="utf-8")

        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert "DONE" in proc.stdout, proc.stdout
        assert proc.returncode == 0

        for name in (
            "coverage_summary.json", "issues_normalized.json", "summary.json",
            "summary.md", "final_review.md", "aggregation_worksheet.json",
            "final_review.html",
        ):
            path = d / name
            assert path.exists() and path.stat().st_size > 0, name

        assert run(CHECK_RUN, "--review-dir", str(d)).returncode == 0

        # Re-running must stay DONE (idempotent) rather than re-detecting
        # missing work.
        proc2 = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert "DONE" in proc2.stdout


class TestAggregateObservations:
    """Unit tests for the pure-grouping worksheet builder, independent of the
    full pipeline. It must group and count — never judge."""

    def _write(self, tmp_path: Path, merged: dict, results_rows: list[dict]) -> tuple[Path, Path, Path]:
        merged_path = tmp_path / "merged_observations.json"
        merged_path.write_text(json.dumps(merged, ensure_ascii=False), encoding="utf-8")
        results_path = tmp_path / "results.json"
        results_path.write_text(
            json.dumps({"results": results_rows}, ensure_ascii=False), encoding="utf-8"
        )
        out_path = tmp_path / "worksheet.json"
        return merged_path, results_path, out_path

    def test_every_checklist_item_appears_even_without_observations(self, tmp_path):
        merged_path, results_path, out_path = self._write(
            tmp_path,
            {"checklist_observations": [], "conclusion_observations": [],
             "issue_observations": [], "open_questions": []},
            [
                {"checklist_id": "CUS-1-1", "item": "a", "level": "必須",
                 "unknown_allowed": False, "verdict": None},
                {"checklist_id": "CUS-1-2", "item": "b", "level": "推奨",
                 "unknown_allowed": False, "verdict": "met"},
            ],
        )
        proc = run(AGGREGATE, "--merged-observations", str(merged_path),
                   "--results", str(results_path), "--out", str(out_path))
        assert proc.returncode == 0, proc.stdout
        w = json.loads(out_path.read_text(encoding="utf-8"))
        ids = {c["checklist_id"] for c in w["checklist_items"]}
        assert ids == {"CUS-1-1", "CUS-1-2"}
        cus11 = next(c for c in w["checklist_items"] if c["checklist_id"] == "CUS-1-1")
        assert cus11["observation_count"] == 0
        assert cus11["observations"] == []
        assert cus11["conflicting"] is False
        assert cus11["current_verdict"] is None

    def test_conflicting_verdicts_are_flagged(self, tmp_path):
        merged_path, results_path, out_path = self._write(
            tmp_path,
            {
                "checklist_observations": [
                    {"chunk_id": "CHK-001", "observation_id": "OBS-1",
                     "checklist_id": "CUS-1-1", "candidate_verdict": "met",
                     "rationale": "r1", "source_span_ids": ["SPN-1"], "confidence": 0.9},
                    {"chunk_id": "CHK-002", "observation_id": "OBS-2",
                     "checklist_id": "CUS-1-1", "candidate_verdict": "not_met",
                     "rationale": "r2", "source_span_ids": ["SPN-2"], "confidence": 0.4},
                ],
                "conclusion_observations": [], "issue_observations": [], "open_questions": [],
            },
            [{"checklist_id": "CUS-1-1", "item": "a", "level": "必須",
              "unknown_allowed": False, "verdict": None}],
        )
        proc = run(AGGREGATE, "--merged-observations", str(merged_path),
                   "--results", str(results_path), "--out", str(out_path))
        assert proc.returncode == 0, proc.stdout
        assert "1 conflicting" in proc.stdout
        w = json.loads(out_path.read_text(encoding="utf-8"))
        cus11 = w["checklist_items"][0]
        assert cus11["conflicting"] is True
        assert cus11["candidate_verdict_counts"] == {"met": 1, "not_met": 1}
        assert len(cus11["observations"]) == 2

    def test_unknown_and_not_applicable_disagreement_is_not_a_conflict(self, tmp_path):
        # unknown/not_applicable alongside met is not the same kind of
        # contradiction as met vs not_met — see review_model.md section 2 (conflicting observations).
        merged_path, results_path, out_path = self._write(
            tmp_path,
            {
                "checklist_observations": [
                    {"chunk_id": "CHK-001", "observation_id": "OBS-1",
                     "checklist_id": "CUS-1-1", "candidate_verdict": "met",
                     "rationale": "r1", "source_span_ids": ["SPN-1"]},
                    {"chunk_id": "CHK-002", "observation_id": "OBS-2",
                     "checklist_id": "CUS-1-1", "candidate_verdict": "not_applicable",
                     "rationale": "r2", "source_span_ids": []},
                ],
                "conclusion_observations": [], "issue_observations": [], "open_questions": [],
            },
            [{"checklist_id": "CUS-1-1", "item": "a", "level": "必須",
              "unknown_allowed": False, "verdict": None}],
        )
        proc = run(AGGREGATE, "--merged-observations", str(merged_path),
                   "--results", str(results_path), "--out", str(out_path))
        assert proc.returncode == 0, proc.stdout
        w = json.loads(out_path.read_text(encoding="utf-8"))
        assert w["checklist_items"][0]["conflicting"] is False

    def test_topics_include_all_required_topics_even_when_empty(self, tmp_path):
        merged_path, results_path, out_path = self._write(
            tmp_path,
            {
                "checklist_observations": [], "issue_observations": [], "open_questions": [],
                "conclusion_observations": [
                    {"chunk_id": "CHK-001", "observation_id": "OBS-1",
                     "topic": "initial_access", "stated_conclusion": "x",
                     "source_span_ids": ["SPN-1"], "confidence_language": "possible"},
                ],
            },
            [],
        )
        proc = run(AGGREGATE, "--merged-observations", str(merged_path),
                   "--results", str(results_path), "--out", str(out_path))
        assert proc.returncode == 0, proc.stdout
        w = json.loads(out_path.read_text(encoding="utf-8"))
        topics = {t["topic"]: t for t in w["topics"]}
        assert "initial_access" in topics
        assert "recommendations" in topics  # present even with 0 observations
        assert topics["initial_access"]["observation_count"] == 1
        assert topics["recommendations"]["observation_count"] == 0

    def test_issue_observations_are_clustered_by_related_checklist_ids(self, tmp_path):
        merged_path, results_path, out_path = self._write(
            tmp_path,
            {
                "checklist_observations": [], "conclusion_observations": [], "open_questions": [],
                "issue_observations": [
                    {"chunk_id": "CHK-001", "observation_id": "OBS-1",
                     "category": "evidence_integrity", "related_checklist_ids": ["CUS-1-1"],
                     "reason": "r1", "source_span_ids": ["SPN-1"]},
                    {"chunk_id": "CHK-002", "observation_id": "OBS-2",
                     "category": "evidence_integrity", "related_checklist_ids": ["CUS-1-1"],
                     "reason": "r2 (duplicate finding, different chunk)", "source_span_ids": ["SPN-2"]},
                    {"chunk_id": "CHK-003", "observation_id": "OBS-3",
                     "category": "format_or_usability", "related_checklist_ids": [],
                     "reason": "r3", "source_span_ids": ["SPN-3"]},
                ],
            },
            [],
        )
        proc = run(AGGREGATE, "--merged-observations", str(merged_path),
                   "--results", str(results_path), "--out", str(out_path))
        assert proc.returncode == 0, proc.stdout
        w = json.loads(out_path.read_text(encoding="utf-8"))
        clusters = {tuple(c["related_checklist_ids"]): c for c in w["issue_clusters"]}
        assert clusters[("CUS-1-1",)]["observation_count"] == 2
        assert clusters[("(no checklist link)",)]["observation_count"] == 1

    def test_open_questions_pass_through(self, tmp_path):
        merged_path, results_path, out_path = self._write(
            tmp_path,
            {
                "checklist_observations": [], "conclusion_observations": [], "issue_observations": [],
                "open_questions": [{
                    "question_id": "Q-CHK-001-001", "question": "確認事項",
                    "reason": "chunk内では判定不可", "source_span_ids": ["SPN-1"],
                }],
            },
            [],
        )
        proc = run(AGGREGATE, "--merged-observations", str(merged_path),
                   "--results", str(results_path), "--out", str(out_path))
        assert proc.returncode == 0, proc.stdout
        w = json.loads(out_path.read_text(encoding="utf-8"))
        assert [q["question_id"] for q in w["open_questions"]] == ["Q-CHK-001-001"]

    def test_missing_inputs_fail_cleanly(self, tmp_path):
        proc = run(AGGREGATE,
                   "--merged-observations", str(tmp_path / "missing.json"),
                   "--results", str(tmp_path / "results.json"),
                   "--out", str(tmp_path / "out.json"))
        assert proc.returncode == 2

    def test_malformed_input_names_the_broken_file(self, tmp_path):
        bad = tmp_path / "merged_observations.json"
        bad.write_text('{"checklist_observations": [}', encoding="utf-8")  # invalid
        results = tmp_path / "results.json"
        results.write_text("{}", encoding="utf-8")
        proc = run(AGGREGATE,
                   "--merged-observations", str(bad), "--results", str(results),
                   "--out", str(tmp_path / "out.json"))
        assert proc.returncode == 2
        assert "Traceback" not in proc.stderr
        assert str(bad) in proc.stderr
        assert "JSON 構文エラー" in proc.stderr


class TestCheckAbsenceGrounding:
    """Not a wording check: it only compares results.json's grounding against
    what SubAgents independently observed (aggregation_worksheet.json). It
    must stay silent whenever there is nothing observed to compare against —
    including the ordinary case of zero observations — and fire only when a
    real, already-collected span is being dropped."""

    def _worksheet(self, tmp_path: Path, checklist_items: list[dict]) -> Path:
        path = tmp_path / "aggregation_worksheet.json"
        path.write_text(json.dumps({"checklist_items": checklist_items}, ensure_ascii=False),
                         encoding="utf-8")
        return path

    def _results(self, tmp_path: Path, rows: list[dict]) -> Path:
        path = tmp_path / "results.json"
        path.write_text(json.dumps({"results": rows}, ensure_ascii=False), encoding="utf-8")
        return path

    @staticmethod
    def _row(cid, verdict, spans=None):
        return {"checklist_id": cid, "verdict": verdict, "source_span_ids": spans or []}

    @staticmethod
    def _group(cid, observations):
        return {"checklist_id": cid, "observations": observations}

    def test_silent_when_no_observation_has_a_span(self, tmp_path):
        # Zero observations at all (the common, legitimate case) and an
        # observation that itself has no span both must not trigger anything.
        results = self._results(tmp_path, [
            self._row("CUS-1-1", "not_met"),
            self._row("CUS-1-2", "unknown"),
        ])
        worksheet = self._worksheet(tmp_path, [
            self._group("CUS-1-1", []),
            self._group("CUS-1-2", [{"observation_id": "O1", "source_span_ids": []}]),
        ])
        proc = run(ABSENCE_GROUNDING, "--results", str(results), "--worksheet", str(worksheet))
        assert proc.returncode == 0, proc.stdout
        assert "PASS" in proc.stdout

    def test_silent_when_already_grounded_or_verdict_is_not_absence(self, tmp_path):
        results = self._results(tmp_path, [
            self._row("CUS-1-1", "not_met", spans=["SPN-1"]),  # already cites the span
            self._row("CUS-1-2", "partial"),  # not an absence verdict
        ])
        worksheet = self._worksheet(tmp_path, [
            self._group("CUS-1-1", [{"observation_id": "O1", "source_span_ids": ["SPN-1"]}]),
            self._group("CUS-1-2", [{"observation_id": "O2", "source_span_ids": ["SPN-2"]}]),
        ])
        proc = run(ABSENCE_GROUNDING, "--results", str(results), "--worksheet", str(worksheet))
        assert proc.returncode == 0, proc.stdout

    def test_flags_a_dropped_observed_span(self, tmp_path):
        # Regression test for a real run: SubAgents observed a span for an
        # item, but the final results.json row claimed plain absence anyway.
        results = self._results(tmp_path, [self._row("CUS-2.3-2", "not_met")])
        worksheet = self._worksheet(tmp_path, [
            self._group("CUS-2.3-2", [{"observation_id": "O1", "source_span_ids": ["SPN-9"]}]),
        ])
        proc = run(ABSENCE_GROUNDING, "--results", str(results), "--worksheet", str(worksheet))
        assert proc.returncode == 1
        assert "CUS-2.3-2" in proc.stdout and "SPN-9" in proc.stdout

    def test_out_of_scope_rows_are_never_flagged(self, tmp_path):
        results = self._results(tmp_path, [
            {"checklist_id": "CUS-1-1", "verdict": "not_met", "source_span_ids": [],
             "evaluation_scope": "out_of_scope"},
        ])
        worksheet = self._worksheet(tmp_path, [
            self._group("CUS-1-1", [{"observation_id": "O1", "source_span_ids": ["SPN-1"]}]),
        ])
        proc = run(ABSENCE_GROUNDING, "--results", str(results), "--worksheet", str(worksheet))
        assert proc.returncode == 0, proc.stdout


class TestRenderReviewHtml:
    """final_review.html is a derived, read-only view of final_review.md."""

    MD = (
        "# レビュー結果\n\n## 3. 重大な指摘事項\n\n"
        "- `ISS-aaaaaaaa` [quality_defect / high] unsupported_claim\n"
        "  - 理由: 根拠なし。参照 ISS-aaaaaaaa\n"
        "  - 原文引用:\n"
        "    - 3.2: 「<script>alert(1)</script> & <img src=x onerror=1>」\n\n"
        "## 付録A. チェックリスト全項目結果\n\n"
        "| ID | 区分 | 判定 | 項目 |\n|---|---|---|---|\n"
        "| CUS-1-1 | 必須 | not_met | a |\n| CUS-1-2 | 推奨 | met | b |\n"
    )

    def _render(self, tmp_path, md=None):
        src = tmp_path / "final_review.md"
        src.write_text(md or self.MD, encoding="utf-8")
        out = tmp_path / "final_review.html"
        proc = run(RENDER_HTML, "--review", str(src), "--out", str(out))
        assert proc.returncode == 0, proc.stderr
        return out.read_text(encoding="utf-8")

    def test_untrusted_report_text_is_escaped(self, tmp_path):
        page = self._render(tmp_path)
        assert "<script>alert(1)</script>" not in page
        assert "<img src=x" not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
        # the only script element is our own filter code, and no network loads
        assert page.count("<script>") == 1
        assert "http://" not in page and "https://" not in page

    def test_issue_badge_anchor_and_crosslink(self, tmp_path):
        page = self._render(tmp_path)
        assert 'id="ISS-aaaaaaaa"' in page
        assert "sev-high" in page
        assert 'href="#ISS-aaaaaaaa"' in page  # mention in the reason links back

    def test_toc_and_appendix_filter(self, tmp_path):
        page = self._render(tmp_path)
        assert "<nav" in page and 'href="#3-重大な指摘事項"' in page
        assert page.count("data-verdict=") == 2
        assert 'data-verdict="not_met"' in page and "v-not_met" in page
        assert 'id="verdict-filters"' in page

    def test_missing_or_empty_input_fails_cleanly(self, tmp_path):
        out = tmp_path / "o.html"
        assert run(RENDER_HTML, "--review", str(tmp_path / "no.md"), "--out", str(out)).returncode == 2
        empty = tmp_path / "e.md"
        empty.write_text("", encoding="utf-8")
        proc = run(RENDER_HTML, "--review", str(empty), "--out", str(out))
        assert proc.returncode == 2 and not out.exists()

    def test_html_artifact_is_allowed_by_check_review_run(self, tmp_path):
        d = TestCheckReviewRun()._make_run_dir(tmp_path)
        (d / "final_review.html").write_text("<html></html>", encoding="utf-8")
        assert run(CHECK_RUN, "--review-dir", str(d)).returncode == 0


class TestSuggestionsAndIssuesSkeleton:
    """Time-savers for the two slowest hand-written steps: filling unanimous
    `met` rows in results.json and writing issues.json from scratch."""

    def _worksheet(self, tmp_path, observations, rows):
        merged = tmp_path / "merged_observations.json"
        merged.write_text(json.dumps({
            "checklist_observations": observations, "conclusion_observations": [],
            "issue_observations": [], "open_questions": [],
        }, ensure_ascii=False), encoding="utf-8")
        results = tmp_path / "results.json"
        results.write_text(json.dumps({"results": rows}, ensure_ascii=False), encoding="utf-8")
        out = tmp_path / "aggregation_worksheet.json"
        assert run(AGGREGATE, "--merged-observations", str(merged),
                   "--results", str(results), "--out", str(out)).returncode == 0
        return {c["checklist_id"]: c for c in json.loads(out.read_text(encoding="utf-8"))["checklist_items"]}

    @staticmethod
    def _obs(cid, verdict, oid, spans=("SPN-1",)):
        return {"observation_id": oid, "checklist_id": cid, "candidate_verdict": verdict,
                "rationale": "根拠あり", "source_span_ids": list(spans), "absence_check_ids": []}

    @staticmethod
    def _row(cid, item, verdict=None):
        return {"checklist_id": cid, "item": item, "level": "必須", "verdict": verdict}

    def test_suggestion_only_where_subagents_agree(self, tmp_path):
        ws = self._worksheet(tmp_path, [
            self._obs("CUS-1-1", "met", "O1"), self._obs("CUS-1-1", "met", "O2", ("SPN-2",)),
            self._obs("CUS-1-2", "met", "O3"), self._obs("CUS-1-2", "not_met", "O4"),
            self._obs("CUS-1-3", "partial", "O5"),
            self._obs("CUS-1-4", "met", "O6", ()),
            self._obs("CUS-1-5", "met", "O7"),
            self._obs("CUS-1-6", "not_met", "O8"),
            self._obs("CUS-1-7", "unknown", "O9"),
            self._obs("CUS-1-8", "partial", "O10"), self._obs("CUS-1-8", "not_met", "O11"),
        ], [
            self._row("CUS-1-1", "連絡先が記載されている"),
            self._row("CUS-1-2", "b"), self._row("CUS-1-3", "c"), self._row("CUS-1-4", "d"),
            self._row("CUS-1-5", "すべての結論に確度が付いている"),
            self._row("CUS-1-6", "f"), self._row("CUS-1-7", "g"), self._row("CUS-1-8", "h"),
        ])
        sug = ws["CUS-1-1"]["suggestion"]
        assert sug["verdict"] == "met" and sug["source_span_ids"] == ["SPN-1", "SPN-2"]
        assert sug["auto_applicable"] is True and "O1" in sug["rationale"]
        assert ws["CUS-1-2"]["suggestion"] is None      # conflict stays with the Agent
        assert ws["CUS-1-4"]["suggestion"] is None      # no cited span
        assert ws["CUS-1-7"]["suggestion"] is None      # unknown needs external-material fields
        assert ws["CUS-1-8"]["suggestion"] is None      # partial vs not_met: mixed
        # unanimous non-met verdicts are suggested too; not_met carries its absence id
        partial = ws["CUS-1-3"]["suggestion"]
        assert partial["verdict"] == "partial" and partial["auto_applicable"] is True
        notmet = ws["CUS-1-6"]["suggestion"]
        assert notmet["verdict"] == "not_met" and notmet["absence_check_ids"] == ["ABS-CUS-1-6"]
        # only a "met" on an all-of-X item needs the Agent to confirm it holds everywhere
        universal = ws["CUS-1-5"]["suggestion"]
        assert universal["auto_applicable"] is False and "すべて" in universal["not_auto_reason"]

    def test_zero_observation_items_are_not_met_without_searching_the_report(self, tmp_path):
        rows = [
            self._row("CUS-2-1", None), self._row("CUS-2-2", None),
            {**self._row("CUS-2-3", None), "unknown_allowed": True},
            {**self._row("CUS-2-4", None), "section": "2.4. 脅威インテリジェンス調査［依頼している場合］"},
        ]
        for r in rows:
            r["item"] = "項目"
        ws = self._worksheet(tmp_path, [], rows)
        sug = ws["CUS-2-1"]["suggestion"]
        assert sug["verdict"] == "not_met" and sug["basis"] == "no_observation"
        assert sug["absence_check_ids"] == ["ABS-CUS-2-1"] and sug["source_span_ids"] == []
        assert sug["auto_applicable"] is True
        assert ws["CUS-2-3"]["suggestion"] is None   # may need out-of-report material: Agent's call
        assert ws["CUS-2-4"]["suggestion"] is None   # conditional item may be not_applicable
        # applied verbatim, including the absence id
        proc = run(APPLY_SUGGESTED, "--review-dir", str(tmp_path), "--all-auto")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        after = {r["checklist_id"]: r for r in json.loads(
            (tmp_path / "results.json").read_text(encoding="utf-8"))["results"]}
        assert after["CUS-2-1"]["verdict"] == "not_met"
        assert after["CUS-2-1"]["absence_check_ids"] == ["ABS-CUS-2-1"]
        assert after["CUS-2-3"]["verdict"] is None and after["CUS-2-4"]["verdict"] is None

    def test_apply_suggested_results_never_overwrites_and_skips_universal(self, tmp_path):
        self._worksheet(tmp_path, [
            self._obs("CUS-1-1", "met", "O1"), self._obs("CUS-1-2", "met", "O2"),
            self._obs("CUS-1-3", "met", "O3"),
        ], [
            self._row("CUS-1-1", "a"), self._row("CUS-1-2", "b", verdict="partial"),
            self._row("CUS-1-3", "すべての項目"),
        ])
        proc = run(APPLY_SUGGESTED, "--review-dir", str(tmp_path), "--all-auto")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        rows = {r["checklist_id"]: r for r in json.loads(
            (tmp_path / "results.json").read_text(encoding="utf-8"))["results"]}
        assert rows["CUS-1-1"]["verdict"] == "met" and rows["CUS-1-1"]["source_span_ids"] == ["SPN-1"]
        assert rows["CUS-1-2"]["verdict"] == "partial"       # Agent's judgment kept
        assert rows["CUS-1-3"]["verdict"] is None            # universal: not auto
        # ...but the Agent can name it explicitly after reading it
        assert run(APPLY_SUGGESTED, "--review-dir", str(tmp_path), "--ids", "CUS-1-3").returncode == 0
        # and cannot force a verdict where no suggestion exists
        bad = run(APPLY_SUGGESTED, "--review-dir", str(tmp_path), "--ids", "CUS-9-9")
        assert bad.returncode == 2 and "CUS-9-9" in bad.stderr

    def _skeleton_dir(self, tmp_path):
        d = TestReviewStatus()._built_pipeline(tmp_path)
        source = json.loads((d / "source_index.json").read_text(encoding="utf-8"))
        span = source["spans"][-1]["source_span_id"]
        results = json.loads((d / "results.json").read_text(encoding="utf-8"))
        rows = results["results"]
        manifest = json.loads((d / "subagent_tasks" / "task_manifest.json").read_text(encoding="utf-8"))
        for idx, task in enumerate(manifest["tasks"]):
            core_ids = json.loads(Path(task["task_path"]).read_text(encoding="utf-8"))["chunk"]["core_span_ids"]
            first = idx == 0
            obs = {
                "schema_version": "1.0", "chunk_id": task["chunk_id"], "review_mode": "customer",
                "covered_span_ids": core_ids,
                "checklist_observations": [{
                    "observation_id": "OBS-1", "checklist_id": "CUS-2-9", "candidate_verdict": "met",
                    "rationale": "test", "source_span_ids": [core_ids[0]],
                    "absence_check_ids": [], "confidence": 0.9,
                }] if first else [],
                "conclusion_observations": [{
                    "observation_id": "OBS-C1", "topic": "persistence",
                    "stated_conclusion": "UNS40-76でスケジュールタスクによる永続化が確認された",
                    "source_span_ids": [core_ids[0]], "confidence_language": "confirmed",
                }] if first else [],
                "issue_observations": [{
                    "observation_id": "ISO-1", "related_checklist_ids": [rows[1]["checklist_id"]],
                    "category": "unsupported_claim", "severity_hint": "high", "reason": "r",
                    "source_span_ids": [core_ids[0]], "suggested_revision": "s",
                }] if first else [],
                "open_questions": [{
                    "question_id": "Q-1", "question": "調査依頼書の内容は？", "reason": "本文に記載なし",
                    "source_span_ids": [core_ids[0]],
                    "related_checklist_ids": [rows[0]["checklist_id"]],
                }] if first else [],
            }
            out_path = Path(task["observation_output_path"])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(obs, ensure_ascii=False), encoding="utf-8")
        run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert (d / "merged_observations.json").exists()
        rows[0].update(verdict="not_met", rationale="未記載", source_span_ids=[])
        rows[1].update(verdict="partial", rationale="一部のみ", source_span_ids=[span])
        rows[2].update(verdict="unknown", unknown_reason="external_information_missing",
                       external_confirmation_needed="契約書の確認", rationale="")
        for row in rows[3:]:
            row.update(verdict="met", rationale="ok")
        (d / "results.json").write_text(json.dumps(results, ensure_ascii=False), encoding="utf-8")
        return d, rows, span

    def test_skeleton_is_grounded_and_prefilled_with_item_derived_defaults(self, tmp_path):
        d, rows, span = self._skeleton_dir(tmp_path)
        proc = run(ISSUES_SKELETON, "--review-dir", str(d))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        issues = json.loads((d / "issues.json").read_text(encoding="utf-8"))["issues"]
        by_cid = {i["checklist_ids"][0]: i for i in issues if "Q-1" not in i.get(
            "source_observation_ids", [])}
        assert len(issues) == 4   # 3 judged items + 1 open question; met rows produce nothing
        notmet = by_cid[rows[0]["checklist_id"]]
        assert notmet["absence_check_ids"] == [f"ABS-{rows[0]['checklist_id']}"]
        assert notmet["category"] == "missing_required_item"
        # item-derived defaults mean nothing is left for a bulk-fix script to write ...
        assert rows[0]["item"] in notmet["suggested_revision"]
        assert "auto_filled" in notmet and "suggested_revision" in notmet["auto_filled"]
        partial = by_cid[rows[1]["checklist_id"]]
        assert partial["source_span_ids"] == [span]
        assert (partial["category"], partial["severity"]) == ("unsupported_claim", "high")
        assert "ISO-1" in partial["source_observation_ids"]
        unknown = by_cid[rows[2]["checklist_id"]]
        assert unknown["category"] == "external_confirmation"
        assert unknown["suggested_revision"] == "契約書の確認"
        # ... and every default is a valid category, so none can be invented
        assert all(i["category"] in ISSUE_CATEGORIES for i in issues)
        # SubAgent open questions cannot be lost: each becomes its own issue
        question = next(i for i in issues if "Q-1" in i.get("source_observation_ids", []))
        assert question["category"] == "external_confirmation"
        assert "調査依頼書の内容は？" in question["suggested_revision"]

    def test_leftover_placeholder_still_blocks_the_gate(self, tmp_path):
        d, rows, _ = self._skeleton_dir(tmp_path)
        assert run(ISSUES_SKELETON, "--review-dir", str(d)).returncode == 0
        data = json.loads((d / "issues.json").read_text(encoding="utf-8"))
        data["issues"][0]["suggested_revision"] = "【要記入】"
        (d / "issues.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        gate = run(ISSUES, "--issues", str(d / "issues.json"), "--results", str(d / "results.json"),
                   "--mode", "customer", "--source-index", str(d / "source_index.json"),
                   "--strict-grounding")
        assert gate.returncode != 0 and "【要記入】" in gate.stdout + gate.stderr

    def test_skeleton_refuses_overwrite_and_unfilled_results(self, tmp_path):
        d, rows, _ = self._skeleton_dir(tmp_path)
        assert run(ISSUES_SKELETON, "--review-dir", str(d)).returncode == 0
        again = run(ISSUES_SKELETON, "--review-dir", str(d))
        assert again.returncode == 2 and "already exists" in again.stderr
        (d / "issues.json").unlink()
        results = json.loads((d / "results.json").read_text(encoding="utf-8"))
        results["results"][0]["verdict"] = None
        (d / "results.json").write_text(json.dumps(results), encoding="utf-8")
        assert run(ISSUES_SKELETON, "--review-dir", str(d)).returncode == 2

    def test_review_status_creates_both_skeletons_then_reports_all_failures_at_once(self, tmp_path):
        d, rows, _ = self._skeleton_dir(tmp_path)
        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert proc.returncode == 1
        assert (d / "issues.json").exists() and (d / "claim_assessments.json").exists()
        assert "雛形を自動生成" in proc.stdout
        events = [json.loads(line) for line in (d / "run_log.jsonl").read_text(encoding="utf-8").splitlines()]
        assert any(e["event"] == "init_issues_skeleton" and e["ok"] for e in events)
        assert any(e["event"] == "init_claims_skeleton" and e["ok"] for e in events)

        # Second run: the claims skeleton still has 【要記入】 (the Agent's
        # judgment). Put a problem into issues.json too: both gates must be
        # reported in the SAME run, not one gate per round trip.
        issues = json.loads((d / "issues.json").read_text(encoding="utf-8"))
        issues["issues"][0]["category"] = "completeness"  # an invented category
        (d / "issues.json").write_text(json.dumps(issues, ensure_ascii=False), encoding="utf-8")
        proc2 = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert proc2.returncode == 1
        assert "--- check_claim_assessments.py ---" in proc2.stdout
        assert "--- check_issues.py ---" in proc2.stdout
        repairs = json.loads((d / "repair_instructions.json").read_text(encoding="utf-8"))
        assert {"check_claim_assessments.py", "check_issues.py"} <= set(repairs["failed_gates"])
        assert {r["gate"] for r in repairs["repairs"]} <= set(repairs["failed_gates"])
        assert {r["gate"] for r in repairs["repairs"]} >= {
            "check_claim_assessments.py", "check_issues.py"}

    def test_gate_failure_reason_and_repair_targets_are_logged(self, tmp_path):
        d, rows, _ = self._skeleton_dir(tmp_path)
        # A complete-looking but ungrounded issue set: the gate must fail and
        # run_log.jsonl must say why and which file to edit.
        (d / "issues.json").write_text(json.dumps({"issues": [{
            "category": "unsupported_claim", "severity": "low", "checklist_ids": [rows[1]["checklist_id"]],
            "reason": "r", "suggested_revision": "s",
        }]}), encoding="utf-8")
        (d / "claim_assessments.json").write_text(json.dumps({
            "conclusion_inventory": [{"x": 1}], "consistency_assessments": [{"x": 1}],
            "claim_assessments": [{"x": 1}],
        }), encoding="utf-8")
        run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        events = [json.loads(line) for line in (d / "run_log.jsonl").read_text(encoding="utf-8").splitlines()]
        failures = [e for e in events if e["event"] == "gate_result" and not e["ok"]]
        assert failures and failures[-1]["summary"]
        assert any(e["event"] == "repair_targets" for e in events)


class TestSlimClaimAssessments:
    """The Agent writes only review_verdict + one reason per assessment row."""

    @staticmethod
    def _render_module():
        import importlib
        scripts = str(SKILLS / "ir-review-report" / "scripts")
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        return importlib.import_module("render_review")

    def _minimal(self):
        payload = TestClaimAssessments()._valid_payload()
        for row in payload["conclusion_inventory"]:
            row.pop("reason", None)
        for row in payload["claim_assessments"]:
            for key in ("support_summary", "evidence_assessment", "logic_assessment",
                        "confidence_assessment", "limitations", "suggested_revision"):
                row.pop(key, None)
        payload["consistency_assessments"][0].pop("suggested_revision", None)
        return payload

    def test_minimal_rows_pass_the_checker(self, tmp_path):
        path = tmp_path / "a.json"
        path.write_text(json.dumps(self._minimal(), ensure_ascii=False), encoding="utf-8")
        proc = run(ASSESS, "--assessments", str(path))
        assert proc.returncode == 0, proc.stdout

    def test_reason_is_still_required(self, tmp_path):
        payload = self._minimal()
        payload["claim_assessments"][0].pop("reason")
        path = tmp_path / "a.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        proc = run(ASSESS, "--assessments", str(path))
        assert proc.returncode == 1 and "reason" in proc.stdout

    def test_skeleton_leaves_only_verdict_and_reason_to_the_agent(self, tmp_path):
        d = TestReviewStatus()._built_pipeline(tmp_path)
        source = json.loads((d / "source_index.json").read_text(encoding="utf-8"))
        span = source["spans"][0]["source_span_id"]
        (d / "merged_observations.json").write_text(json.dumps({
            "checklist_observations": [], "issue_observations": [], "open_questions": [],
            "conclusion_observations": [{
                "observation_id": "O1", "topic": "persistence", "source_span_ids": [span],
                "stated_conclusion": "UNS40-76でスケジュールタスクによる永続化が確認された",
                "confidence_language": "confirmed"}],
        }, ensure_ascii=False), encoding="utf-8")
        assert run(CLAIMS_SKELETON, "--review-dir", str(d)).returncode == 0
        data = json.loads((d / "claim_assessments.json").read_text(encoding="utf-8"))
        for key in ("claim_assessments", "consistency_assessments", "recommendation_assessments"):
            for row in data[key]:
                todo = {k for k, v in row.items() if v == "【要記入】"}
                assert todo <= {"review_verdict", "consistency_verdict", "reason"}, (key, todo)
        asm = data["claim_assessments"][0]
        assert set(asm) >= {"review_verdict", "reason"}
        assert not {"support_summary", "evidence_assessment", "logic_assessment",
                    "confidence_assessment"} & set(asm)
        assert "limitations" not in asm          # optional; added only when relevant

    def test_limitations_column_appears_only_when_used_and_legacy_fields_fold(self):
        render = self._render_module()
        rows = [
            {"assessment_id": "ASM-001", "conclusion": "c", "stated_confidence": "possible",
             "review_verdict": "supported", "reason": "新形式の評価"},
            {"assessment_id": "ASM-002", "conclusion": "c", "stated_confidence": "possible",
             "review_verdict": "supported", "reason": "旧形式の評価",
             "evidence_assessment": "証拠あり", "logic_assessment": "論理は妥当",
             "confidence_assessment": "確度は適切"},
        ]
        plain = render.render_assessments({"claim_assessments": rows}).splitlines()
        assert plain[0] == "| ID | 主要結論 | 報告書上の確度 | 評価 | 評価理由 |"   # no 限界 column
        assert plain[2].endswith("| 新形式の評価 |")
        assert all(t in plain[3] for t in
                   ("旧形式の評価", "根拠: 証拠あり", "論理: 論理は妥当", "確度: 確度は適切"))
        rows[1]["limitations"] = ["ログ不足"]
        table = render.render_assessments({"claim_assessments": rows}).splitlines()
        assert table[0] == "| ID | 主要結論 | 報告書上の確度 | 評価 | 評価理由 | 限界 |"
        assert table[2].endswith("| 新形式の評価 | - |")
        assert table[3].endswith("| ログ不足 |")

    def test_limitations_must_be_a_list_or_string(self, tmp_path):
        payload = self._minimal()
        payload["claim_assessments"][0]["limitations"] = {"x": 1}
        path = tmp_path / "a.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        proc = run(ASSESS, "--assessments", str(path))
        assert proc.returncode == 1 and "limitations must be a list" in proc.stdout


class TestObservationCarryOver:
    """SubAgent information must reach the final files by construction, not by
    a gate the Agent learns to satisfy: skeletons derive what is mechanical,
    merge repairs bad span ids, and observed spans are pre-filled."""

    def _dir(self, tmp_path):
        d = TestReviewStatus()._built_pipeline(tmp_path)
        source = json.loads((d / "source_index.json").read_text(encoding="utf-8"))
        spans = [x["source_span_id"] for x in source["spans"]]
        return d, spans

    @staticmethod
    def _write_merged(d, **lists):
        merged = {"checklist_observations": [], "conclusion_observations": [],
                  "issue_observations": [], "open_questions": [], **lists}
        (d / "merged_observations.json").write_text(
            json.dumps(merged, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def _conclusion(oid, topic, spans, text="UNS40-76でスケジュールタスクによる永続化が確認された",
                    conf="confirmed"):
        return {"observation_id": oid, "topic": topic, "stated_conclusion": text,
                "source_span_ids": spans, "confidence_language": conf}

    def _fill(self, data):
        """Replace every 【要記入】 the way an Agent's judgment would."""
        fixed = {"review_verdict": "supported", "consistency_verdict": "consistent"}

        def walk(node, key=None):
            if isinstance(node, dict):
                is_rec = "recommendation_id" in node
                for k, v in node.items():
                    if v == "【要記入】":
                        node[k] = ("mapped" if is_rec else fixed[k]) if k in fixed else "評価済み"
                    else:
                        walk(v, k)
            elif isinstance(node, list):
                for x in node:
                    walk(x)
        walk(data)
        return data

    def test_claims_skeleton_has_one_row_per_topic_and_never_drops_observed_topics(self, tmp_path):
        d, spans = self._dir(tmp_path)
        self._write_merged(d, conclusion_observations=[
            self._conclusion("O1", "persistence", [spans[0]], conf="confirmed"),
            self._conclusion("O2", "persistence", [spans[1], "SPN-nonexistent"],
                             text="FRPによる持続的アクセスが確認された", conf="possible"),
            self._conclusion("O3", "recommendations", [spans[2]],
                             text="MFA導入とパッチ適用サイクルの確立を推奨している"),
        ])
        proc = run(CLAIMS_SKELETON, "--review-dir", str(d))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        data = json.loads((d / "claim_assessments.json").read_text(encoding="utf-8"))
        inv = {r["topic"]: r for r in data["conclusion_inventory"]}
        assert len(data["conclusion_inventory"]) == 9 and len(inv) == 9   # once each
        assert inv["persistence"]["presence"] == "reported"      # observed -> never not_reported
        assert set(inv["persistence"]["source_span_ids"]) == {spans[0], spans[1]}   # bad id gone
        assert inv["persistence"]["source_observation_ids"] == ["O1", "O2"]
        assert inv["c2_external"]["presence"] == "not_reported"
        assert inv["c2_external"]["absence_check_ids"] == ["ABS-CON-c2_external"]
        asm = {a["topic"]: a for a in data["claim_assessments"]}
        assert set(asm) == {"persistence", "recommendations"}
        assert inv["persistence"]["assessment_ids"] == [asm["persistence"]["assessment_id"]]
        assert asm["persistence"]["stated_confidence"] == "possible"   # weakest wording wins
        assert asm["persistence"]["review_verdict"] == "【要記入】"       # judgment is not automated
        assert data["recommendation_assessments"][0]["linked_finding_ids"] == [
            asm["persistence"]["assessment_id"]]
        assert "auto_filled" in inv["persistence"]

    def test_claims_skeleton_blocks_until_judged_then_passes(self, tmp_path):
        d, spans = self._dir(tmp_path)
        self._write_merged(d, conclusion_observations=[
            self._conclusion("O1", "persistence", [spans[0]]),
            self._conclusion("O2", "scope", [spans[1]], text="侵害範囲はUNS40-76とANS10031である"),
        ])
        assert run(CLAIMS_SKELETON, "--review-dir", str(d)).returncode == 0
        args = ("--assessments", str(d / "claim_assessments.json"),
                "--source-index", str(d / "source_index.json"),
                "--merged-observations", str(d / "merged_observations.json"))
        blocked = run(ASSESS, *args)
        assert blocked.returncode == 1 and "【要記入】" in blocked.stdout
        data = self._fill(json.loads((d / "claim_assessments.json").read_text(encoding="utf-8")))
        (d / "claim_assessments.json").write_text(json.dumps(data, ensure_ascii=False),
                                                  encoding="utf-8")
        assert run(ASSESS, *args).returncode == 0

    def test_observed_topic_cannot_be_flipped_to_not_reported_without_a_reason(self, tmp_path):
        d, spans = self._dir(tmp_path)
        self._write_merged(d, conclusion_observations=[
            self._conclusion("O1", "persistence", [spans[0]]),
            self._conclusion("O2", "scope", [spans[1]], text="侵害範囲はUNS40-76である"),
        ])
        assert run(CLAIMS_SKELETON, "--review-dir", str(d)).returncode == 0
        data = self._fill(json.loads((d / "claim_assessments.json").read_text(encoding="utf-8")))
        row = next(r for r in data["conclusion_inventory"] if r["topic"] == "persistence")
        row.update(presence="not_reported", assessment_ids=[], source_span_ids=[],
                   absence_check_ids=["ABS-CON-persistence"])
        data["claim_assessments"] = [a for a in data["claim_assessments"]
                                     if a["topic"] != "persistence"]
        path = d / "claim_assessments.json"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        args = ("--assessments", str(path), "--source-index", str(d / "source_index.json"),
                "--merged-observations", str(d / "merged_observations.json"))
        bad = run(ASSESS, *args)
        assert bad.returncode == 1 and "override_reason" in bad.stdout
        row["override_reason"] = "観測 O1 は別文書の記述で、本報告書の結論ではない"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        assert run(ASSESS, *args).returncode == 0

    def test_a_topic_may_not_appear_twice_in_the_inventory(self, tmp_path):
        payload = TestClaimAssessments()._valid_payload()
        dup = dict(payload["conclusion_inventory"][-1])
        dup.update(conclusion_id="CON-099", presence="not_reported",
                   absence_check_ids=["ABS-CON-recommendations"], stated_conclusion="")
        payload["conclusion_inventory"].append(dup)
        path = tmp_path / "a.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        proc = run(ASSESS, "--assessments", str(path))
        assert proc.returncode == 1 and "appears in 2 rows" in proc.stdout

    def test_merge_repairs_or_drops_invalid_span_ids_and_records_it(self, tmp_path):
        d, spans = self._dir(tmp_path)
        manifest = json.loads((d / "subagent_tasks" / "task_manifest.json").read_text(encoding="utf-8"))
        task = manifest["tasks"][0]
        core = json.loads(Path(task["task_path"]).read_text(encoding="utf-8"))["chunk"]["core_span_ids"]
        typo = "SPN, " + core[0].removeprefix("SPN-")   # the real-world mistake
        obs = {
            "schema_version": "1.0", "chunk_id": task["chunk_id"], "review_mode": "customer",
            "covered_span_ids": core,
            "checklist_observations": [{
                "observation_id": "OBS-1", "checklist_id": "CUS-2-9", "candidate_verdict": "met",
                "rationale": "t", "source_span_ids": [typo, "SPN-bogus"],
                "absence_check_ids": [], "confidence": 0.9}],
            "conclusion_observations": [], "issue_observations": [], "open_questions": [],
        }
        out = Path(task["observation_output_path"])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(obs, ensure_ascii=False), encoding="utf-8")
        original = out.read_text(encoding="utf-8")
        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        merged = json.loads((d / "merged_observations.json").read_text(encoding="utf-8"))
        assert merged["checklist_observations"][0]["source_span_ids"] == [core[0]]
        ledger = json.loads((d / "coverage_ledger.json").read_text(encoding="utf-8"))
        changes = {c["original"]: c["repaired_to"] for c in ledger["sanitized_span_ids"]}
        assert changes == {typo: core[0], "SPN-bogus": None}
        assert out.read_text(encoding="utf-8") == original      # SubAgent file untouched
        assert "Traceback" not in proc.stdout + proc.stderr

    def test_prefill_puts_observed_spans_only_on_unjudged_empty_rows(self, tmp_path):
        d, spans = self._dir(tmp_path)
        results = json.loads((d / "results.json").read_text(encoding="utf-8"))
        rows = results["results"]
        rows[1]["verdict"] = "partial"                       # already judged
        rows[2]["source_span_ids"] = [spans[3]]              # Agent already chose spans
        (d / "results.json").write_text(json.dumps(results, ensure_ascii=False), encoding="utf-8")
        ids = [r["checklist_id"] for r in rows[:4]]
        self._write_merged(d, checklist_observations=[
            {"observation_id": f"O{i}", "checklist_id": cid, "candidate_verdict": "not_met",
             "rationale": "r", "source_span_ids": [spans[0], "SPN-bogus"]}
            for i, cid in enumerate(ids)
        ])
        proc = run(PREFILL_SPANS, "--review-dir", str(d))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        after = {r["checklist_id"]: r for r in json.loads(
            (d / "results.json").read_text(encoding="utf-8"))["results"]}
        assert after[ids[0]]["source_span_ids"] == [spans[0]]   # unjudged: prefilled, bogus skipped
        assert after[ids[0]]["verdict"] is None                 # never a verdict
        assert after[ids[1]]["source_span_ids"] == []           # judged row untouched
        assert after[ids[2]]["source_span_ids"] == [spans[3]]   # Agent's choice untouched

    def test_status_warns_when_claims_or_issues_were_written_by_hand(self, tmp_path):
        d, rows, _ = TestSuggestionsAndIssuesSkeleton()._skeleton_dir(tmp_path)
        assert run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer").returncode == 1
        # skeleton-derived files: no warning
        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert "雛形（auto_filled 付き）から作られて" not in proc.stdout
        # the Agent replaces one with a from-scratch file
        data = json.loads((d / "claim_assessments.json").read_text(encoding="utf-8"))
        for row in data["conclusion_inventory"] + data["claim_assessments"]:
            row.pop("auto_filled", None)
        for key in ("consistency_assessments", "recommendation_assessments"):
            for row in data.get(key, []):
                row.pop("auto_filled", None)
        (d / "claim_assessments.json").write_text(json.dumps(data, ensure_ascii=False),
                                                  encoding="utf-8")
        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert "警告: claim_assessments.json は雛形" in proc.stdout
        events = [json.loads(line) for line in
                  (d / "run_log.jsonl").read_text(encoding="utf-8").splitlines()]
        assert any(e["event"] == "handwritten_files" for e in events)

    def test_open_question_without_related_item_is_reported_not_lost(self, tmp_path):
        d, spans = self._dir(tmp_path)
        results = json.loads((d / "results.json").read_text(encoding="utf-8"))
        for r in results["results"]:
            r.update(verdict="met", rationale="ok")
        (d / "results.json").write_text(json.dumps(results, ensure_ascii=False), encoding="utf-8")
        self._write_merged(d, open_questions=[{
            "question_id": "Q-9", "question": "?", "reason": "r", "source_span_ids": [spans[0]],
        }])
        proc = run(ISSUES_SKELETON, "--review-dir", str(d))
        assert proc.returncode == 0
        assert "Q-9" in proc.stdout and "no related checklist id" in proc.stdout


class TestReviewStatusIsTheOnlyEntryPoint:
    """A stuck Agent must not be able to route around review_status.py."""

    INTERNAL = [
        "merge_subagent_observations", "aggregate_observations", "prefill_result_spans",
        "init_issues_skeleton", "init_claims_skeleton", "check_coverage",
        "check_claim_assessments", "check_absence_grounding", "check_issues",
        "check_review_doc", "check_review_run", "render_review", "render_review_html",
        "make_repair_instructions", "link_assessment_issues",
    ]

    @pytest.mark.parametrize("name", INTERNAL)
    def test_internal_scripts_refuse_direct_execution(self, name):
        script = SKILLS / "ir-review-report" / "scripts" / f"{name}.py"
        proc = run(script, direct=True)
        assert proc.returncode == 2, name
        assert "review_status.py" in proc.stderr and "単独では実行しません" in proc.stderr
        assert "Traceback" not in proc.stderr

    def test_agent_facing_scripts_still_run_directly(self, tmp_path):
        proc = run(APPLY_SUGGESTED, "--review-dir", str(tmp_path), "--all-auto", direct=True)
        assert "単独では実行しません" not in proc.stderr   # fails for its own reasons only

    def test_review_status_itself_needs_no_permission(self, tmp_path):
        proc = run(REVIEW_STATUS, "--review-dir", str(tmp_path), direct=True)
        assert "単独では実行しません" not in proc.stderr

    def test_agent_facing_docs_do_not_advertise_internal_scripts(self):
        docs = [
            SKILLS / "ir-review-report" / "references" / "scripts_index.md",
            SKILLS / "ir-review-report" / "SKILL.md",
            SKILLS / "ir-review-report-customer" / "SKILL.md",
            SKILLS / "ir-review-report-reporter" / "SKILL.md",
            SKILLS / "ir-review-report" / "references" / "json_contracts.md",
            SKILLS / "ir-review-report" / "references" / "review_model.md",
        ]
        for doc in docs:
            text = doc.read_text(encoding="utf-8")
            leaked = [n for n in self.INTERNAL if f"{n}.py" in text]
            assert not leaked, f"{doc.name} names internal scripts: {leaked}"


class TestStatusIsIndependentOfCwd:
    def test_finished_subagent_work_is_found_from_any_directory(self, tmp_path):
        """Regression test for a real incident: the manifest stored paths relative
        to where the tasks were created, and running review_status.py from another
        directory reported all 6 finished chunks as "unprocessed" — the Agent then
        rewrote the manifest, forged log lines and ran gates by hand."""
        d = TestReviewStatus()._built_pipeline(tmp_path)
        manifest_path = d / "subagent_tasks" / "task_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for task in manifest["tasks"]:
            core = json.loads(Path(task["task_path"]).read_text(encoding="utf-8"))[
                "chunk"]["core_span_ids"]
            obs = {
                "schema_version": "1.0", "chunk_id": task["chunk_id"], "review_mode": "customer",
                "covered_span_ids": core,
                "checklist_observations": [{
                    "observation_id": f"O-{task['chunk_id']}", "checklist_id": "CUS-2-9",
                    "candidate_verdict": "met", "rationale": "t", "source_span_ids": [core[0]],
                    "absence_check_ids": [], "confidence": 0.9}],
                "conclusion_observations": [], "issue_observations": [], "open_questions": [],
            }
            out = d / "subagent_observations" / f"{task['chunk_id']}.json"
            out.parent.mkdir(exist_ok=True)
            out.write_text(json.dumps(obs, ensure_ascii=False), encoding="utf-8")
            # a manifest path that only resolves from one particular directory
            task["observation_output_path"] = f"subagent_observations/{task['chunk_id']}.json"
            task["task_path"] = f"elsewhere/{task['chunk_id']}.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        elsewhere = tmp_path / "unrelated"
        elsewhere.mkdir()
        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer", cwd=elsewhere)
        assert "未処理" not in proc.stdout, proc.stdout
        assert (d / "merged_observations.json").exists()

    def test_pending_chunks_are_listed_with_absolute_task_paths(self, tmp_path):
        d = TestReviewStatus()._built_pipeline(tmp_path)
        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer", cwd=tmp_path)
        manifest = json.loads(
            (d / "subagent_tasks" / "task_manifest.json").read_text(encoding="utf-8"))
        for task in manifest["tasks"]:
            assert str((d.resolve() / "subagent_tasks" / f"{task['chunk_id']}.json")) in proc.stdout
            assert Path(task["task_path"]).is_absolute()
            assert Path(task["observation_output_path"]).is_absolute()

    def test_missing_review_dir_message_names_the_current_directory(self, tmp_path):
        proc = run(REVIEW_STATUS, "--review-dir", "no/such/dir", cwd=tmp_path)
        assert proc.returncode == 2 and str(tmp_path.resolve()) in proc.stderr


class TestJudgmentDigest:
    def _digest(self, tmp_path, observations, rows):
        (tmp_path / "source_index.json").write_text(json.dumps({"spans": [
            {"source_span_id": "SPN-1", "text": "VPN認証ログの抜粋がある段落"}]}), encoding="utf-8")
        ws = {"checklist_items": [
            {"checklist_id": cid, "item": item, "level": "必須", "unknown_allowed": ua,
             "observation_count": len(obs), "conflicting": len({o["candidate_verdict"] for o in obs}) > 1,
             "candidate_verdict_counts": dict(collections.Counter(o["candidate_verdict"] for o in obs)),
             "observations": obs}
            for cid, item, ua, obs in rows]}
        scripts = str(SKILLS / "ir-review-report" / "scripts")
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        import review_status
        spans = {"SPN-1": "VPN認証ログの抜粋がある段落"}
        return review_status._judgment_digest(ws, [r[0] for r in rows], spans)

    def test_digest_shows_what_is_needed_to_judge_without_opening_the_worksheet(self, tmp_path):
        obs = [
            {"chunk_id": "CHK-001", "candidate_verdict": "met", "rationale": "連絡先あり",
             "source_span_ids": ["SPN-1"]},
            {"chunk_id": "CHK-002", "candidate_verdict": "partial", "rationale": "一部のみ",
             "source_span_ids": []},
        ]
        text = self._digest(tmp_path, obs, [
            ("CUS-1-1", "連絡先が記載されている", False, obs),
            ("CUS-1-2", "合意の記録", True, []),
        ])
        assert "■ CUS-1-1 [必須]" in text and "met×1 partial×1  ※食い違い" in text
        assert "CHK-001 met: 連絡先あり" in text and "SPN-1「VPN認証ログの抜粋がある段落」" in text
        assert "■ CUS-1-2 [必須/unknown可]" in text and "観測0件" in text

    def test_review_status_prints_the_digest_and_forbids_viewer_scripts(self, tmp_path):
        d = TestReviewStatus()._built_pipeline(tmp_path)
        manifest = json.loads((d / "subagent_tasks" / "task_manifest.json").read_text(encoding="utf-8"))
        for task in manifest["tasks"]:
            core = json.loads(Path(task["task_path"]).read_text(encoding="utf-8"))["chunk"]["core_span_ids"]
            obs = {"schema_version": "1.0", "chunk_id": task["chunk_id"], "review_mode": "customer",
                   "covered_span_ids": core,
                   "checklist_observations": [{
                       "observation_id": f"O-{task['chunk_id']}", "checklist_id": "CUS-2-9",
                       "candidate_verdict": "partial", "rationale": "観測の根拠テキスト",
                       "source_span_ids": [core[0]], "absence_check_ids": [], "confidence": 0.9},
                       {"observation_id": f"P-{task['chunk_id']}", "checklist_id": "CUS-2-9",
                        "candidate_verdict": "met", "rationale": "別の観測", "source_span_ids": [core[0]],
                        "absence_check_ids": [], "confidence": 0.9}],
                   "conclusion_observations": [], "issue_observations": [], "open_questions": []}
            out = d / "subagent_observations" / f"{task['chunk_id']}.json"
            out.parent.mkdir(exist_ok=True)
            out.write_text(json.dumps(obs, ensure_ascii=False), encoding="utf-8")
        proc = run(REVIEW_STATUS, "--review-dir", str(d), "--mode", "customer")
        assert "■ CUS-2-9" in proc.stdout and "観測の根拠テキスト" in proc.stdout
        assert "表示・集計用のスクリプトを書いたりしません" in proc.stdout


LINK_ISSUES = SKILLS / "ir-review-report" / "scripts" / "link_assessment_issues.py"


class TestAssessmentIssueLinking:
    """Weak assessments get a real issue of their own; issue_ids cannot lie."""

    def _dir(self, tmp_path, verdicts):
        d = TestReviewStatus()._built_pipeline(tmp_path)
        source = json.loads((d / "source_index.json").read_text(encoding="utf-8"))
        span = source["spans"][0]["source_span_id"]
        claims = TestClaimAssessments()._valid_payload()
        claims["claim_assessments"][0].update(
            review_verdict=verdicts["asm"], source_span_ids=[span], reason="根拠が限定的である",
            issue_ids=["OBS-CHK-001-002"])            # the real-world mistake
        claims["consistency_assessments"][0].update(consistency_verdict=verdicts["cns"])
        claims["recommendation_assessments"] = [{
            "recommendation_id": "REC-001", "recommendation": "MFAを導入する",
            "linked_finding_ids": ["ASM-001"], "review_verdict": verdicts["rec"],
            "reason": "所見との対応が不明", "source_span_ids": [span], "issue_ids": []}]
        (d / "claim_assessments.json").write_text(json.dumps(claims, ensure_ascii=False), encoding="utf-8")
        (d / "issues.json").write_text(json.dumps({"issues": [{
            "category": "missing_required_item", "severity": "medium", "checklist_ids": ["CUS-1-1"],
            "reason": "r", "suggested_revision": "s", "source_span_ids": [span]}]}), encoding="utf-8")
        return d

    def _link(self, d):
        proc = run(LINK_ISSUES, "--review-dir", str(d))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return (json.loads((d / "claim_assessments.json").read_text(encoding="utf-8")),
                json.loads((d / "issues.json").read_text(encoding="utf-8"))["issues"], proc.stdout)

    def test_each_weak_assessment_gets_its_own_issue_and_bogus_ids_are_dropped(self, tmp_path):
        d = self._dir(tmp_path, {"asm": "partially_supported", "cns": "minor_inconsistency",
                                 "rec": "not_mapped"})
        claims, issues, out = self._link(d)
        assert all(i.get("issue_id") for i in issues)                  # ids assigned
        asm = claims["claim_assessments"][0]
        own = [i for i in issues if "ASM-001" in (i.get("assessment_ids") or [])]
        assert len(own) == 1 and own[0]["category"] == "unsupported_claim"
        assert own[0]["severity"] == "medium" and own[0]["reason"] == "根拠が限定的である"
        assert own[0]["auto_for"] == "ASM-001"
        assert asm["issue_ids"] == [own[0]["issue_id"]]                 # OBS id is gone
        assert "OBS-CHK-001-002" in out
        cns = [i for i in issues if "CNS-001" in (i.get("assessment_ids") or [])]
        assert cns and cns[0]["category"] == "cross_section_inconsistency"
        rec = [i for i in issues if "REC-001" in (i.get("recommendation_ids") or [])]
        assert rec and rec[0]["category"] == "countermeasure_mapping" and rec[0]["severity"] == "high"
        assert claims["recommendation_assessments"][0]["issue_ids"] == [rec[0]["issue_id"]]

    def test_linking_is_idempotent_and_keeps_the_agents_own_issue_links(self, tmp_path):
        d = self._dir(tmp_path, {"asm": "unsupported", "cns": "consistent", "rec": "mapped"})
        claims, issues, _ = self._link(d)
        first = json.loads(json.dumps(issues))
        claims["claim_assessments"][0]["issue_ids"].append(issues[0]["issue_id"])  # a real issue
        (d / "claim_assessments.json").write_text(json.dumps(claims), encoding="utf-8")
        claims2, issues2, out2 = self._link(d)
        assert len(issues2) == len(first)                                # nothing duplicated
        assert issues[0]["issue_id"] in claims2["claim_assessments"][0]["issue_ids"]
        assert "created 0" in out2

    def test_auto_issue_disappears_when_the_assessment_becomes_supported(self, tmp_path):
        d = self._dir(tmp_path, {"asm": "unsupported", "cns": "consistent", "rec": "mapped"})
        claims, issues, _ = self._link(d)
        assert any(i.get("auto_for") == "ASM-001" for i in issues)
        claims["claim_assessments"][0]["review_verdict"] = "supported"
        (d / "claim_assessments.json").write_text(json.dumps(claims), encoding="utf-8")
        claims2, issues2, _ = self._link(d)
        assert not any(i.get("auto_for") for i in issues2)
        assert claims2["claim_assessments"][0]["issue_ids"] == []

    def test_checker_rejects_issue_ids_that_are_not_issues(self, tmp_path):
        d = self._dir(tmp_path, {"asm": "partially_supported", "cns": "consistent", "rec": "mapped"})
        args = ("--assessments", str(d / "claim_assessments.json"),
                "--issues", str(d / "issues.json"))
        bad = run(ASSESS, *args)
        assert bad.returncode == 1 and "OBS-CHK-001-002" in bad.stdout
        self._link(d)
        assert run(ASSESS, *args).returncode == 0


class TestPreEngagementUnknownSuggestion:
    def test_zero_observation_pre_engagement_items_get_an_unknown_suggestion(self, tmp_path):
        helper = TestSuggestionsAndIssuesSkeleton()
        rows = [
            {**helper._row("CUS-1-1", None), "unknown_allowed": True,
             "applies_to": "pre_engagement", "item": "調査目的と報告書の利用目的"},
            {**helper._row("CUS-2-3", None), "unknown_allowed": True,
             "applies_to": "investigation_process", "item": "調査手法"},
            {**helper._row("CUS-2-1", None), "unknown_allowed": True,
             "applies_to": "pre_engagement", "item": "条件付き［依頼している場合］の項目"},
        ]
        ws = helper._worksheet(tmp_path, [], rows)
        sug = ws["CUS-1-1"]["suggestion"]
        assert sug["verdict"] == "unknown" and sug["auto_applicable"] is True
        assert sug["unknown_reason"] == "external_information_missing"
        assert "調査目的と報告書の利用目的" in sug["external_confirmation_needed"]
        assert sug["rationale"]                                   # never an empty rationale
        assert ws["CUS-2-3"]["suggestion"] is None                # other items stay the Agent's call
        assert ws["CUS-2-1"]["suggestion"] is None                # conditional: maybe not applicable
        assert run(APPLY_SUGGESTED, "--review-dir", str(tmp_path), "--all-auto").returncode == 0
        after = {r["checklist_id"]: r for r in json.loads(
            (tmp_path / "results.json").read_text(encoding="utf-8"))["results"]}
        row = after["CUS-1-1"]
        assert row["verdict"] == "unknown" and row["unknown_reason"] == "external_information_missing"
        assert row["external_confirmation_needed"] and row["rationale"]
        assert after["CUS-2-3"]["verdict"] is None


class TestPdfBreakRejoinGuards:
    """Section numbers after a line break must not merge into evidence IDs."""

    EIDS_SCRIPT = SKILLS / "ir-review-report" / "scripts" / "check_evidence_ids.py"

    def test_section_number_not_joined(self, tmp_path):
        report = tmp_path / "r.md"
        report.write_text(
            "## 証拠一覧\n\n| 証拠ID | ファイル |\n|---|---|\n| E-101 | a.log |\n"
            "| E-110 | b.log |\n\n"
            "## 結果\n\n根拠は E-101\n3.2 認証情報取得の節を参照。\n"
            "また E-110\n3.7 の節も参照。\n",
            encoding="utf-8",
        )
        proc = run(self.EIDS_SCRIPT, "--report", str(report))
        out = json.loads(proc.stdout)
        undefined = [p["id"] for p in out["problems"]["undefined_references"]]
        assert "E-1013" not in undefined and "E-1103" not in undefined
        assert proc.returncode == 0, proc.stdout

    def test_genuine_split_id_still_joined(self, tmp_path):
        report = tmp_path / "r.md"
        report.write_text(
            "## 証拠一覧\n\n| 証拠ID | ファイル |\n|---|---|\n| E-109 | a.log |\n\n"
            "## 結果\n\n根拠は E-1\n09 のログです。\n",
            encoding="utf-8",
        )
        out = json.loads(run(self.EIDS_SCRIPT, "--report", str(report)).stdout)
        assert "E-109" not in [
            p["id"] for p in out["problems"]["undefined_references"]]
        assert "E-109" not in out["info"]["unreferenced_defined"]

    def test_single_digit_split_continuation_joins(self, tmp_path):
        # pypdf splits table IDs as "E-10\n1" (single-digit continuation).
        report = tmp_path / "r.md"
        report.write_text(
            "## 証拠一覧\n\n| 証拠ID | ファイル |\n|---|---|\n| E-101 | a.log |\n\n"
            "## 結果\n\n根拠は E-10\n1 のログです。\n",
            encoding="utf-8",
        )
        out = json.loads(run(self.EIDS_SCRIPT, "--report", str(report)).stdout)
        undefined = [p["id"] for p in out["problems"]["undefined_references"]]
        assert "E-10" not in undefined and "E-101" not in undefined

    def test_pdf_style_evidence_list_without_pipes(self, tmp_path):
        # A 証拠ID column header opens a definition zone even without markdown
        # table pipes (pypdf output), and bare numbered headings are detected.
        report = tmp_path / "r.txt"
        report.write_text(
            "1.6 調査対象・提供データ\n"
            "証拠IDファイル名 対象 SHA-256\n"
            "E-101 vpn.log AD01 aaa\n"
            "E-102 fw.csv FS01 bbb\n"
            "3. 調査結果\n"
            "初期侵入は E-101 から確認。E-102 も参照。\n",
            encoding="utf-8",
        )
        out = json.loads(run(self.EIDS_SCRIPT, "--report", str(report)).stdout)
        assert set(out["defined_ids"]) >= {"E-101", "E-102"}
        assert not out["problems"]["undefined_references"]


# ---------------------------------------------------------------------------
# Draft skeleton + carry-over lint + hash-bound approval (ir-draft-report)
# ---------------------------------------------------------------------------

BUILD_MATERIAL = SKILLS / "ir-draft-report" / "scripts" / "build_case_material.py"
QUALITY_SUMMARY = SKILLS / "ir-review-quality" / "scripts" / "write_quality_summary.py"

_EV1 = "ev-uuid-1"
_EV2 = "ev-uuid-2"


def _jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                    encoding="utf-8")


@pytest.fixture()
def draft_case(tmp_path) -> Path:
    case = tmp_path / "case"
    (case / "data").mkdir(parents=True)
    (case / "reports").mkdir()
    (case / "manifest.yaml").write_text(
        'case_id: "case-x"\ncase_name: "Case X"\nhosts: ["vpn01", "AD01"]\n'
        'time_range:\n  start: "2025-05-10T00:00:00+09:00"\n'
        '  end: "2025-05-11T00:00:00+09:00"\nreport_timezone: "Asia/Tokyo"\n',
        encoding="utf-8",
    )
    _jsonl(case / "data" / "evidence_ledger.jsonl", [
        {"evidence_id": _EV1, "observed_fact": "VPN接続", "interpretation": "",
         "interpretation_confidence": "possible",
         "observed_event": {"host": "vpn01"},
         "source_refs": [{"source_path": "VPN/vpn.log", "source_lines": [2, 3],
                          "excerpt": "login user=a srcip=89[.]233[.]109[.]69\ntunnel-up"}]},
        {"evidence_id": _EV2, "observed_fact": "ログオン", "interpretation": "",
         "interpretation_confidence": "probable",
         "observed_event": {"host": "AD01"},
         "source_refs": [{"source_path": "AD01/sec.log", "source_lines": [5],
                          "excerpt": "EventID=4624 SourceNetworkAddress=10.8.14.23"}]},
    ])
    _jsonl(case / "data" / "claims.jsonl", [
        {"claim_id": "CLM-1", "review_status": "approved", "report_section": "3.1",
         "claim_text": "外部からVPN接続", "confidence_level": "possible",
         "supporting_evidence": [_EV1]},
    ])
    _jsonl(case / "data" / "timeline.jsonl", [
        {"evidence_id": _EV1, "event_time": "2025-05-09T17:14:08Z", "host": "vpn01",
         "interpretation_confidence": "possible"},
    ])
    _jsonl(case / "data" / "gaps.jsonl", [
        {"gap_id": "GAP-lim1", "disposition": "accepted_as_limitation",
         "description": "x", "recommended_action": "y", "severity": "minor"},
    ])
    proc = run(BUILD_MATERIAL, "--case-dir", str(case))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return case


def _fill(case: Path) -> Path:
    """Write every 【要記入】 marker the way an analyst would."""
    import re as _re

    draft = case / "reports" / "draft_report.md"
    text = _re.sub(r"【要記入[^】]*】", "所見を記載しました。", draft.read_text(encoding="utf-8"))
    text = text.replace(
        "### 3.1 初期侵入\n",
        "### 3.1 初期侵入\n\n外部IP 89[.]233[.]109[.]69 からのVPN接続が記録されました"
        "（証拠ID: EV-001）。接続元端末は特定できませんでした（不足事項ID: GAP-lim1）。\n",
    )
    draft.write_text(text, encoding="utf-8")
    return draft


def _fill_reviewer_sections(draft: Path) -> None:
    """The human's part: the reviewer sections approve-draft requires."""
    import re as _re

    from ir_agent.reporting.draft_lint import REVIEW_COMMENT_SECTIONS

    text = draft.read_text(encoding="utf-8")
    for heading in REVIEW_COMMENT_SECTIONS:
        text = _re.sub(rf"(?m)^{_re.escape(heading)}[ \t]*$",
                       heading + "\n\nレビュー担当者が記入した内容です。", text, count=1)
    draft.write_text(text, encoding="utf-8")


class TestDraftSkeleton:
    def test_skeleton_is_written_with_markers_and_verbatim_excerpts(self, draft_case):
        text = (draft_case / "reports" / "draft_report.md").read_text(encoding="utf-8")
        assert "【要記入: 3.1" in text and "CLM-1(possible)" in text
        # chapter 4 keeps the excerpt's line break (case_material used to collapse it)
        assert "srcip=89[.]233[.]109[.]69\ntunnel-up" in text
        assert "| 2025-05-10 02:14 (JST) | vpn01 |" in text
        material = json.loads(
            (draft_case / "reports" / "case_material.json").read_text(encoding="utf-8"))
        assert "\n" in material["evidence_ledger"][0]["source_refs"][0]["excerpt"]

    def test_existing_draft_is_never_overwritten(self, draft_case):
        draft = draft_case / "reports" / "draft_report.md"
        draft.write_text("mine", encoding="utf-8")
        proc = run(BUILD_MATERIAL, "--case-dir", str(draft_case))
        assert proc.returncode == 0 and "退避" in proc.stdout
        assert draft.read_text(encoding="utf-8") == "mine"

    def test_unwritten_markers_fail_lint(self, draft_case):
        proc = run(LINT, "--case-dir", str(draft_case))
        assert proc.returncode == 1 and "【要記入】" in proc.stdout

    def test_filled_draft_passes(self, draft_case):
        _fill(draft_case)
        proc = run(LINT, "--case-dir", str(draft_case))
        assert proc.returncode == 0, proc.stdout


class TestDraftCarryOverAndGrounding:
    @staticmethod
    def _lint_after(case: Path, old: str, new: str) -> str:
        draft = _fill(case)
        text = draft.read_text(encoding="utf-8")
        assert old in text
        draft.write_text(text.replace(old, new, 1), encoding="utf-8")
        proc = run(LINT, "--case-dir", str(case))
        assert proc.returncode == 1
        return proc.stdout

    def test_approved_claim_missing_from_its_section_fails(self, draft_case):
        out = self._lint_after(draft_case, "記録されました（証拠ID: EV-001）",
                               "記録されました")
        assert "CLM-1" in out

    def test_limitation_gap_not_mentioned_fails(self, draft_case):
        out = self._lint_after(draft_case, "（不足事項ID: GAP-lim1）", "")
        assert "GAP-lim1" in out

    def test_edited_chapter4_excerpt_fails(self, draft_case):
        out = self._lint_after(draft_case, "\ntunnel-up\n", "\ntunnel-up (edited)\n")
        assert "4章のログ抜粋" in out

    def test_ip_not_in_evidence_fails(self, draft_case):
        out = self._lint_after(draft_case, "外部IP 89[.]233[.]109[.]69",
                               "外部IP 45[.]77[.]1[.]9")
        assert "45.77.1.9" in out

    _SENTENCE = "外部IP 89[.]233[.]109[.]69 からのVPN接続が記録されました（証拠ID: EV-001）。"

    def _lint_with(self, case: Path, sentence: str) -> str:
        return self._lint_after(case, self._SENTENCE, self._SENTENCE + sentence)

    def test_skeleton_copy_is_written(self, draft_case):
        reports = draft_case / "reports"
        assert (reports / "draft_skeleton.md").read_text(encoding="utf-8") == \
            (reports / "draft_report.md").read_text(encoding="utf-8")

    def test_edited_skeleton_line_fails(self, draft_case):
        skeleton = (draft_case / "reports" / "draft_skeleton.md").read_text(encoding="utf-8")
        row = next(line for line in skeleton.splitlines()
                   if "| vpn01 |" in line and "【要記入" not in line)
        out = self._lint_after(draft_case, row, row.replace("| vpn01 |", "| vpn-01 |"))
        assert "雛形" in out

    def test_time_matching_cited_evidence_passes(self, draft_case):
        draft = _fill(draft_case)
        text = draft.read_text(encoding="utf-8")
        added = "接続は 2025-05-10 02:14 (JST) でした（証拠ID: EV-001）。"
        draft.write_text(text.replace(self._SENTENCE, self._SENTENCE + added), encoding="utf-8")
        proc = run(LINT, "--case-dir", str(draft_case))
        assert proc.returncode == 0, proc.stdout

    def test_time_not_in_cited_evidence_fails(self, draft_case):
        out = self._lint_with(draft_case,
                              "接続は 2025-05-10 03:30 (JST) でした（証拠ID: EV-001）。")
        assert "証拠の時刻" in out and "03:30" in out

    def test_time_without_zone_label_fails(self, draft_case):
        out = self._lint_with(draft_case, "接続は 2025-05-10 02:14 でした（証拠ID: EV-001）。")
        assert "(JST)" in out

    def test_file_name_not_in_evidence_fails(self, draft_case):
        out = self._lint_with(draft_case, "その後 evil.exe が実行されました（証拠ID: EV-001）。")
        assert "evil.exe" in out

    def test_negative_claim_against_public_ip_fails(self, draft_case):
        out = self._lint_with(draft_case, "外部への通信は確認できませんでした。")
        assert "外部通信なし" in out

    def test_assertion_on_possible_evidence_fails(self, draft_case):
        out = self._lint_with(draft_case, "攻撃者による侵入が確認されました（証拠ID: EV-001）。")
        assert "断定" in out

    def test_hedged_assertion_passes(self, draft_case):
        draft = _fill(draft_case)
        text = draft.read_text(encoding="utf-8")
        draft.write_text(text.replace(
            self._SENTENCE,
            self._SENTENCE + "攻撃者による侵入の可能性が確認されました（証拠ID: EV-001）。"),
            encoding="utf-8")
        proc = run(LINT, "--case-dir", str(draft_case))
        assert proc.returncode == 0, proc.stdout

    def test_case_scope_gap_must_appear_whatever_its_disposition(self, draft_case):
        path = draft_case / "reports" / "case_material.json"
        material = json.loads(path.read_text(encoding="utf-8"))
        material["gaps"].append({
            "gap_id": "GAP-scope1", "related_claim_id": "CASE-SCOPE",
            "disposition": "out_of_scope_with_analyst_approval",
            "description": "未抽出ファイル", "severity": "minor"})
        path.write_text(json.dumps(material, ensure_ascii=False), encoding="utf-8")
        _fill(draft_case)
        proc = run(LINT, "--case-dir", str(draft_case))
        assert proc.returncode == 1 and "GAP-scope1" in proc.stdout

    def test_stray_script_in_case_fails_and_scratch_is_allowed(self, draft_case):
        _fill(draft_case)
        (draft_case / "fix_timeline.py").write_text("pass\n", encoding="utf-8")
        proc = run(LINT, "--case-dir", str(draft_case))
        assert proc.returncode == 1 and "fix_timeline.py" in proc.stdout
        assert "_scratch" in proc.stdout

        (draft_case / "_scratch").mkdir()
        (draft_case / "fix_timeline.py").rename(draft_case / "_scratch" / "fix_timeline.py")
        proc = run(LINT, "--case-dir", str(draft_case))
        assert proc.returncode == 0, proc.stdout


class TestWorkspaceLayout:
    def test_scripts_inside_layout_dirs_are_stray_except_scratch_and_artifacts(self, tmp_path):
        from ir_agent.workflow.workspace import stray_case_entries

        for d in ("data", "reports", "artifacts", "_scratch"):
            (tmp_path / d).mkdir()
            (tmp_path / d / "x.py").write_text("", encoding="utf-8")
        (tmp_path / "notes.md").write_text("", encoding="utf-8")
        (tmp_path / ".DS_Store").write_text("", encoding="utf-8")
        assert stray_case_entries(tmp_path) == ["notes.md", "data/x.py", "reports/x.py"]

    def test_skill_directory_holds_only_its_layout(self):
        from ir_agent.workflow.workspace import _outside_skill_layout

        base = ".claude/skills/ir-extract-evidence/"
        for ok in ("SKILL.md", "scripts/new_check.py", "references/rules.md"):
            assert not _outside_skill_layout(base + ok)
        for stray in ("extract_all.py", "extractions_final.json", "tmp/x.json"):
            assert _outside_skill_layout(base + stray)
        assert not _outside_skill_layout("ir_agent/x.py")


class TestCheckDraftCommand:
    @pytest.fixture()
    def cli_case(self, draft_case) -> Path:
        state = {
            "case_id": "case-x", "current_phase": "report_plan_approved",
            "completed_phases": ["case_initialized", "report_plan_approved"],
            "stale_phases": [], "blocked_reasons": [],
            "last_updated_at": "2026-01-01T00:00:00+00:00", "last_updated_by": None,
        }
        (draft_case / "workflow_state.json").write_text(json.dumps(state), encoding="utf-8")
        return draft_case

    @staticmethod
    def _cli(case: Path, *args: str):
        from click.testing import CliRunner

        from ir_agent.cli.main import cli

        return CliRunner().invoke(cli, ["--case-dir", str(case), *args])

    @staticmethod
    def _phases(case: Path) -> list[str]:
        return json.loads((case / "workflow_state.json").read_text())["completed_phases"]

    def test_fail_does_not_register_the_draft(self, cli_case):
        result = self._cli(cli_case, "check-draft")
        assert result.exit_code == 1 and "【要記入】" in result.output
        assert "draft_report_generated" not in self._phases(cli_case)

    def test_status_warns_about_stray_case_files(self, cli_case):
        (cli_case / "fix_ioc.py").write_text("pass\n", encoding="utf-8")
        result = self._cli(cli_case, "status")
        assert "fix_ioc.py" in result.output and "_scratch" in result.output

    def test_approval_refused_while_reviewer_sections_are_empty(self, cli_case):
        draft = _fill(cli_case)
        assert self._cli(cli_case, "check-draft").exit_code == 0
        from ir_agent.reporting.draft_record import draft_sha256

        (cli_case / "reviews").mkdir(exist_ok=True)
        (cli_case / "reviews" / "quality_review_001.md").write_text(
            f"- 対象ドラフト SHA-256: {draft_sha256(draft)}\n", encoding="utf-8")
        result = self._cli(cli_case, "approve-draft", "--analyst-id", "tom")
        assert result.exit_code == 1 and "レビュー担当者記入欄" in result.output
        assert "draft_report_approved" not in self._phases(cli_case)

    def test_pass_registers_and_approval_is_bound_to_content(self, cli_case):
        draft = _fill(cli_case)
        _fill_reviewer_sections(draft)
        result = self._cli(cli_case, "check-draft")
        assert result.exit_code == 0, result.output
        assert "draft_report_generated" in self._phases(cli_case)

        # Edited after the check → approval refused until re-checked.
        draft.write_text(draft.read_text(encoding="utf-8") + "\n追記", encoding="utf-8")
        result = self._cli(cli_case, "approve-draft", "--analyst-id", "tom")
        assert result.exit_code == 1 and "check-draft" in result.output

        assert self._cli(cli_case, "check-draft").exit_code == 0
        result = self._cli(cli_case, "approve-draft", "--analyst-id", "tom")
        # No quality review for this exact draft yet → approval is refused.
        assert result.exit_code == 1 and "品質レビュー" in result.output
        assert "draft_report_approved" not in self._phases(cli_case)

        from ir_agent.reporting.draft_record import approval_problem, draft_sha256

        (cli_case / "reviews").mkdir(exist_ok=True)
        (cli_case / "reviews" / "quality_review_001.md").write_text(
            f"- 対象ドラフト SHA-256: {draft_sha256(draft)}\n", encoding="utf-8")
        result = self._cli(cli_case, "approve-draft", "--analyst-id", "tom")
        assert result.exit_code == 0, result.output

        reports = cli_case / "reports"
        assert approval_problem(reports, draft_sha256(draft)) is None
        draft.write_text(draft.read_text(encoding="utf-8") + "\n承認後の変更", encoding="utf-8")
        assert "承認後" in approval_problem(reports, draft_sha256(draft))


class TestSkeletonIntegrity:
    def test_fresh_generation_passes(self, draft_case):
        from ir_agent.reporting.skeleton_integrity import integrity_problems

        assert integrity_problems(draft_case) == []

    def test_edited_skeleton_is_detected(self, draft_case):
        from ir_agent.reporting.skeleton_integrity import integrity_problems

        skeleton = draft_case / "reports" / "draft_skeleton.md"
        skeleton.write_text(skeleton.read_text(encoding="utf-8").replace(
            "2025-05-10 00:00", "2025-05-10 01:00"), encoding="utf-8")
        problems = integrity_problems(draft_case)
        assert len(problems) == 1 and "draft_skeleton.md" in problems[0]

    def test_edited_material_is_detected(self, draft_case):
        from ir_agent.reporting.skeleton_integrity import integrity_problems

        path = draft_case / "reports" / "case_material.json"
        material = json.loads(path.read_text(encoding="utf-8"))
        material["case"]["case_name"] = "別名"
        path.write_text(json.dumps(material, ensure_ascii=False), encoding="utf-8")
        problems = integrity_problems(draft_case)
        assert len(problems) == 1 and "case_material.json" in problems[0]

    def test_skeleton_fixed_text_is_already_defanged(self):
        from ir_agent.reporting.draft_lint import defang_text

        assert defang_text("接続先 203.0.113.88:22、内部 10.0.0.5") == \
            "接続先 203[.]0[.]113[.]88:22、内部 10.0.0.5"


class TestQualitySummaryExternalInput:
    def test_findings_only_the_human_can_resolve_are_separated(self):
        sys.path.insert(0, str(QUALITY_SUMMARY.parent))
        import write_quality_summary as w

        assert w.needs_external_input({"reason": "問い合わせ先の担当部署は提供資料から確認できない"})
        assert w.needs_external_input({"reason": "優先順位として合意された事項は明記されていない"})
        assert not w.needs_external_input({"reason": "robocopy.exe のハッシュ値が付録Aにない"})


class TestQualitySummaryRefusals:
    def test_review_of_another_file_is_refused(self, draft_case, tmp_path):
        review = tmp_path / "review"
        review.mkdir()
        (review / "run_manifest.json").write_text(
            json.dumps({"review_mode": "reporter", "report_path": str(tmp_path / "other.md")}))
        proc = run(QUALITY_SUMMARY, "--case-dir", str(draft_case), "--review-dir", str(review))
        assert proc.returncode == 2 and "対象" in proc.stdout
        assert not list((draft_case / "reviews").glob("quality_review_*.md")) \
            if (draft_case / "reviews").exists() else True

    def test_draft_changed_after_review_is_refused(self, draft_case, tmp_path):
        review = tmp_path / "review"
        review.mkdir()
        draft = draft_case / "reports" / "draft_report.md"
        (review / "run_manifest.json").write_text(
            json.dumps({"review_mode": "reporter", "report_path": str(draft)}))
        (review / "normalized.txt").write_text("x")
        os.utime(review / "normalized.txt", (1, 1))
        proc = run(QUALITY_SUMMARY, "--case-dir", str(draft_case), "--review-dir", str(review))
        assert proc.returncode == 2 and "変更" in proc.stdout


class TestTemplateIsTheSingleSource:
    """Skeleton and lint both derive the report structure from the template."""

    def test_lint_headings_come_from_the_template(self):
        from ir_agent.reporting import draft_lint, report_template

        headings = report_template.required_headings()
        assert draft_lint.REQUIRED_HEADINGS == headings
        assert not any("補足" in h for h in headings)
        assert "### 1.1 調査にかかる経緯" in draft_lint.REVIEW_COMMENT_SECTIONS
        assert [s for s, _ in report_template.attack_sections()] == [
            f"3.{i}" for i in range(1, 8)]

    def test_skeleton_follows_template_order_and_fixed_text(self, draft_case):
        from ir_agent.reporting import report_template

        text = (draft_case / "reports" / "draft_report.md").read_text(encoding="utf-8")
        positions = [text.index(f"\n{h}\n") for h in report_template.required_headings()]
        assert positions == sorted(positions)
        for heading in report_template.reviewer_sections():
            assert report_template.body(heading) in text
        assert report_template.fixed_body("### 本報告書に関する留意事項") in text
        assert "### 4.3 侵害・侵害疑いのアカウント/ホスト一覧" in text  # 2 hosts → 4.3
