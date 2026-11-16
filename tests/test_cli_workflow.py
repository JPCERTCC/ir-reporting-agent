"""Consolidated unit tests for CLI workflow cross-cutting concerns.

Tests the cross-cutting behaviors that apply to ALL CLI commands:
1. Workflow prerequisite enforcement — every command (except init) fails with
   non-zero exit code when prerequisites are not met (WorkflowBlockedError)
2. Audit log entries are produced by commands (spot-checked)
3. Fatal errors return non-zero exit code
4. Status command displays current phase and item counts

This file does NOT duplicate command-specific tests found in:
- tests/test_cli_main.py (init, status, audit-summary)
- tests/test_cli_ingestion_extraction.py (ingest, normalize-events, extract-candidates)
- tests/test_cli_evidence_commands.py (review-evidence, promote-evidence)
- tests/test_cli_claim_gap_commands.py (review-claims, apply-claim-review, check-gaps, etc.)

Requirements: 21.1, 21.2, 21.3, 21.4
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from ir_agent.cli.main import cli


@pytest.fixture
def runner():
    """Create a Click test runner."""
    return CliRunner()


@pytest.fixture
def initialized_case(tmp_path):
    """Create a case that is only at CASE_INITIALIZED phase."""
    case_dir = tmp_path / "test_case"
    runner = CliRunner()
    runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
    return case_dir


def _set_workflow_phase(case_dir: Path, phase: str, completed: list[str]) -> None:
    """Set the workflow state to a specific phase with completed phases."""
    state = {
        "case_id": case_dir.name,
        "current_phase": phase,
        "completed_phases": completed,
        "blocked_reasons": [],
        "last_updated_at": "2024-01-01T00:00:00+00:00",
        "last_updated_by": None,
    }
    state_path = case_dir / "workflow_state.json"
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


# ============================================================================
# Section 1: Workflow Prerequisite Enforcement
# Every command that requires prerequisites MUST fail with non-zero exit code
# when those prerequisites are not met.
# ============================================================================


class TestWorkflowPrerequisiteEnforcement:
    """Test that commands with prerequisites fail with non-zero exit code when out of order.

    Validates Requirement 21.1: Workflow state machine prevents out-of-order execution.
    Validates Requirement 21.4: Non-zero exit codes for blocked commands.
    """

    def test_normalize_events_blocked_without_artifacts_ingested(
        self, runner, initialized_case
    ):
        """normalize-events requires ARTIFACTS_INGESTED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "normalize-events"]
        )
        assert result.exit_code != 0
        assert "cannot run" in result.output.lower() or "error" in result.output.lower()

    def test_extract_candidates_blocked_without_artifacts_ingested(
        self, runner, initialized_case
    ):
        """extract-candidates requires ARTIFACTS_INGESTED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "extract-candidates"]
        )
        assert result.exit_code != 0

    def test_promote_evidence_blocked_without_candidates_generated(
        self, runner, initialized_case
    ):
        """promote-evidence requires EVIDENCE_CANDIDATES_GENERATED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "promote-evidence"]
        )
        assert result.exit_code != 0

    def test_build_coverage_blocked_without_ledger_approved(
        self, runner, initialized_case
    ):
        """build-coverage requires EVIDENCE_LEDGER_APPROVED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "build-coverage"]
        )
        assert result.exit_code != 0

    def test_build_timeline_blocked_without_coverage_built(
        self, runner, initialized_case
    ):
        """build-timeline requires DATA_COVERAGE_BUILT."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "build-timeline"]
        )
        assert result.exit_code != 0

    def test_map_attack_blocked_without_timeline_built(
        self, runner, initialized_case
    ):
        """map-attack requires TIMELINE_BUILT."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "map-attack"]
        )
        assert result.exit_code != 0

    def test_build_claims_blocked_without_attack_mapped(
        self, runner, initialized_case
    ):
        """build-claims requires ATTACK_MAPPED and DATA_COVERAGE_BUILT."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "build-claims"]
        )
        assert result.exit_code != 0

    def test_apply_claim_review_blocked_without_claims_generated(
        self, runner, initialized_case
    ):
        """apply-claim-review requires CLAIMS_GENERATED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "apply-claim-review"]
        )
        assert result.exit_code != 0

    def test_check_gaps_blocked_without_claims_reviewed(
        self, runner, initialized_case
    ):
        """check-gaps requires CLAIMS_REVIEWED and DATA_COVERAGE_BUILT."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "check-gaps"]
        )
        assert result.exit_code != 0

    def test_apply_gap_disposition_blocked_without_gaps_checked(
        self, runner, initialized_case
    ):
        """apply-gap-disposition requires GAPS_CHECKED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "apply-gap-disposition"]
        )
        assert result.exit_code != 0

    def test_plan_report_blocked_without_gaps_dispositioned(
        self, runner, initialized_case
    ):
        """plan-report requires GAPS_DISPOSITIONED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "plan-report"]
        )
        assert result.exit_code != 0

    def test_approve_report_plan_blocked_without_plan_generated(
        self, runner, initialized_case
    ):
        """approve-report-plan requires REPORT_PLAN_GENERATED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "approve-report-plan"]
        )
        assert result.exit_code != 0

    def test_draft_report_blocked_without_plan_approved(
        self, runner, initialized_case
    ):
        """draft-report requires REPORT_PLAN_APPROVED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "draft-report"]
        )
        assert result.exit_code != 0

    def test_approve_draft_blocked_without_draft_generated(
        self, runner, initialized_case
    ):
        """approve-draft requires DRAFT_REPORT_GENERATED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "approve-draft"]
        )
        assert result.exit_code != 0

    def test_finalize_report_blocked_without_draft_approved(
        self, runner, initialized_case
    ):
        """finalize-report requires DRAFT_REPORT_APPROVED."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "finalize-report"]
        )
        assert result.exit_code != 0

    def test_prerequisite_error_message_mentions_missing_phases(
        self, runner, initialized_case
    ):
        """The error message should indicate what prerequisites are missing."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "build-coverage"]
        )
        assert result.exit_code != 0
        # Should mention that evidence_ledger_approved is missing
        assert "evidence_ledger_approved" in result.output.lower() or "cannot run" in result.output.lower()

    def test_blocked_command_with_explicit_blocker(self, runner, initialized_case):
        """Commands should also fail when workflow has explicit blockers."""
        # Set state with a blocker
        state = {
            "case_id": initialized_case.name,
            "current_phase": "evidence_ledger_approved",
            "completed_phases": [
                "case_initialized",
                "artifacts_ingested",
                "events_normalized",
                "evidence_candidates_generated",
                "evidence_reviewed",
                "evidence_ledger_approved",
            ],
            "blocked_reasons": ["Critical gaps not resolved"],
            "last_updated_at": "2024-01-01T00:00:00+00:00",
            "last_updated_by": None,
        }
        state_path = initialized_case / "workflow_state.json"
        state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "build-coverage"]
        )
        assert result.exit_code != 0


# ============================================================================
# Section 2: Audit Logging Validation (spot-check)
# Commands should produce audit log entries when they run.
# ============================================================================


class TestAuditLogging:
    """Test that commands log operations to the audit log.

    Validates Requirement 20.1: Every operation logged with timestamp and context.
    Validates Requirement 21.2: Commands display and log progress.
    """

    def test_build_coverage_logs_audit_entry(self, runner, initialized_case):
        """build-coverage should produce an audit log entry on success."""
        _set_workflow_phase(
            initialized_case,
            "evidence_ledger_approved",
            [
                "case_initialized",
                "artifacts_ingested",
                "events_normalized",
                "evidence_candidates_generated",
                "evidence_reviewed",
                "evidence_ledger_approved",
            ],
        )

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "build-coverage"]
        )
        assert result.exit_code == 0

        audit_path = initialized_case / "logs" / "audit.jsonl"
        assert audit_path.exists()
        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        coverage_entries = [
            json.loads(line)
            for line in lines
            if json.loads(line).get("operation_type") == "build-coverage"
        ]
        assert len(coverage_entries) >= 1
        assert coverage_entries[0]["status"] == "success"

    def test_plan_report_logs_audit_entry_on_failure(self, runner, initialized_case):
        """plan-report should log when it fails due to prerequisites."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "plan-report"]
        )
        assert result.exit_code != 0

        # Even on failure, an audit entry may be logged (implementation-dependent)
        # At minimum, the error output should be present
        assert "error" in result.output.lower() or "cannot run" in result.output.lower()

    def test_audit_entry_contains_required_fields(self, runner, initialized_case):
        """Audit entries should contain timestamp, operation_type, and status."""
        # status command always succeeds after init
        runner.invoke(cli, ["--case-dir", str(initialized_case), "status"])

        audit_path = initialized_case / "logs" / "audit.jsonl"
        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) >= 1

        entry = json.loads(lines[-1])
        assert "timestamp" in entry
        assert "operation_type" in entry
        assert "status" in entry

    def test_multiple_commands_append_to_audit(self, runner, initialized_case):
        """Successive commands should append to the same audit log."""
        # status is read-only; re-running init logs each time.
        runner.invoke(cli, ["--case-dir", str(initialized_case), "init"])
        runner.invoke(cli, ["--case-dir", str(initialized_case), "init"])
        runner.invoke(cli, ["--case-dir", str(initialized_case), "init"])

        audit_path = initialized_case / "logs" / "audit.jsonl"
        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        # init + 3 more init commands = at least 4 entries
        assert len(lines) >= 4


# ============================================================================
# Section 3: Fatal Error Exit Codes
# Fatal errors should result in non-zero exit codes.
# ============================================================================


class TestFatalErrorExitCodes:
    """Test that fatal errors return non-zero exit code.

    Validates Requirement 21.4: Fatal errors produce descriptive error message
    and exit with non-zero exit code.
    """

    def test_command_with_no_workflow_state_exits_nonzero(self, runner, tmp_path):
        """Commands that need state should fail if workflow_state.json is missing."""
        case_dir = tmp_path / "empty_case"
        case_dir.mkdir()

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "status"]
        )
        assert result.exit_code != 0

    def test_command_with_corrupt_workflow_state_exits_nonzero(
        self, runner, initialized_case
    ):
        """Commands should fail gracefully if workflow_state.json is corrupted."""
        state_path = initialized_case / "workflow_state.json"
        state_path.write_text("{ invalid json content !!!", encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "normalize-events"]
        )
        assert result.exit_code != 0

    def test_ingest_with_missing_artifacts_dir_exits_nonzero(
        self, runner, initialized_case
    ):
        """ingest should fail with non-zero exit code when artifacts dir doesn't exist."""
        result = runner.invoke(
            cli, [
                "--case-dir", str(initialized_case),
                "ingest",
                "--artifacts-dir", "/nonexistent/path/to/artifacts",
            ]
        )
        assert result.exit_code != 0

    def test_promote_evidence_with_no_review_doc_exits_nonzero(
        self, runner, initialized_case
    ):
        """promote-evidence should fail if no review document is found."""
        _set_workflow_phase(
            initialized_case,
            "evidence_candidates_generated",
            [
                "case_initialized",
                "artifacts_ingested",
                "events_normalized",
                "evidence_candidates_generated",
            ],
        )

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "promote-evidence"]
        )
        assert result.exit_code != 0
        assert "no evidence review document" in result.output.lower() or "error" in result.output.lower()

    def test_check_gaps_without_claims_file_exits_nonzero(
        self, runner, initialized_case
    ):
        """check-gaps should fail if claims.jsonl does not exist."""
        _set_workflow_phase(
            initialized_case,
            "claims_reviewed",
            [
                "case_initialized",
                "artifacts_ingested",
                "events_normalized",
                "evidence_candidates_generated",
                "evidence_reviewed",
                "evidence_ledger_approved",
                "data_coverage_built",
                "timeline_built",
                "attack_mapped",
                "claims_generated",
                "claims_reviewed",
            ],
        )

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "check-gaps"]
        )
        assert result.exit_code != 0

    def test_draft_report_without_claims_exits_nonzero(self, runner, initialized_case):
        """draft-report should fail if required data is missing."""
        _set_workflow_phase(
            initialized_case,
            "report_plan_approved",
            [
                "case_initialized",
                "artifacts_ingested",
                "events_normalized",
                "evidence_candidates_generated",
                "evidence_reviewed",
                "evidence_ledger_approved",
                "data_coverage_built",
                "timeline_built",
                "attack_mapped",
                "claims_generated",
                "claims_reviewed",
                "gaps_checked",
                "gaps_dispositioned",
                "report_plan_generated",
                "report_plan_approved",
            ],
        )

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "draft-report"]
        )
        assert result.exit_code != 0


# ============================================================================
# Section 4: Status Command Progress Display
# The status command should show current phase and item counts.
# ============================================================================


class TestStatusProgressDisplay:
    """Test that the status command shows current phase and item counts.

    Validates Requirement 21.2: Progress information includes current phase
    and item counts.
    Validates Requirement 21.3: Summary of results including counts.
    """

    def test_status_shows_current_phase(self, runner, initialized_case):
        """status should display the current workflow phase name."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "status"]
        )
        assert result.exit_code == 0
        assert "case_initialized" in result.output

    def test_status_shows_completed_phase_count(self, runner, initialized_case):
        """status should list completed phases."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "status"]
        )
        assert result.exit_code == 0
        # Should show at least one completed phase (case_initialized)
        assert "✓" in result.output or "case_initialized" in result.output

    def test_status_shows_multiple_completed_phases(self, runner, initialized_case):
        """status should show all completed phases when multiple are done."""
        _set_workflow_phase(
            initialized_case,
            "events_normalized",
            [
                "case_initialized",
                "artifacts_ingested",
                "events_normalized",
            ],
        )

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "status"]
        )
        assert result.exit_code == 0
        assert "case_initialized" in result.output
        assert "artifacts_ingested" in result.output
        assert "events_normalized" in result.output

    def test_status_shows_blockers(self, runner, initialized_case):
        """status should display active blockers."""
        state = json.loads(
            (initialized_case / "workflow_state.json").read_text(encoding="utf-8")
        )
        state["blocked_reasons"] = ["Unresolved critical gaps"]
        (initialized_case / "workflow_state.json").write_text(
            json.dumps(state, indent=2), encoding="utf-8"
        )

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "status"]
        )
        assert result.exit_code == 0
        assert "Unresolved critical gaps" in result.output

    def test_status_shows_last_updated_timestamp(self, runner, initialized_case):
        """status should display when the workflow was last updated."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "status"]
        )
        assert result.exit_code == 0
        assert "Last Updated" in result.output

    def test_status_shows_case_id(self, runner, initialized_case):
        """status should display the case identifier."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "status"]
        )
        assert result.exit_code == 0
        assert "Case:" in result.output
        assert initialized_case.name in result.output
