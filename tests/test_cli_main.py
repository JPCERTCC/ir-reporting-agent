"""Unit tests for CLI entry point and case management commands.

Tests the init, status, and audit-summary commands.
Requirements: 21.1, 21.2, 21.3, 21.4, 21.5
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from ir_agent.cli.main import MANIFEST_TEMPLATE, cli


@pytest.fixture
def runner():
    """Create a Click test runner."""
    return CliRunner()


@pytest.fixture
def case_dir(tmp_path):
    """Provide a temporary case directory path."""
    return tmp_path / "test_case"


class TestInitCommand:
    """Tests for the 'init' CLI command."""

    def test_init_creates_directory_structure(self, runner, case_dir):
        """Init should create all required subdirectories."""
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result.exit_code == 0

        expected_dirs = ["artifacts", "data", "reviews", "reports", "logs"]
        for subdir in expected_dirs:
            assert (case_dir / subdir).is_dir(), f"{subdir}/ not created"

    def test_init_creates_manifest_template(self, runner, case_dir):
        """Init should create manifest.yaml with required fields."""
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result.exit_code == 0

        manifest_path = case_dir / "manifest.yaml"
        assert manifest_path.is_file()

        content = manifest_path.read_text(encoding="utf-8")
        # Check for key fields
        assert "case_id:" in content
        assert "case_name:" in content
        assert "scope:" in content
        assert "hosts:" in content
        assert "time_range:" in content
        assert 'report_language: "ja"' in content
        assert 'review_language: "ja"' in content
        assert 'report_timezone: "UTC"' in content

    def test_init_creates_workflow_state(self, runner, case_dir):
        """Init should create workflow_state.json with CASE_INITIALIZED."""
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result.exit_code == 0

        state_path = case_dir / "workflow_state.json"
        assert state_path.is_file()

        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert state["case_id"] == "test_case"
        assert state["current_phase"] == "case_initialized"
        assert "case_initialized" in state["completed_phases"]

    def test_init_logs_operation(self, runner, case_dir):
        """Init should log an audit entry."""
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result.exit_code == 0

        audit_path = case_dir / "logs" / "audit.jsonl"
        assert audit_path.is_file()

        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) >= 1

        entry = json.loads(lines[0])
        assert entry["operation_type"] == "init"
        assert entry["status"] == "success"

    def test_init_does_not_overwrite_existing_manifest(self, runner, case_dir):
        """Init should not overwrite an existing manifest.yaml."""
        case_dir.mkdir(parents=True)
        manifest_path = case_dir / "manifest.yaml"
        manifest_path.write_text("custom: content\n", encoding="utf-8")

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result.exit_code == 0
        assert "already exists" in result.output

        # Verify content was not overwritten
        content = manifest_path.read_text(encoding="utf-8")
        assert content == "custom: content\n"

    def test_init_idempotent(self, runner, case_dir):
        """Running init twice should not fail or corrupt state."""
        result1 = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result1.exit_code == 0

        result2 = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result2.exit_code == 0

        # State should still be valid
        state_path = case_dir / "workflow_state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert state["current_phase"] == "case_initialized"
        # Should only have one entry in completed_phases
        assert state["completed_phases"].count("case_initialized") == 1


class TestStatusCommand:
    """Tests for the 'status' CLI command."""

    def test_status_displays_current_phase(self, runner, case_dir):
        """Status should display the current workflow phase."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        assert result.exit_code == 0
        assert "case_initialized" in result.output

    def test_status_displays_completed_phases(self, runner, case_dir):
        """Status should list completed phases."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        assert result.exit_code == 0
        assert "case_initialized" in result.output

    def test_status_displays_no_blockers(self, runner, case_dir):
        """Status should show no blockers when none exist."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        assert result.exit_code == 0
        assert "(none)" in result.output

    def test_status_shows_blockers_when_present(self, runner, case_dir):
        """Status should display blockers when they exist."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        # Manually add a blocker to the state
        state_path = case_dir / "workflow_state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["blocked_reasons"] = ["Critical gaps not resolved"]
        state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        assert result.exit_code == 0
        assert "Critical gaps not resolved" in result.output

    def test_status_fails_without_init(self, runner, case_dir):
        """Status should fail if no workflow state exists."""
        case_dir.mkdir(parents=True)

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        assert result.exit_code == 1
        assert "No workflow state found" in result.output

    def test_status_is_read_only(self, runner, case_dir):
        """Status must not write the audit log (it runs on finalized cases too)."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        audit_path = case_dir / "logs" / "audit.jsonl"
        before = audit_path.read_text(encoding="utf-8")

        runner.invoke(cli, ["--case-dir", str(case_dir), "status"])

        assert audit_path.read_text(encoding="utf-8") == before

    def test_status_warns_on_template_manifest(self, runner, case_dir):
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        (case_dir / "manifest.yaml").write_text(
            MANIFEST_TEMPLATE.format(case_id="c"), encoding="utf-8")
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        assert "manifest.yaml がテンプレートのままです" in result.output


class TestAuditSummaryCommand:
    """Tests for the 'audit-summary' CLI command."""

    def test_audit_summary_displays_entries(self, runner, case_dir):
        """Audit-summary should display recent audit log entries."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "audit-summary"])
        assert result.exit_code == 0
        assert "init" in result.output
        assert "success" in result.output

    def test_audit_summary_respects_n_option(self, runner, case_dir):
        """Audit-summary -n should limit displayed entries."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        runner.invoke(cli, ["--case-dir", str(case_dir), "status"])

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "audit-summary", "-n", "1"]
        )
        assert result.exit_code == 0
        assert "last 1" in result.output

    def test_audit_summary_fails_without_log(self, runner, case_dir):
        """Audit-summary should fail if no audit log exists."""
        case_dir.mkdir(parents=True)

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "audit-summary"])
        assert result.exit_code == 1
        assert "No audit log found" in result.output

    def test_audit_summary_handles_empty_log(self, runner, case_dir):
        """Audit-summary should handle an empty audit log gracefully."""
        case_dir.mkdir(parents=True)
        logs_dir = case_dir / "logs"
        logs_dir.mkdir(parents=True)
        (logs_dir / "audit.jsonl").write_text("", encoding="utf-8")

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "audit-summary"])
        assert result.exit_code == 0
        assert "empty" in result.output

    def test_audit_summary_total_count(self, runner, case_dir):
        """Audit-summary should display total entry count."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        runner.invoke(cli, ["--case-dir", str(case_dir), "status"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "audit-summary"])
        assert result.exit_code == 0
        assert "Total entries in log:" in result.output


class TestAgentOnlyInterface:
    """The CLI is an agent-driven engine with no interactive menu."""

    def test_no_subcommand_shows_help_not_menu(self, runner, case_dir):
        """Running the root command with no subcommand prints help and exits."""
        result = runner.invoke(cli, ["--case-dir", str(case_dir)])

        # With no subcommand the group prints usage instead of launching a menu.
        assert "Usage:" in result.output
        assert "Interactive workflow" not in result.output
        # An explicit --help lists the available subcommands.
        help_result = runner.invoke(cli, ["--help"])
        assert "Commands:" in help_result.output

    def test_interactive_command_is_removed(self, runner, case_dir):
        """There is no 'interactive' subcommand anymore."""
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "interactive"])
        assert result.exit_code != 0
        assert "No such command" in result.output or "Usage:" in result.output

    def test_status_recommends_next_step_after_init(self, runner, case_dir):
        """status prints a concrete next command for the driving agent."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        assert result.exit_code == 0
        assert "Next step:" in result.output
        assert "ir-agent ingest" in result.output

    def test_status_next_step_points_to_extract_skill(self, runner, case_dir):
        """After ingest, the next step references the ir-extract-evidence skill."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        state_path = case_dir / "workflow_state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["current_phase"] = "artifacts_ingested"
        state["completed_phases"] = ["case_initialized", "artifacts_ingested"]
        state_path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        assert result.exit_code == 0
        assert "ir-extract-evidence" in result.output

    def test_status_next_step_complete_when_final(self, runner, case_dir):
        """When the final report exists, status reports completion."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        state_path = case_dir / "workflow_state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        all_phases = [
            "case_initialized", "artifacts_ingested", "evidence_candidates_generated",
            "evidence_ledger_approved", "data_coverage_built", "timeline_built",
            "attack_mapped", "claims_generated", "claims_reviewed", "gaps_checked",
            "gaps_dispositioned", "report_plan_generated", "report_plan_approved",
            "draft_report_generated", "draft_report_approved", "final_report_generated",
        ]
        state["completed_phases"] = all_phases
        state["current_phase"] = "final_report_generated"
        state_path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "status"])
        assert result.exit_code == 0
        assert "Workflow complete" in result.output
