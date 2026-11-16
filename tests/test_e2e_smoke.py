"""End-to-end smoke test for the IR Agent CLI pipeline.

Verifies:
1. All __init__.py files exist for proper imports
2. All services referenced in CLI commands are importable
3. init → ingest → normalize-events runs with real test data
4. Directory structure is created as specified in the design
5. Console_scripts entry point in pyproject.toml is correct
6. Workflow state transitions occur correctly
7. Governance layer (audit) is called at integration points

Requirements: 21.1, 26.5
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from ir_agent.cli.main import cli


class TestPackageStructure:
    """Verify all __init__.py files exist for proper imports."""

    EXPECTED_PACKAGES = [
        "ir_agent",
        "ir_agent/analysis",
        "ir_agent/cli",
        "ir_agent/evidence",
        "ir_agent/extraction",
        "ir_agent/governance",
        "ir_agent/ingestion",
        "ir_agent/models",
        "ir_agent/reporting",
        "ir_agent/steering",
        "ir_agent/storage",
        "ir_agent/workflow",
    ]

    def test_all_init_files_exist(self):
        """All subpackages must have __init__.py files."""
        project_root = Path(__file__).parent.parent
        for pkg_path in self.EXPECTED_PACKAGES:
            init_file = project_root / pkg_path / "__init__.py"
            assert init_file.exists(), f"Missing __init__.py: {init_file}"


class TestAllServicesImportable:
    """Verify all services referenced in CLI commands are importable."""

    def test_import_ingestion_layer(self):
        from ir_agent.ingestion.scanner import IngestionService
        from ir_agent.ingestion.chunker import chunk_file, Chunk
        assert IngestionService is not None
        assert chunk_file is not None
        assert Chunk is not None

    def test_import_extraction_layer(self):
        from ir_agent.extraction.parsers import RuleBasedParser
        from ir_agent.extraction.ioc_extractor import IOCExtractor
        from ir_agent.extraction.entity_resolver import EntityResolver
        assert RuleBasedParser is not None
        assert IOCExtractor is not None
        assert EntityResolver is not None

    def test_import_evidence_layer(self):
        from ir_agent.evidence.deduplicator import EvidenceDeduplicator
        from ir_agent.evidence.ledger_service import EvidenceLedgerService
        from ir_agent.evidence.review_generator import ReviewDocumentGenerator
        assert EvidenceDeduplicator is not None
        assert EvidenceLedgerService is not None
        assert ReviewDocumentGenerator is not None

    def test_import_analysis_layer(self):
        from ir_agent.analysis.timeline import TimelineBuilder
        from ir_agent.analysis.attack_mapper import ATTCKMapper
        from ir_agent.analysis.claim_builder import ClaimBuilder
        from ir_agent.analysis.claim_review import ClaimReviewService
        from ir_agent.analysis.gap_checker import GapChecker
        from ir_agent.analysis.gap_review import GapReviewService
        from ir_agent.analysis.coverage import DataCoverageService
        from ir_agent.analysis.metrics import QualityMetricsCalculator
        from ir_agent.analysis.task_generator import InvestigationTaskGenerator
        assert TimelineBuilder is not None
        assert ATTCKMapper is not None
        assert ClaimBuilder is not None
        assert ClaimReviewService is not None
        assert GapChecker is not None
        assert GapReviewService is not None
        assert DataCoverageService is not None
        assert QualityMetricsCalculator is not None
        assert InvestigationTaskGenerator is not None

    def test_import_reporting_layer(self):
        from ir_agent.reporting.localization import LocalizationEngine
        from ir_agent.reporting.guard import ReportGenerationGuard
        from ir_agent.reporting.planner import ReportPlanner
        from ir_agent.reporting.draft_generator import DraftGenerator
        from ir_agent.reporting.final_generator import FinalReportGenerator
        from ir_agent.reporting.rubric_checker import RubricChecker
        from ir_agent.reporting.ioc_formatter import IOCFormatter
        assert LocalizationEngine is not None
        assert ReportGenerationGuard is not None
        assert ReportPlanner is not None
        assert DraftGenerator is not None
        assert FinalReportGenerator is not None
        assert RubricChecker is not None
        assert IOCFormatter is not None

    def test_import_governance_layer(self):
        from ir_agent.governance.audit import AuditLogger
        from ir_agent.governance.injection_guard import PromptInjectionGuard
        from ir_agent.governance.redaction import RedactionService
        from ir_agent.governance.approval import ApprovalGate
        assert AuditLogger is not None
        assert PromptInjectionGuard is not None
        assert RedactionService is not None
        assert ApprovalGate is not None

    def test_import_workflow_layer(self):
        from ir_agent.workflow.service import WorkflowStateService
        from ir_agent.workflow.state import WorkflowState, WorkflowBlockedError
        assert WorkflowStateService is not None
        assert WorkflowState is not None
        assert WorkflowBlockedError is not None

    def test_import_steering_layer(self):
        from ir_agent.steering.service import CaseSteeringService
        from ir_agent.steering.manifest import CaseManifest
        assert CaseSteeringService is not None
        assert CaseManifest is not None


    def test_import_storage_layer(self):
        from ir_agent.storage.store import AppendOnlyStore
        assert AppendOnlyStore is not None

    def test_import_models(self):
        from ir_agent.models.enums import ConfidenceLevel
        from ir_agent.models.reporting import ReportPlan
        assert ConfidenceLevel is not None
        assert ReportPlan is not None


class TestDirectoryStructure:
    """Verify the complete directory structure is created by init."""

    def test_init_creates_expected_directories(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ["--case-dir", str(tmp_path), "init"])
        assert result.exit_code == 0, f"init failed: {result.output}"

        # Check all expected subdirectories
        expected_dirs = ["artifacts", "data", "reviews", "reports", "logs"]
        for subdir in expected_dirs:
            assert (tmp_path / subdir).is_dir(), f"Missing directory: {subdir}"

    def test_init_creates_manifest_yaml(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ["--case-dir", str(tmp_path), "init"])
        assert result.exit_code == 0

        manifest_path = tmp_path / "manifest.yaml"
        assert manifest_path.exists(), "manifest.yaml not created"

        content = manifest_path.read_text(encoding="utf-8")
        assert "case_id" in content
        assert "report_language" in content
        assert "review_language" in content
        assert "report_timezone" in content

    def test_init_creates_workflow_state(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ["--case-dir", str(tmp_path), "init"])
        assert result.exit_code == 0

        state_path = tmp_path / "workflow_state.json"
        assert state_path.exists(), "workflow_state.json not created"

        state_data = json.loads(state_path.read_text(encoding="utf-8"))
        assert "current_phase" in state_data
        assert "completed_phases" in state_data
        assert "case_initialized" in state_data["completed_phases"]


class TestEndToEndSmoke:
    """Run a minimal pipeline: init → ingest → normalize-events."""

    @pytest.fixture
    def case_dir(self, tmp_path):
        """Create a case directory with sample artifacts."""
        case = tmp_path / "test_case"
        case.mkdir()
        return case

    @pytest.fixture
    def artifacts_dir(self, tmp_path):
        """Create a directory with test artifacts."""
        artifacts = tmp_path / "artifacts"
        artifacts.mkdir()

        # Create a sample syslog file
        syslog_content = (
            "Jan 15 10:23:45 webserver01 sshd[1234]: Accepted password for admin from 192.168.1.100 port 22\n"
            "Jan 15 10:24:01 webserver01 sshd[1235]: Failed password for root from 10.0.0.5 port 22\n"
            "Jan 15 10:25:30 webserver01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.200 DST=192.168.1.1\n"
        )
        (artifacts / "auth.log").write_text(syslog_content, encoding="utf-8")

        # Create a simple text memo
        memo_content = (
            "Investigation Memo\n"
            "Date: 2024-01-15\n"
            "Analyst: John Doe\n\n"
            "Suspicious login activity observed on webserver01.\n"
            "IP 192.168.1.100 accessed admin account at 10:23:45 UTC.\n"
        )
        (artifacts / "memo.txt").write_text(memo_content, encoding="utf-8")

        return artifacts

    def test_init_command(self, case_dir):
        """Test that init creates proper directory structure."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result.exit_code == 0, f"init failed: {result.output}"
        assert "Case initialized" in result.output

        # Verify workflow state
        state_path = case_dir / "workflow_state.json"
        assert state_path.exists()
        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert "case_initialized" in state["completed_phases"]

    def test_init_then_ingest(self, case_dir, artifacts_dir):
        """Test init → ingest pipeline."""
        runner = CliRunner()

        # Step 1: init
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result.exit_code == 0, f"init failed: {result.output}"

        # Step 2: ingest
        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "ingest", "--artifacts-dir", str(artifacts_dir)]
        )
        assert result.exit_code == 0, f"ingest failed: {result.output}"
        assert "Found" in result.output

        # Verify outputs
        inventory_path = case_dir / "data" / "file_inventory.json"
        assert inventory_path.exists(), "file_inventory.json not created"

        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        assert len(inventory) >= 2, "Expected at least 2 files in inventory"

        # Verify chunks were created
        chunks_dir = case_dir / "data" / "chunks"
        assert chunks_dir.exists(), "chunks directory not created"

        # Verify workflow state advanced
        state = json.loads(
            (case_dir / "workflow_state.json").read_text(encoding="utf-8")
        )
        assert "artifacts_ingested" in state["completed_phases"]

    def test_init_ingest_normalize(self, case_dir, artifacts_dir):
        """Test init → ingest → normalize-events pipeline."""
        runner = CliRunner()

        # Step 1: init
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result.exit_code == 0, f"init failed: {result.output}"

        # Step 2: ingest
        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "ingest", "--artifacts-dir", str(artifacts_dir)]
        )
        assert result.exit_code == 0, f"ingest failed: {result.output}"

        # Step 3: normalize-events
        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "normalize-events"]
        )
        assert result.exit_code == 0, f"normalize-events failed: {result.output}"

        # Verify normalized events output
        events_path = case_dir / "data" / "normalized_events.jsonl"
        assert events_path.exists(), "normalized_events.jsonl not created"

        # Verify workflow state advanced
        state = json.loads(
            (case_dir / "workflow_state.json").read_text(encoding="utf-8")
        )
        assert "events_normalized" in state["completed_phases"]

    def test_audit_log_created_during_pipeline(self, case_dir, artifacts_dir):
        """Verify audit logger is called at all integration points."""
        runner = CliRunner()

        # Run init → ingest → normalize-events
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        runner.invoke(
            cli, ["--case-dir", str(case_dir), "ingest", "--artifacts-dir", str(artifacts_dir)]
        )
        runner.invoke(cli, ["--case-dir", str(case_dir), "normalize-events"])

        # Verify audit log exists and contains entries
        audit_path = case_dir / "logs" / "audit.jsonl"
        assert audit_path.exists(), "audit.jsonl not created"

        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) >= 3, f"Expected at least 3 audit entries, got {len(lines)}"

        # Verify audit entries are valid JSON with expected fields
        operations_logged = set()
        for line in lines:
            entry = json.loads(line)
            assert "timestamp" in entry
            assert "operation_type" in entry or "item_type" in entry
            op = entry.get("operation_type", "")
            if op:
                operations_logged.add(op)

        # Check that init, ingest, and normalize-events were logged
        assert "init" in operations_logged, "init not found in audit log"
        assert "ingest" in operations_logged, "ingest not found in audit log"
        assert "normalize-events" in operations_logged, "normalize-events not found in audit log"

    def test_workflow_state_transitions(self, case_dir, artifacts_dir):
        """Verify workflow state transitions occur correctly through the pipeline."""
        runner = CliRunner()

        # After init: CASE_INITIALIZED
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        state = json.loads(
            (case_dir / "workflow_state.json").read_text(encoding="utf-8")
        )
        assert "case_initialized" in state["completed_phases"]

        # After ingest: ARTIFACTS_INGESTED
        runner.invoke(
            cli, ["--case-dir", str(case_dir), "ingest", "--artifacts-dir", str(artifacts_dir)]
        )
        state = json.loads(
            (case_dir / "workflow_state.json").read_text(encoding="utf-8")
        )
        assert "artifacts_ingested" in state["completed_phases"]

        # After normalize-events: EVENTS_NORMALIZED
        runner.invoke(cli, ["--case-dir", str(case_dir), "normalize-events"])
        state = json.loads(
            (case_dir / "workflow_state.json").read_text(encoding="utf-8")
        )
        assert "events_normalized" in state["completed_phases"]

    def test_workflow_enforcement_blocks_out_of_order(self, case_dir):
        """Test that running commands out of order is blocked."""
        runner = CliRunner()

        # Try to run normalize-events without init/ingest
        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "normalize-events"]
        )
        # Should fail because prerequisites aren't met
        assert result.exit_code != 0 or "Error" in result.output


class TestConsoleScripts:
    """Verify the console_scripts entry point is correct."""

    def test_entry_point_in_pyproject(self):
        """Check pyproject.toml has correct console_scripts entry."""
        project_root = Path(__file__).parent.parent
        pyproject_path = project_root / "pyproject.toml"
        assert pyproject_path.exists()

        content = pyproject_path.read_text(encoding="utf-8")
        assert 'ir-agent = "ir_agent.cli.main:cli"' in content

    def test_cli_group_is_click_group(self):
        """Verify the cli object is a Click group."""
        from ir_agent.cli.main import cli
        import click
        assert isinstance(cli, click.Group)

    def test_cli_has_all_expected_commands(self):
        """Verify CLI registers all expected commands."""
        from ir_agent.cli.main import cli

        expected_commands = [
            "init",
            "status",
            "audit-summary",
            "ingest",
            "normalize-events",
            "extract-candidates",
            "review-evidence",
            "promote-evidence",
            "build-coverage",
            "build-timeline",
            "map-attack",
            "build-claims",
            "review-claims",
            "apply-claim-review",
            "check-gaps",
            "generate-tasks",
            "review-gaps",
            "apply-gap-disposition",
            "plan-report",
            "approve-report-plan",
            "draft-report",
            "review-draft",
            "approve-draft",
            "finalize-report",
        ]

        registered_commands = list(cli.commands.keys())
        for cmd in expected_commands:
            assert cmd in registered_commands, (
                f"Command '{cmd}' not registered in CLI. "
                f"Available: {registered_commands}"
            )
