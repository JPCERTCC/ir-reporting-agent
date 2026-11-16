"""Unit tests for claim review and gap CLI commands.

Tests the claim review, gap checking, task generation, gap review,
and gap disposition workflow commands.

Requirements: 12.1, 13.1, 13.5, 27.1
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from ir_agent.cli.main import cli
from ir_agent.models.analysis import Claim, DataCoverageEntry, Gap
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel


@pytest.fixture
def runner():
    """Create a Click test runner."""
    return CliRunner()


@pytest.fixture
def case_dir(tmp_path):
    """Provide a temporary case directory path."""
    return tmp_path / "test_case"


@pytest.fixture
def initialized_case(runner, case_dir):
    """Create a fully initialized case with subdirectories and manifest."""
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


def _make_claim(claim_id: str, claim_text: str = "Test claim") -> Claim:
    """Create a sample Claim for testing."""
    return Claim(
        claim_id=claim_id,
        report_section="findings",
        claim_text=claim_text,
        claim_category=ClaimCategory.OBSERVED_FACT,
        confidence_level=ConfidenceLevel.PROBABLE,
        confidence_basis="Based on single corroborated evidence source",
        supporting_evidence=["EV-001"],
        counter_evidence=[],
        limitations=["Limited log retention"],
        missing_evidence=[],
        recommended_expressions=["おそらく"],
        prohibited_expressions=["確認された"],
        review_status="pending",
    )


def _write_claims(case_dir: Path, claims: list[Claim]) -> None:
    """Write claims to the expected JSONL file."""
    claims_path = case_dir / "data" / "claims.jsonl"
    claims_path.parent.mkdir(parents=True, exist_ok=True)
    with open(claims_path, "w", encoding="utf-8") as f:
        for c in claims:
            f.write(c.model_dump_json() + "\n")


def _make_gap(gap_id: str, severity: str = "major") -> Gap:
    """Create a sample Gap for testing."""
    return Gap(
        gap_id=gap_id,
        related_claim_id="CLAIM-001",
        gap_type="weak_evidence",
        severity=severity,
        description="Claim relies on weak evidence",
        recommended_action="Collect additional corroborating sources",
    )


def _write_gaps(case_dir: Path, gaps: list[Gap]) -> None:
    """Write gaps to the expected JSONL file."""
    gaps_path = case_dir / "data" / "gaps.jsonl"
    gaps_path.parent.mkdir(parents=True, exist_ok=True)
    with open(gaps_path, "w", encoding="utf-8") as f:
        for g in gaps:
            f.write(g.model_dump_json() + "\n")


class TestReviewClaimsCommand:
    """Tests for the 'review-claims' CLI command."""

    def test_review_claims_generates_review_doc(self, runner, initialized_case):
        """review-claims should generate a claim review Markdown file."""
        claims = [_make_claim("CLAIM-001"), _make_claim("CLAIM-002", "Second claim")]
        _write_claims(initialized_case, claims)

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-claims"]
        )
        assert result.exit_code == 0

        review_path = initialized_case / "reviews" / "claim_review_001.md"
        assert review_path.is_file()
        content = review_path.read_text(encoding="utf-8")
        assert "CLAIM-001" in content
        assert "CLAIM-002" in content

    def test_review_claims_uses_japanese_headings(self, runner, initialized_case):
        """review-claims should render headings in Japanese by default."""
        claims = [_make_claim("CLAIM-001")]
        _write_claims(initialized_case, claims)

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-claims"]
        )
        assert result.exit_code == 0

        review_path = initialized_case / "reviews" / "claim_review_001.md"
        content = review_path.read_text(encoding="utf-8")
        # Check Japanese heading
        assert "Claim レビュー" in content
        assert "信頼度" in content

    def test_review_claims_fails_without_claims(self, runner, initialized_case):
        """review-claims should fail if claims.jsonl does not exist."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-claims"]
        )
        assert result.exit_code != 0
        assert "No claims found" in result.output or "Error" in result.output

    def test_review_claims_increments_review_number(self, runner, initialized_case):
        """Subsequent review-claims calls should increment the review number."""
        claims = [_make_claim("CLAIM-001")]
        _write_claims(initialized_case, claims)

        # Create first review
        runner.invoke(cli, ["--case-dir", str(initialized_case), "review-claims"])
        # Create second review
        runner.invoke(cli, ["--case-dir", str(initialized_case), "review-claims"])

        assert (initialized_case / "reviews" / "claim_review_001.md").is_file()
        assert (initialized_case / "reviews" / "claim_review_002.md").is_file()


class TestApplyClaimReviewCommand:
    """Tests for the 'apply-claim-review' CLI command."""

    def test_apply_claim_review_updates_claim_statuses(self, runner, initialized_case):
        """apply-claim-review should update claim review_status from decisions."""
        claims = [_make_claim("CLAIM-001"), _make_claim("CLAIM-002")]
        _write_claims(initialized_case, claims)

        # Set workflow state to allow review-claims
        _set_workflow_phase(
            initialized_case,
            "claims_generated",
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
            ],
        )

        # Generate review doc
        runner.invoke(cli, ["--case-dir", str(initialized_case), "review-claims"])

        # Modify the review doc to approve CLAIM-001 and reject CLAIM-002
        review_path = initialized_case / "reviews" / "claim_review_001.md"
        content = review_path.read_text(encoding="utf-8")
        content = content.replace(
            "item_id: CLAIM-001\nitem_type: claim\ndecision: pending",
            "item_id: CLAIM-001\nitem_type: claim\ndecision: approved",
        )
        content = content.replace(
            "item_id: CLAIM-002\nitem_type: claim\ndecision: pending",
            "item_id: CLAIM-002\nitem_type: claim\ndecision: rejected",
        )
        review_path.write_text(content, encoding="utf-8")

        # Apply review
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "apply-claim-review"]
        )
        assert result.exit_code == 0
        assert "Approved:" in result.output
        assert "Rejected:" in result.output

        # Verify claims were updated
        claims_path = initialized_case / "data" / "claims.jsonl"
        with open(claims_path, "r", encoding="utf-8") as f:
            updated_claims = [
                Claim.model_validate_json(line.strip())
                for line in f
                if line.strip()
            ]

        assert updated_claims[0].review_status == "approved"
        assert updated_claims[1].review_status == "rejected"

    def test_apply_claim_review_marks_claims_reviewed(self, runner, initialized_case):
        """apply-claim-review should mark CLAIMS_REVIEWED when no pending items."""
        claims = [_make_claim("CLAIM-001")]
        _write_claims(initialized_case, claims)

        _set_workflow_phase(
            initialized_case,
            "claims_generated",
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
            ],
        )

        # Generate and approve
        runner.invoke(cli, ["--case-dir", str(initialized_case), "review-claims"])
        review_path = initialized_case / "reviews" / "claim_review_001.md"
        content = review_path.read_text(encoding="utf-8")
        content = content.replace(
            "decision: pending",
            "decision: approved",
        )
        review_path.write_text(content, encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "apply-claim-review"]
        )
        assert result.exit_code == 0
        assert "CLAIMS_REVIEWED" in result.output

    def test_apply_claim_review_fails_without_prerequisite(self, runner, initialized_case):
        """apply-claim-review should fail if CLAIMS_GENERATED is not completed."""
        claims = [_make_claim("CLAIM-001")]
        _write_claims(initialized_case, claims)

        # Set workflow state without CLAIMS_GENERATED
        _set_workflow_phase(
            initialized_case,
            "case_initialized",
            ["case_initialized"],
        )

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "apply-claim-review"]
        )
        assert result.exit_code != 0


class TestCheckGapsCommand:
    """Tests for the 'check-gaps' CLI command."""

    def test_check_gaps_writes_gaps_jsonl(self, runner, initialized_case):
        """check-gaps should write identified gaps to data/gaps.jsonl."""
        # Create a claim with a single source (will be flagged)
        claim = _make_claim("CLAIM-001")
        claim.confidence_level = ConfidenceLevel.CONFIRMED
        claim.supporting_evidence = ["EV-001"]  # Single source for CONFIRMED
        _write_claims(initialized_case, [claim])

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
        assert result.exit_code == 0

        gaps_path = initialized_case / "data" / "gaps.jsonl"
        assert gaps_path.is_file()

        # Read and verify gaps
        with open(gaps_path, "r", encoding="utf-8") as f:
            gaps = [Gap.model_validate_json(line.strip()) for line in f if line.strip()]
        assert len(gaps) > 0

    def test_check_gaps_marks_gaps_checked(self, runner, initialized_case):
        """check-gaps should mark GAPS_CHECKED workflow phase."""
        claim = _make_claim("CLAIM-001")
        _write_claims(initialized_case, [claim])

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
        assert result.exit_code == 0
        assert "GAPS_CHECKED" in result.output

    def test_check_gaps_fails_without_prerequisite(self, runner, initialized_case):
        """check-gaps should fail if prerequisites are not met."""
        claim = _make_claim("CLAIM-001")
        _write_claims(initialized_case, [claim])

        _set_workflow_phase(
            initialized_case,
            "case_initialized",
            ["case_initialized"],
        )

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "check-gaps"]
        )
        assert result.exit_code != 0

    def test_check_gaps_fails_without_claims(self, runner, initialized_case):
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


class TestGenerateTasksCommand:
    """Tests for the 'generate-tasks' CLI command."""

    def test_generate_tasks_writes_tasks_jsonl(self, runner, initialized_case):
        """generate-tasks should write tasks to data/investigation_tasks.jsonl."""
        gaps = [_make_gap("GAP-001"), _make_gap("GAP-002", "critical")]
        _write_gaps(initialized_case, gaps)

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "generate-tasks"]
        )
        assert result.exit_code == 0

        tasks_path = initialized_case / "data" / "investigation_tasks.jsonl"
        assert tasks_path.is_file()

        with open(tasks_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        assert len(lines) == 2

    def test_generate_tasks_fails_without_gaps(self, runner, initialized_case):
        """generate-tasks should fail if gaps.jsonl does not exist."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "generate-tasks"]
        )
        assert result.exit_code != 0

    def test_generate_tasks_reports_priority_summary(self, runner, initialized_case):
        """generate-tasks should report task priorities in output."""
        gaps = [_make_gap("GAP-001", "critical"), _make_gap("GAP-002", "minor")]
        _write_gaps(initialized_case, gaps)

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "generate-tasks"]
        )
        assert result.exit_code == 0
        assert "high" in result.output.lower() or "medium" in result.output.lower()


class TestReviewGapsCommand:
    """Tests for the 'review-gaps' CLI command."""

    def test_review_gaps_generates_review_doc(self, runner, initialized_case):
        """review-gaps should generate a gap review Markdown file."""
        gaps = [_make_gap("GAP-001"), _make_gap("GAP-002")]
        _write_gaps(initialized_case, gaps)

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-gaps"]
        )
        assert result.exit_code == 0

        review_path = initialized_case / "reviews" / "gap_review_001.md"
        assert review_path.is_file()
        content = review_path.read_text(encoding="utf-8")
        assert "GAP-001" in content
        assert "GAP-002" in content

    def test_review_gaps_uses_japanese_headings(self, runner, initialized_case):
        """review-gaps should render headings in Japanese by default."""
        gaps = [_make_gap("GAP-001")]
        _write_gaps(initialized_case, gaps)

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-gaps"]
        )
        assert result.exit_code == 0

        review_path = initialized_case / "reviews" / "gap_review_001.md"
        content = review_path.read_text(encoding="utf-8")
        assert "説明" in content
        assert "関連Claim" in content

    def test_review_gaps_fails_without_gaps(self, runner, initialized_case):
        """review-gaps should fail if gaps.jsonl does not exist."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-gaps"]
        )
        assert result.exit_code != 0


class TestApplyGapDispositionCommand:
    """Tests for the 'apply-gap-disposition' CLI command."""

    def test_apply_gap_disposition_updates_gaps(self, runner, initialized_case):
        """apply-gap-disposition should update gap dispositions."""
        gaps = [_make_gap("GAP-001"), _make_gap("GAP-002")]
        _write_gaps(initialized_case, gaps)

        _set_workflow_phase(
            initialized_case,
            "gaps_checked",
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
            ],
        )

        # Generate gap review doc
        runner.invoke(cli, ["--case-dir", str(initialized_case), "review-gaps"])

        # Set dispositions in the review doc
        review_path = initialized_case / "reviews" / "gap_review_001.md"
        content = review_path.read_text(encoding="utf-8")
        content = content.replace(
            "item_id: GAP-001\nitem_type: gap\ndisposition: null",
            "item_id: GAP-001\nitem_type: gap\ndisposition: accepted_as_limitation",
        )
        content = content.replace(
            "item_id: GAP-002\nitem_type: gap\ndisposition: null",
            "item_id: GAP-002\nitem_type: gap\ndisposition: deferred_with_reason",
        )
        review_path.write_text(content, encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "apply-gap-disposition"]
        )
        assert result.exit_code == 0
        assert "Dispositioned:" in result.output

        # Verify gaps were updated
        gaps_path = initialized_case / "data" / "gaps.jsonl"
        with open(gaps_path, "r", encoding="utf-8") as f:
            updated_gaps = [
                Gap.model_validate_json(line.strip())
                for line in f
                if line.strip()
            ]

        assert updated_gaps[0].disposition == "accepted_as_limitation"
        assert updated_gaps[1].disposition == "deferred_with_reason"

    def test_apply_gap_disposition_marks_gaps_dispositioned(self, runner, initialized_case):
        """apply-gap-disposition should mark GAPS_DISPOSITIONED when all dispositioned."""
        gaps = [_make_gap("GAP-001")]
        _write_gaps(initialized_case, gaps)

        _set_workflow_phase(
            initialized_case,
            "gaps_checked",
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
            ],
        )

        # Generate and disposition
        runner.invoke(cli, ["--case-dir", str(initialized_case), "review-gaps"])
        review_path = initialized_case / "reviews" / "gap_review_001.md"
        content = review_path.read_text(encoding="utf-8")
        content = content.replace(
            "disposition: null",
            "disposition: accepted_as_limitation",
        )
        review_path.write_text(content, encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "apply-gap-disposition"]
        )
        assert result.exit_code == 0
        assert "GAPS_DISPOSITIONED" in result.output

    def test_apply_gap_disposition_fails_without_prerequisite(self, runner, initialized_case):
        """apply-gap-disposition should fail if GAPS_CHECKED is not completed."""
        gaps = [_make_gap("GAP-001")]
        _write_gaps(initialized_case, gaps)

        _set_workflow_phase(
            initialized_case,
            "case_initialized",
            ["case_initialized"],
        )

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "apply-gap-disposition"]
        )
        assert result.exit_code != 0

    def test_apply_gap_disposition_does_not_mark_if_pending(self, runner, initialized_case):
        """apply-gap-disposition should not mark GAPS_DISPOSITIONED if gaps still pending."""
        gaps = [_make_gap("GAP-001"), _make_gap("GAP-002")]
        _write_gaps(initialized_case, gaps)

        _set_workflow_phase(
            initialized_case,
            "gaps_checked",
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
            ],
        )

        # Generate review doc but only disposition one gap
        runner.invoke(cli, ["--case-dir", str(initialized_case), "review-gaps"])
        review_path = initialized_case / "reviews" / "gap_review_001.md"
        content = review_path.read_text(encoding="utf-8")
        # Only replace the first occurrence
        content = content.replace(
            "item_id: GAP-001\nitem_type: gap\ndisposition: null",
            "item_id: GAP-001\nitem_type: gap\ndisposition: accepted_as_limitation",
            1,
        )
        review_path.write_text(content, encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "apply-gap-disposition"]
        )
        assert result.exit_code == 0
        assert "GAPS_DISPOSITIONED" not in result.output
        assert "pending" in result.output.lower()
