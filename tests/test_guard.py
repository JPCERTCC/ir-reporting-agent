"""Unit tests for ReportGenerationGuard.

Tests the three validation gates: validate_before_plan,
validate_before_draft, and validate_before_final.

Requirements: 13.6, 16.2, 16.9, 17.4
"""

import pytest

from ir_agent.models.analysis import Claim, Gap
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel, WorkflowPhase
from ir_agent.models.reporting import ReportPlan
from ir_agent.reporting.guard import ReportBlockedError, ReportGenerationGuard
from ir_agent.workflow.state import WorkflowState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_claim(
    claim_id: str = "CLM-001",
    review_status: str = "approved",
    supporting_evidence: list[str] | None = None,
) -> Claim:
    """Helper to create a Claim for testing."""
    return Claim(
        claim_id=claim_id,
        report_section="findings",
        claim_text="Test claim text",
        claim_category=ClaimCategory.INTERPRETATION,
        confidence_level=ConfidenceLevel.PROBABLE,
        confidence_basis="Test basis",
        supporting_evidence=supporting_evidence if supporting_evidence is not None else ["EV-001"],
        counter_evidence=[],
        review_status=review_status,
    )


def _make_gap(
    gap_id: str = "GAP-001",
    severity: str = "critical",
    disposition: str | None = None,
) -> Gap:
    """Helper to create a Gap for testing."""
    return Gap(
        gap_id=gap_id,
        related_claim_id="CLM-001",
        gap_type="missing_evidence",
        severity=severity,
        description="Missing log data",
        recommended_action="Collect additional logs",
        disposition=disposition,
    )


def _make_state(
    completed_phases: list[WorkflowPhase] | None = None,
) -> WorkflowState:
    """Helper to create a WorkflowState for testing."""
    return WorkflowState(
        case_id="CASE-001",
        completed_phases=completed_phases if completed_phases is not None else [],
    )


def _make_plan() -> ReportPlan:
    """Helper to create a ReportPlan for testing."""
    return ReportPlan(
        sections=[
            {
                "heading": "Findings",
                "claims": ["CLM-001"],
                "evidence_refs": ["EV-001"],
                "narrative_flow": "chronological",
            }
        ],
        structure_type="standard",
    )


# ---------------------------------------------------------------------------
# Tests for validate_before_plan
# ---------------------------------------------------------------------------


class TestValidateBeforePlan:
    """Tests for the plan-phase validation gate."""

    def test_passes_with_all_approved_claims_and_dispositioned_gaps(self):
        guard = ReportGenerationGuard()
        claims = [_make_claim(review_status="approved")]
        gaps = [_make_gap(disposition="accepted_as_limitation")]
        state = _make_state()

        reasons = guard.validate_before_plan(claims, gaps, state)

        assert reasons == []

    def test_passes_with_rejected_claims_excluded(self):
        """Rejected claims should not block — they are excluded from the report."""
        guard = ReportGenerationGuard()
        claims = [
            _make_claim(claim_id="CLM-001", review_status="approved"),
            _make_claim(claim_id="CLM-002", review_status="rejected"),
        ]
        gaps = []
        state = _make_state()

        reasons = guard.validate_before_plan(claims, gaps, state)

        assert reasons == []

    def test_blocks_on_pending_claims(self):
        guard = ReportGenerationGuard()
        claims = [_make_claim(claim_id="CLM-001", review_status="pending")]
        gaps = []
        state = _make_state()

        reasons = guard.validate_before_plan(claims, gaps, state)

        assert len(reasons) == 1
        assert "CLM-001" in reasons[0]
        assert "Unapproved" in reasons[0]

    def test_blocks_on_edited_claims(self):
        guard = ReportGenerationGuard()
        claims = [_make_claim(claim_id="CLM-002", review_status="edited")]
        gaps = []
        state = _make_state()

        reasons = guard.validate_before_plan(claims, gaps, state)

        assert len(reasons) == 1
        assert "CLM-002" in reasons[0]

    def test_blocks_on_downgraded_claims(self):
        guard = ReportGenerationGuard()
        claims = [_make_claim(claim_id="CLM-003", review_status="downgraded")]
        gaps = []
        state = _make_state()

        reasons = guard.validate_before_plan(claims, gaps, state)

        assert len(reasons) == 1
        assert "CLM-003" in reasons[0]

    def test_blocks_on_undispositioned_critical_gaps(self):
        guard = ReportGenerationGuard()
        claims = [_make_claim(review_status="approved")]
        gaps = [_make_gap(gap_id="GAP-001", severity="critical", disposition=None)]
        state = _make_state()

        reasons = guard.validate_before_plan(claims, gaps, state)

        assert len(reasons) == 1
        assert "GAP-001" in reasons[0]
        assert "critical" in reasons[0].lower()

    def test_does_not_block_on_minor_undispositioned_gaps(self):
        guard = ReportGenerationGuard()
        claims = [_make_claim(review_status="approved")]
        gaps = [_make_gap(gap_id="GAP-001", severity="minor", disposition=None)]
        state = _make_state()

        reasons = guard.validate_before_plan(claims, gaps, state)

        assert reasons == []

    def test_does_not_block_on_major_undispositioned_gaps(self):
        guard = ReportGenerationGuard()
        claims = [_make_claim(review_status="approved")]
        gaps = [_make_gap(gap_id="GAP-001", severity="major", disposition=None)]
        state = _make_state()

        reasons = guard.validate_before_plan(claims, gaps, state)

        assert reasons == []

    def test_multiple_blocking_reasons(self):
        guard = ReportGenerationGuard()
        claims = [_make_claim(claim_id="CLM-001", review_status="pending")]
        gaps = [_make_gap(gap_id="GAP-001", severity="critical", disposition=None)]
        state = _make_state()

        reasons = guard.validate_before_plan(claims, gaps, state)

        assert len(reasons) == 2

    def test_passes_with_empty_claims_and_gaps(self):
        guard = ReportGenerationGuard()
        reasons = guard.validate_before_plan([], [], _make_state())
        assert reasons == []


# ---------------------------------------------------------------------------
# Tests for validate_before_draft
# ---------------------------------------------------------------------------


class TestValidateBeforeDraft:
    """Tests for the draft-phase validation gate."""

    def test_passes_with_zero_unsupported_rate_and_all_approved(self):
        guard = ReportGenerationGuard()
        plan = _make_plan()
        claims = [_make_claim(review_status="approved")]
        gaps = []
        metrics = {"unsupported_claim_rate": 0.0, "overclaim_rate": 0.0}

        reasons = guard.validate_before_draft(plan, claims, gaps, metrics)

        assert reasons == []

    def test_blocks_on_nonzero_unsupported_claim_rate(self):
        guard = ReportGenerationGuard()
        plan = _make_plan()
        claims = [_make_claim(review_status="approved", supporting_evidence=[])]
        gaps = []
        metrics = {"unsupported_claim_rate": 0.5}

        reasons = guard.validate_before_draft(plan, claims, gaps, metrics)

        assert len(reasons) >= 1
        assert "unsupported" in reasons[0].lower() or "Unsupported" in reasons[0]

    def test_blocks_on_unapproved_claims_in_use(self):
        guard = ReportGenerationGuard()
        plan = _make_plan()
        claims = [
            _make_claim(claim_id="CLM-001", review_status="approved"),
            _make_claim(claim_id="CLM-002", review_status="pending"),
        ]
        gaps = []
        metrics = {"unsupported_claim_rate": 0.0}

        reasons = guard.validate_before_draft(plan, claims, gaps, metrics)

        assert len(reasons) == 1
        assert "CLM-002" in reasons[0]

    def test_rejected_claims_do_not_block(self):
        guard = ReportGenerationGuard()
        plan = _make_plan()
        claims = [
            _make_claim(claim_id="CLM-001", review_status="approved"),
            _make_claim(claim_id="CLM-002", review_status="rejected"),
        ]
        gaps = []
        metrics = {"unsupported_claim_rate": 0.0}

        reasons = guard.validate_before_draft(plan, claims, gaps, metrics)

        assert reasons == []

    def test_blocks_on_both_conditions(self):
        guard = ReportGenerationGuard()
        plan = _make_plan()
        claims = [_make_claim(claim_id="CLM-001", review_status="pending")]
        gaps = []
        metrics = {"unsupported_claim_rate": 0.25}

        reasons = guard.validate_before_draft(plan, claims, gaps, metrics)

        assert len(reasons) == 2


# ---------------------------------------------------------------------------
# Tests for validate_before_final
# ---------------------------------------------------------------------------


class TestValidateBeforeFinal:
    """Tests for the final-phase validation gate."""

    def test_passes_with_all_conditions_met(self):
        guard = ReportGenerationGuard()
        draft = "# Final Report\n\nContent here."
        rubric_results = {"critical_failures": [], "audit_log_valid": True}
        gaps = [_make_gap(disposition="accepted_as_limitation")]
        state = _make_state(
            completed_phases=[WorkflowPhase.DRAFT_REPORT_APPROVED]
        )

        reasons = guard.validate_before_final(draft, rubric_results, gaps, state)

        assert reasons == []

    def test_blocks_on_critical_rubric_failures(self):
        guard = ReportGenerationGuard()
        draft = "# Draft\n"
        rubric_results = {
            "critical_failures": ["Missing executive summary", "No evidence citations"],
            "audit_log_valid": True,
        }
        gaps = []
        state = _make_state(
            completed_phases=[WorkflowPhase.DRAFT_REPORT_APPROVED]
        )

        reasons = guard.validate_before_final(draft, rubric_results, gaps, state)

        assert len(reasons) == 1
        assert "rubric" in reasons[0].lower()

    def test_blocks_on_undispositioned_critical_gaps(self):
        guard = ReportGenerationGuard()
        draft = "# Draft\n"
        rubric_results = {"critical_failures": [], "audit_log_valid": True}
        gaps = [_make_gap(gap_id="GAP-X", severity="critical", disposition=None)]
        state = _make_state(
            completed_phases=[WorkflowPhase.DRAFT_REPORT_APPROVED]
        )

        reasons = guard.validate_before_final(draft, rubric_results, gaps, state)

        assert len(reasons) == 1
        assert "GAP-X" in reasons[0]

    def test_blocks_on_failed_audit_log(self):
        guard = ReportGenerationGuard()
        draft = "# Draft\n"
        rubric_results = {"critical_failures": [], "audit_log_valid": False}
        gaps = []
        state = _make_state(
            completed_phases=[WorkflowPhase.DRAFT_REPORT_APPROVED]
        )

        reasons = guard.validate_before_final(draft, rubric_results, gaps, state)

        assert len(reasons) == 1
        assert "audit" in reasons[0].lower()

    def test_blocks_on_missing_final_approval(self):
        guard = ReportGenerationGuard()
        draft = "# Draft\n"
        rubric_results = {"critical_failures": [], "audit_log_valid": True}
        gaps = []
        # DRAFT_REPORT_APPROVED not in completed_phases
        state = _make_state(
            completed_phases=[WorkflowPhase.DRAFT_REPORT_GENERATED]
        )

        reasons = guard.validate_before_final(draft, rubric_results, gaps, state)

        assert len(reasons) == 1
        assert "approval" in reasons[0].lower()

    def test_blocks_on_multiple_conditions(self):
        guard = ReportGenerationGuard()
        draft = "# Draft\n"
        rubric_results = {
            "critical_failures": ["No limitations section"],
            "audit_log_valid": False,
        }
        gaps = [_make_gap(gap_id="GAP-Y", severity="critical", disposition=None)]
        state = _make_state(completed_phases=[])

        reasons = guard.validate_before_final(draft, rubric_results, gaps, state)

        # Should have 4 reasons: rubric, gaps, audit, approval
        assert len(reasons) == 4

    def test_dispositioned_critical_gaps_do_not_block(self):
        guard = ReportGenerationGuard()
        draft = "# Draft\n"
        rubric_results = {"critical_failures": [], "audit_log_valid": True}
        gaps = [
            _make_gap(
                gap_id="GAP-Z",
                severity="critical",
                disposition="mitigated_by_claim_downgrade",
            )
        ]
        state = _make_state(
            completed_phases=[WorkflowPhase.DRAFT_REPORT_APPROVED]
        )

        reasons = guard.validate_before_final(draft, rubric_results, gaps, state)

        assert reasons == []


# ---------------------------------------------------------------------------
# Tests for ReportBlockedError
# ---------------------------------------------------------------------------


class TestReportBlockedError:
    """Tests for the ReportBlockedError exception."""

    def test_error_attributes(self):
        error = ReportBlockedError("plan", ["reason1", "reason2"])
        assert error.phase == "plan"
        assert error.reasons == ["reason1", "reason2"]
        assert "plan" in str(error)
        assert "reason1" in str(error)
        assert "reason2" in str(error)

    def test_error_single_reason(self):
        error = ReportBlockedError("final", ["Audit log failed"])
        assert "final" in str(error)
        assert "Audit log failed" in str(error)
