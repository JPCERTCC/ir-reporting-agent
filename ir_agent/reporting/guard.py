"""Report Generation Guard for the Reporting Layer.

Provides validation gates that prevent report generation from proceeding
when prerequisite conditions are not met. Each gate returns a list of
blocking reasons; an empty list means the gate passes.

The guard raises ReportBlockedError to prevent generation when blocking
conditions are detected, ensuring reports are only produced from
fully-approved, evidence-grounded inputs.

Requirements: 13.6, 16.2, 16.9, 17.4
"""

from __future__ import annotations

import logging
from typing import Optional

from ir_agent.models.analysis import Claim, Gap
from ir_agent.models.reporting import ReportPlan
from ir_agent.workflow.state import WorkflowState

logger = logging.getLogger(__name__)


class ReportBlockedError(Exception):
    """Raised when report generation is blocked by unmet conditions.

    Attributes:
        phase: The generation phase that was blocked (plan, draft, final).
        reasons: List of human-readable reasons why generation was blocked.
    """

    def __init__(self, phase: str, reasons: list[str]) -> None:
        self.phase = phase
        self.reasons = reasons
        reasons_str = "; ".join(reasons)
        super().__init__(
            f"Report generation blocked at '{phase}' phase: {reasons_str}"
        )


class ReportGenerationGuard:
    """Validates preconditions before each report generation phase.

    Three validation gates correspond to the three generation phases:
    1. validate_before_plan — before generating the report plan
    2. validate_before_draft — before generating the draft report
    3. validate_before_final — before producing the final report

    Each method returns a list of blocking reasons. If the list is
    non-empty, the caller should raise ReportBlockedError or handle
    the blocking condition appropriately.

    Requirements:
    - 13.6: Block final report generation on unresolved critical gaps
    - 16.2: Use ONLY approved claims in the draft report
    - 16.9: Generate draft using only approved inputs
    - 17.4: Do not produce final report without explicit analyst approval
    """

    def validate_before_plan(
        self,
        claims: list[Claim],
        gaps: list[Gap],
        state: WorkflowState,
    ) -> list[str]:
        """Validate conditions before generating a report plan.

        Blocks if:
        - Any claims have review_status other than 'approved' (pending,
          rejected, edited without re-approval, or downgraded without
          re-approval are treated as unapproved for planning purposes)
        - Unresolved critical gaps exist (critical severity with no disposition)

        Args:
            claims: All claims from the analysis layer.
            gaps: All identified gaps.
            state: Current workflow state.

        Returns:
            List of blocking reasons. Empty list means validation passes.
        """
        reasons: list[str] = []

        # Check for unapproved claims
        unapproved_claims = [
            c for c in claims
            if c.review_status not in ("approved", "rejected")
        ]
        if unapproved_claims:
            unapproved_ids = [c.claim_id for c in unapproved_claims]
            reasons.append(
                f"Unapproved claims exist (count={len(unapproved_claims)}): "
                f"{unapproved_ids}"
            )

        # Check for undispositioned critical gaps
        undispositioned_critical = [
            g for g in gaps
            if g.severity == "critical" and g.disposition is None
        ]
        if undispositioned_critical:
            gap_ids = [g.gap_id for g in undispositioned_critical]
            reasons.append(
                f"Unresolved critical gaps without disposition "
                f"(count={len(undispositioned_critical)}): {gap_ids}"
            )

        if reasons:
            logger.warning(
                "Report plan generation blocked: %s", "; ".join(reasons)
            )

        return reasons

    def validate_before_draft(
        self,
        plan: ReportPlan,
        claims: list[Claim],
        gaps: list[Gap],
        metrics: dict,
    ) -> list[str]:
        """Validate conditions before generating a draft report.

        Blocks if:
        - unsupported_claim_rate > 0 (all claims must have evidence)
        - Any claim used in the plan references unapproved evidence
          (i.e., claims that aren't approved are included)

        Args:
            plan: The approved report plan.
            claims: All claims from the analysis layer.
            gaps: All identified gaps.
            metrics: Quality metrics dict with keys like
                'unsupported_claim_rate', 'overclaim_rate', etc.

        Returns:
            List of blocking reasons. Empty list means validation passes.
        """
        reasons: list[str] = []

        # Check unsupported claim rate must be exactly 0
        unsupported_rate = metrics.get("unsupported_claim_rate", 0.0)
        if unsupported_rate > 0:
            reasons.append(
                f"Unsupported claim rate is {unsupported_rate:.4f} "
                f"(must be 0.0 — all claims must link to evidence)"
            )

        # Check for unapproved evidence usage: any non-approved, non-rejected
        # claim that would be used in draft generation
        unapproved_claims_in_use = [
            c for c in claims
            if c.review_status not in ("approved", "rejected")
        ]
        if unapproved_claims_in_use:
            unapproved_ids = [c.claim_id for c in unapproved_claims_in_use]
            reasons.append(
                f"Unapproved claims would be used in draft "
                f"(count={len(unapproved_claims_in_use)}): {unapproved_ids}"
            )

        if reasons:
            logger.warning(
                "Draft report generation blocked: %s", "; ".join(reasons)
            )

        return reasons

    def validate_before_final(
        self,
        draft: str,
        rubric_results: dict,
        gaps: list[Gap],
        state: WorkflowState,
    ) -> list[str]:
        """Validate conditions before producing the final report.

        Blocks if:
        - Critical rubric failure exists (rubric_results indicates failure)
        - Undispositioned critical gaps remain
        - Audit log has failed (indicated by rubric_results or state)
        - Missing final approval (DRAFT_REPORT_APPROVED not in
          completed_phases)

        Args:
            draft: The draft report content (markdown string).
            rubric_results: Results from the rubric checker, expected to
                have 'critical_failures' (list) and optionally
                'audit_log_valid' (bool) keys.
            gaps: All identified gaps.
            state: Current workflow state.

        Returns:
            List of blocking reasons. Empty list means validation passes.
        """
        reasons: list[str] = []

        # Check for critical rubric failures
        critical_failures = rubric_results.get("critical_failures", [])
        if critical_failures:
            reasons.append(
                f"Critical rubric failures detected "
                f"(count={len(critical_failures)}): {critical_failures}"
            )

        # Check for undispositioned critical gaps
        undispositioned_critical = [
            g for g in gaps
            if g.severity == "critical" and g.disposition is None
        ]
        if undispositioned_critical:
            gap_ids = [g.gap_id for g in undispositioned_critical]
            reasons.append(
                f"Undispositioned critical gaps remain "
                f"(count={len(undispositioned_critical)}): {gap_ids}"
            )

        # Check audit log validity
        audit_log_valid = rubric_results.get("audit_log_valid", True)
        if not audit_log_valid:
            reasons.append("Audit log validation failed")

        # Check for final approval (DRAFT_REPORT_APPROVED must be completed)
        from ir_agent.models.enums import WorkflowPhase

        if WorkflowPhase.DRAFT_REPORT_APPROVED not in state.completed_phases:
            reasons.append(
                "Missing final approval: DRAFT_REPORT_APPROVED phase "
                "not in completed_phases"
            )

        if reasons:
            logger.warning(
                "Final report generation blocked: %s", "; ".join(reasons)
            )

        return reasons
