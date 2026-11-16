"""Workflow state management for the IR Reporting Support Agent.

Defines the WorkflowState model, command prerequisite mapping, and
the WorkflowBlockedError exception used by the WorkflowStateService
to enforce correct ordering of CLI commands.

Requirements: 21.1, 21.4
"""

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from ir_agent.models.enums import WorkflowPhase


class WorkflowBlockedError(Exception):
    """Raised when a command cannot execute because prerequisites are not met.

    Attributes:
        command: The command that was attempted.
        missing_phases: Phases that must be completed before the command can run.
        blocked_reasons: Any additional blocking reasons on the workflow state.
    """

    def __init__(
        self,
        command: str,
        missing_phases: list[WorkflowPhase],
        blocked_reasons: Optional[list[str]] = None,
    ) -> None:
        self.command = command
        self.missing_phases = missing_phases
        self.blocked_reasons = blocked_reasons or []

        missing_names = [p.value for p in missing_phases]
        parts = [f"Command '{command}' cannot run: prerequisite phases not completed: {missing_names}"]
        if self.blocked_reasons:
            parts.append(f"Additional blockers: {self.blocked_reasons}")
        super().__init__(". ".join(parts))


class WorkflowState(BaseModel):
    """Represents the current state of the IR workflow for a case.

    Tracks which phases have been completed, what blockers exist,
    and metadata about the last state change.
    """

    case_id: str
    current_phase: WorkflowPhase = WorkflowPhase.CASE_INITIALIZED
    completed_phases: list[WorkflowPhase] = Field(default_factory=list)
    stale_phases: list[WorkflowPhase] = Field(default_factory=list)
    blocked_reasons: list[str] = Field(default_factory=list)
    last_updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_updated_by: Optional[str] = None


# Command prerequisite mapping.
# Each key is a CLI command name; the value is a list of WorkflowPhase
# values that must ALL appear in WorkflowState.completed_phases before
# the command is allowed to execute.
COMMAND_PREREQUISITES: dict[str, list[WorkflowPhase]] = {
    "normalize-events": [WorkflowPhase.ARTIFACTS_INGESTED],
    "extract-candidates": [WorkflowPhase.ARTIFACTS_INGESTED],
    "promote-evidence": [WorkflowPhase.EVIDENCE_CANDIDATES_GENERATED],
    "extract-iocs": [WorkflowPhase.EVIDENCE_LEDGER_APPROVED],
    "build-coverage": [WorkflowPhase.EVIDENCE_LEDGER_APPROVED],
    "build-timeline": [WorkflowPhase.DATA_COVERAGE_BUILT],
    "map-attack": [WorkflowPhase.TIMELINE_BUILT],
    # Upstream-analysis steps (recommended before build-claims; build-claims
    # itself does not require them and falls back to single-evidence claims).
    "ground-evidence-fields": [WorkflowPhase.EVIDENCE_LEDGER_APPROVED],
    "build-correlation-hints": [WorkflowPhase.FIELDS_GROUNDED],
    "validate-analysis-groups": [WorkflowPhase.CORRELATION_HINTS_BUILT],
    "build-claims": [WorkflowPhase.ATTACK_MAPPED, WorkflowPhase.DATA_COVERAGE_BUILT],
    "review-claims": [WorkflowPhase.CLAIMS_GENERATED],
    "check-gaps": [WorkflowPhase.CLAIMS_REVIEWED, WorkflowPhase.DATA_COVERAGE_BUILT],
    "apply-gap-disposition": [WorkflowPhase.GAPS_CHECKED],
    "report-plan": [WorkflowPhase.GAPS_DISPOSITIONED],
    "approve-report-plan": [WorkflowPhase.REPORT_PLAN_GENERATED],
    "draft-report": [WorkflowPhase.REPORT_PLAN_APPROVED],
    "check-draft": [WorkflowPhase.REPORT_PLAN_APPROVED],
    "approve-draft": [WorkflowPhase.DRAFT_REPORT_GENERATED],
    "finalize-report": [WorkflowPhase.DRAFT_REPORT_APPROVED],
}
