"""WorkflowStateService for the IR Reporting Support Agent.

Provides persistence and enforcement logic for the workflow state machine.
Loads/saves state from JSON, checks command prerequisites, manages blockers,
and marks phases as completed.

Requirements: 21.1, 21.4
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ir_agent.models.enums import WorkflowPhase
from ir_agent.workflow.state import (
    COMMAND_PREREQUISITES,
    WorkflowBlockedError,
    WorkflowState,
)

WORKFLOW_STATE_FILENAME = "workflow_state.json"


class WorkflowStateService:
    """Service for managing workflow state persistence and enforcement.

    Provides methods to load/save state, check command prerequisites,
    mark phases as completed, and manage workflow blockers.
    """

    def __init__(self) -> None:
        self._state: Optional[WorkflowState] = None

    @property
    def state(self) -> Optional[WorkflowState]:
        """Return the currently loaded workflow state."""
        return self._state

    def load_state(self, case_dir: Path) -> WorkflowState:
        """Load workflow state from the case directory.

        Reads `workflow_state.json` from the given case directory.
        If the file does not exist, returns a default state with
        CASE_INITIALIZED phase and empty completed_phases.

        Args:
            case_dir: Path to the case directory.

        Returns:
            The loaded or default WorkflowState.
        """
        state_path = Path(case_dir) / WORKFLOW_STATE_FILENAME

        if not state_path.exists():
            self._state = WorkflowState(
                case_id=Path(case_dir).name,
                current_phase=WorkflowPhase.CASE_INITIALIZED,
                completed_phases=[],
                stale_phases=[],
                blocked_reasons=[],
                last_updated_at=datetime.now(timezone.utc).isoformat(),
                last_updated_by=None,
            )
            return self._state

        with open(state_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self._state = WorkflowState(**data)
        return self._state

    def save_state(self, case_dir: Path, state: WorkflowState) -> None:
        """Persist workflow state to JSON in the case directory.

        Writes the state to `workflow_state.json` in the given case directory.

        Args:
            case_dir: Path to the case directory.
            state: The WorkflowState to persist.
        """
        state_path = Path(case_dir) / WORKFLOW_STATE_FILENAME
        state_path.parent.mkdir(parents=True, exist_ok=True)

        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(state.model_dump(), f, indent=2, ensure_ascii=False)

        self._state = state

    def assert_can_run(self, command: str, state: WorkflowState) -> None:
        """Check if a command can execute given the current workflow state.

        Raises WorkflowBlockedError if:
        - The command has prerequisite phases that are not yet completed.
        - The workflow state has unresolved blockers.

        Commands not listed in COMMAND_PREREQUISITES are assumed to have
        no prerequisites and can always run (unless blockers exist).

        Args:
            command: The CLI command name to check.
            state: The current WorkflowState.

        Raises:
            WorkflowBlockedError: If prerequisites are not met or blockers exist.
        """
        required_phases = COMMAND_PREREQUISITES.get(command, [])
        missing_phases = [
            phase for phase in required_phases
            if phase not in state.completed_phases
        ]
        stale_prerequisites = [
            phase for phase in required_phases
            if phase in state.stale_phases
        ]

        blocked_reasons = state.blocked_reasons if state.blocked_reasons else []
        if stale_prerequisites:
            stale_names = ", ".join(phase.value for phase in stale_prerequisites)
            blocked_reasons = [
                *blocked_reasons,
                f"Prerequisite phase is stale and must be rerun: {stale_names}",
            ]

        if missing_phases or blocked_reasons:
            raise WorkflowBlockedError(
                command=command,
                missing_phases=missing_phases,
                blocked_reasons=blocked_reasons,
            )

    def mark_completed(
        self, phase: WorkflowPhase, analyst_id: Optional[str] = None
    ) -> None:
        """Mark a workflow phase as completed and update state metadata.

        Updates current_phase, appends to completed_phases (if not already
        present), and records the timestamp and analyst who completed it.

        Args:
            phase: The WorkflowPhase that was completed.
            analyst_id: Optional identifier of the analyst who completed the phase.

        Raises:
            RuntimeError: If no state has been loaded yet.
        """
        if self._state is None:
            raise RuntimeError(
                "No workflow state loaded. Call load_state() first."
            )

        self._state.current_phase = phase
        if phase not in self._state.completed_phases:
            self._state.completed_phases.append(phase)
        if phase in self._state.stale_phases:
            self._state.stale_phases.remove(phase)
        self._state.last_updated_at = datetime.now(timezone.utc).isoformat()
        self._state.last_updated_by = analyst_id

    def mark_stale(
        self, phases: list[WorkflowPhase], analyst_id: Optional[str] = None
    ) -> None:
        """Mark completed downstream phases as stale after input changes."""
        if self._state is None:
            raise RuntimeError(
                "No workflow state loaded. Call load_state() first."
            )

        for phase in phases:
            if (
                phase in self._state.completed_phases
                and phase not in self._state.stale_phases
            ):
                self._state.stale_phases.append(phase)
        self._state.last_updated_at = datetime.now(timezone.utc).isoformat()
        self._state.last_updated_by = analyst_id

    def add_blocker(self, reason: str) -> None:
        """Add a blocking reason to the workflow state.

        Blockers prevent commands from executing even if phase
        prerequisites are met.

        Args:
            reason: A description of the blocking condition.

        Raises:
            RuntimeError: If no state has been loaded yet.
        """
        if self._state is None:
            raise RuntimeError(
                "No workflow state loaded. Call load_state() first."
            )

        if reason not in self._state.blocked_reasons:
            self._state.blocked_reasons.append(reason)

    def clear_blocker(self, reason: str) -> None:
        """Remove a blocking reason from the workflow state.

        Args:
            reason: The blocking reason to remove.

        Raises:
            RuntimeError: If no state has been loaded yet.
        """
        if self._state is None:
            raise RuntimeError(
                "No workflow state loaded. Call load_state() first."
            )

        if reason in self._state.blocked_reasons:
            self._state.blocked_reasons.remove(reason)

    def has_unresolved_blockers(self) -> bool:
        """Check if the workflow state has any unresolved blockers.

        Returns:
            True if there are one or more blocking reasons, False otherwise.

        Raises:
            RuntimeError: If no state has been loaded yet.
        """
        if self._state is None:
            raise RuntimeError(
                "No workflow state loaded. Call load_state() first."
            )

        return len(self._state.blocked_reasons) > 0
