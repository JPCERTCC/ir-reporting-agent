"""Property-based tests for Workflow State Machine.

**Validates: Requirements 21.1, 21.4**

Property 6: Workflow Phase Ordering
- No CLI command may execute unless all its prerequisite phases
  (as defined in COMMAND_PREREQUISITES) are in WorkflowState.completed_phases.
- mark_completed advances state correctly.
- Blockers prevent commands from running even with all phases complete.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st
import pytest

from ir_agent.models.enums import WorkflowPhase
from ir_agent.workflow.state import (
    COMMAND_PREREQUISITES,
    WorkflowBlockedError,
    WorkflowState,
)
from ir_agent.workflow.service import WorkflowStateService


# --- Strategies ---

# All workflow phases as a list for sampling
ALL_PHASES = list(WorkflowPhase)

# All commands that have prerequisites
ALL_COMMANDS = list(COMMAND_PREREQUISITES.keys())

# Strategy for a random command from COMMAND_PREREQUISITES
command_st = st.sampled_from(ALL_COMMANDS)

# Strategy for a random workflow phase
phase_st = st.sampled_from(ALL_PHASES)

# Strategy for a subset of phases (possibly empty)
phase_subset_st = st.lists(phase_st, min_size=0, max_size=len(ALL_PHASES), unique=True)

# Strategy for a non-empty blocker reason
blocker_reason_st = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd", "Zs"), whitelist_characters="-_:."),
    min_size=1,
    max_size=50,
)

# Strategy for a case_id
case_id_st = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_"),
    min_size=1,
    max_size=20,
)


# --- Property Tests ---


class TestWorkflowPhaseOrdering:
    """Property 6: Workflow Phase Ordering — command prerequisites enforcement.

    **Validates: Requirements 21.1, 21.4**
    """

    @given(command=command_st, completed_phases=phase_subset_st)
    @settings(max_examples=200, deadline=None)
    def test_missing_prerequisite_blocks_command(
        self, command: str, completed_phases: list[WorkflowPhase]
    ):
        """For any command with prerequisites, assert_can_run raises
        WorkflowBlockedError when ANY prerequisite phase is missing
        from completed_phases.

        **Validates: Requirements 21.1, 21.4**
        """
        required_phases = COMMAND_PREREQUISITES[command]
        # Only test cases where at least one prerequisite is missing
        missing = [p for p in required_phases if p not in completed_phases]
        assume(len(missing) > 0)

        state = WorkflowState(
            case_id="test-case",
            completed_phases=completed_phases,
            blocked_reasons=[],
        )

        service = WorkflowStateService()

        with pytest.raises(WorkflowBlockedError) as exc_info:
            service.assert_can_run(command, state)

        # Verify the error reports the correct missing phases
        for phase in missing:
            assert phase in exc_info.value.missing_phases

    @given(command=command_st, extra_phases=phase_subset_st)
    @settings(max_examples=200, deadline=None)
    def test_all_prerequisites_satisfied_allows_command(
        self, command: str, extra_phases: list[WorkflowPhase]
    ):
        """For any command in COMMAND_PREREQUISITES, assert_can_run does NOT
        raise when ALL prerequisite phases are in completed_phases and
        there are no blockers.

        **Validates: Requirements 21.1, 21.4**
        """
        required_phases = COMMAND_PREREQUISITES[command]
        # Build completed phases: all required + any random extras (deduplicated)
        completed = list(set(required_phases + extra_phases))

        state = WorkflowState(
            case_id="test-case",
            completed_phases=completed,
            blocked_reasons=[],
        )

        service = WorkflowStateService()

        # Should not raise
        service.assert_can_run(command, state)

    @given(phase=phase_st, case_id=case_id_st, analyst_id=st.one_of(st.none(), st.text(min_size=1, max_size=20)))
    @settings(max_examples=150, deadline=None)
    def test_mark_completed_advances_state(
        self, phase: WorkflowPhase, case_id: str, analyst_id: str | None
    ):
        """mark_completed always adds the phase to completed_phases and
        updates current_phase.

        **Validates: Requirements 21.1, 21.4**
        """
        service = WorkflowStateService()
        # Initialize state by loading from a non-existent dir (gets default)
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp_dir:
            service.load_state(Path(tmp_dir))

            service.mark_completed(phase, analyst_id=analyst_id)

            assert service.state is not None
            assert phase in service.state.completed_phases
            assert service.state.current_phase == phase
            if analyst_id is not None:
                assert service.state.last_updated_by == analyst_id

    @given(
        command=command_st,
        blocker=blocker_reason_st,
        extra_phases=phase_subset_st,
    )
    @settings(max_examples=150, deadline=None)
    def test_blocker_prevents_command_even_with_all_phases(
        self, command: str, blocker: str, extra_phases: list[WorkflowPhase]
    ):
        """Blockers prevent any command from running even if all prerequisite
        phases are complete.

        **Validates: Requirements 21.1, 21.4**
        """
        required_phases = COMMAND_PREREQUISITES[command]
        completed = list(set(required_phases + extra_phases))

        state = WorkflowState(
            case_id="test-case",
            completed_phases=completed,
            blocked_reasons=[blocker],
        )

        service = WorkflowStateService()

        with pytest.raises(WorkflowBlockedError) as exc_info:
            service.assert_can_run(command, state)

        assert blocker in exc_info.value.blocked_reasons

    @given(command=command_st, extra_phases=phase_subset_st)
    @settings(max_examples=100, deadline=None)
    def test_stale_prerequisite_blocks_command(
        self, command: str, extra_phases: list[WorkflowPhase]
    ):
        """A command cannot run when one of its completed prerequisites is stale."""
        required_phases = COMMAND_PREREQUISITES[command]
        assume(len(required_phases) > 0)
        stale_phase = required_phases[0]
        completed = list(set(required_phases + extra_phases))

        state = WorkflowState(
            case_id="test-case",
            completed_phases=completed,
            stale_phases=[stale_phase],
            blocked_reasons=[],
        )

        service = WorkflowStateService()

        with pytest.raises(WorkflowBlockedError) as exc_info:
            service.assert_can_run(command, state)

        assert any("stale" in reason for reason in exc_info.value.blocked_reasons)

    @given(
        command=command_st,
        blocker=blocker_reason_st,
        extra_phases=phase_subset_st,
    )
    @settings(max_examples=150, deadline=None)
    def test_clear_blocker_allows_command_again(
        self, command: str, blocker: str, extra_phases: list[WorkflowPhase]
    ):
        """After clear_blocker, the command can run again (assuming all
        prerequisite phases are satisfied).

        **Validates: Requirements 21.1, 21.4**
        """
        required_phases = COMMAND_PREREQUISITES[command]
        completed = list(set(required_phases + extra_phases))

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp_dir:
            service = WorkflowStateService()
            service.load_state(Path(tmp_dir))

            # Overwrite the loaded state with our test state
            service._state = WorkflowState(
                case_id="test-case",
                completed_phases=completed,
                blocked_reasons=[blocker],
            )

            # Verify blocked
            with pytest.raises(WorkflowBlockedError):
                service.assert_can_run(command, service._state)

            # Clear blocker
            service.clear_blocker(blocker)

            # Should now be able to run (no missing phases, no blockers)
            service.assert_can_run(command, service._state)
