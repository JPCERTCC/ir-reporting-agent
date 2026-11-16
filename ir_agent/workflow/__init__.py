"""Workflow State Service.

Manages the workflow state machine that enforces correct ordering of
CLI commands and transitions between investigation phases.
"""

from ir_agent.workflow.service import WorkflowStateService
from ir_agent.workflow.state import (
    COMMAND_PREREQUISITES,
    WorkflowBlockedError,
    WorkflowState,
)

__all__ = [
    "COMMAND_PREREQUISITES",
    "WorkflowBlockedError",
    "WorkflowState",
    "WorkflowStateService",
]
