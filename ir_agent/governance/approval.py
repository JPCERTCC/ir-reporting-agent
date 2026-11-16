"""Approval Gate for the Governance Layer.

Enforces human approval gates by maintaining an in-memory registry of
approval decisions and persisting all decisions through the AuditLogger.

Requirements: 7.6, 12.8, 17.4
- 7.6: The Evidence_Layer SHALL not promote any candidate without explicit Analyst approval
- 12.8: The Governance_Layer SHALL log all Claim review decisions in the audit log
- 17.4: The Reporting_Layer SHALL not produce a final report without explicit Analyst approval
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ir_agent.governance.audit import AuditLogger
from ir_agent.models.governance import ApprovalEntry

logger = logging.getLogger(__name__)

# Valid approval decisions
VALID_DECISIONS = frozenset({"approved", "rejected", "edited", "needs_more_context"})


class ApprovalGate:
    """Enforces human approval gates for evidence, claims, and reports.

    Design invariants:
    - No item proceeds without explicit approval (Requirements 7.6, 17.4).
    - All approval decisions are logged via AuditLogger (Requirement 12.8).
    - The gate maintains an in-memory registry keyed by (item_type, item_id).
    - Only items with decision == "approved" or "edited" pass require_approval.
    """

    def __init__(self, audit_logger: AuditLogger) -> None:
        """Initialize the ApprovalGate.

        Args:
            audit_logger: An AuditLogger instance for persisting approval decisions.
        """
        self._audit_logger = audit_logger
        # Registry: (item_type, item_id) -> decision string
        self._registry: dict[tuple[str, str], str] = {}

    def require_approval(self, item_type: str, item_id: str) -> bool:
        """Check whether a given item has been approved.

        An item is considered approved if its recorded decision is
        "approved" or "edited" (editing implies approval with changes).

        Args:
            item_type: The type of item (e.g., "evidence_candidate", "claim",
                "draft_report").
            item_id: The unique identifier of the item.

        Returns:
            True if the item has been approved (decision is "approved" or
            "edited"), False otherwise.
        """
        decision = self._registry.get((item_type, item_id))
        return decision in ("approved", "edited")

    def record_approval(
        self,
        analyst_id: str,
        item_type: str,
        item_id: str,
        decision: str,
        reason: Optional[str] = None,
    ) -> None:
        """Record an approval decision and persist it via the AuditLogger.

        The decision is stored in the in-memory registry and simultaneously
        logged to the audit trail for full traceability.

        Args:
            analyst_id: Identifier of the analyst making the decision.
            item_type: The type of item being reviewed.
            item_id: The unique identifier of the item.
            decision: One of "approved", "rejected", "edited",
                "needs_more_context".
            reason: Optional reason for the decision.

        Raises:
            ValueError: If the decision is not one of the valid options.
            AuditWriteError: If the audit log write fails (halts operation).
        """
        if decision not in VALID_DECISIONS:
            raise ValueError(
                f"Invalid decision '{decision}'. "
                f"Must be one of: {', '.join(sorted(VALID_DECISIONS))}"
            )

        # Store in the in-memory registry
        self._registry[(item_type, item_id)] = decision

        # Create and persist the approval entry via AuditLogger
        entry = ApprovalEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            analyst_id=analyst_id,
            item_type=item_type,
            item_id=item_id,
            decision=decision,
            reason=reason,
        )
        self._audit_logger.log_approval(entry)

        logger.info(
            "Approval recorded: analyst=%s, item_type=%s, item_id=%s, decision=%s",
            analyst_id,
            item_type,
            item_id,
            decision,
        )

    def get_decision(self, item_type: str, item_id: str) -> Optional[str]:
        """Get the current decision for an item, if any.

        Args:
            item_type: The type of item.
            item_id: The unique identifier of the item.

        Returns:
            The decision string if a decision has been recorded, None otherwise.
        """
        return self._registry.get((item_type, item_id))
