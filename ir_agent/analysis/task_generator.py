"""Investigation Task Generator for the Analysis Layer.

Generates follow-up investigation tasks from identified gaps and weak claims.
Tasks guide the analyst on what additional evidence to collect or document
to address identified gaps.

The generator uses gap severity and data coverage information to:
- Determine task priority
- Suggest relevant data sources for evidence collection
- Track task lifecycle from proposed through completion

Requirements: 27.1, 27.2, 27.3, 27.4, 27.5
"""

from __future__ import annotations

import logging
from typing import Optional
from uuid import uuid4

from ir_agent.models.analysis import DataCoverageEntry, Gap, InvestigationTask

logger = logging.getLogger(__name__)

# Mapping from gap severity to default task priority
_SEVERITY_TO_PRIORITY: dict[str, str] = {
    "critical": "high",
    "major": "medium",
    "minor": "low",
}

# Valid task statuses per Requirement 27.4
_VALID_STATUSES: set[str] = {
    "proposed",
    "accepted",
    "rejected",
    "in_progress",
    "completed",
    "not_possible",
    "deferred",
}

# Gap types that suggest specific data source actions
_GAP_TYPE_DATA_SOURCES: dict[str, list[str]] = {
    "missing_evidence": [
        "Additional forensic artifacts",
        "Endpoint detection logs",
        "Network traffic captures",
    ],
    "weak_evidence": [
        "Corroborating log sources",
        "Independent system telemetry",
    ],
    "single_source": [
        "Independent verification source",
        "Alternative log system for same host",
    ],
    "unavailable_logs": [
        "Backup or archived log storage",
        "Alternative monitoring system",
        "Cloud-based log aggregation",
    ],
    "logs_outside_scope": [
        "Extended scope approval for relevant logs",
        "Summary reports from adjacent systems",
    ],
    "logs_not_analyzed": [
        "Pending log source (prioritize analysis)",
    ],
    "contradictory_evidence": [
        "Additional independent sources to resolve contradiction",
        "Detailed forensic analysis of conflicting artifacts",
    ],
}


class InvestigationTaskGenerator:
    """Generates investigation tasks from identified gaps.

    When the GapChecker identifies missing or weak evidence, this generator
    creates InvestigationTasks that guide the analyst on:
    - What evidence to collect
    - Where to look for it (suggested data sources)
    - How urgent it is (priority based on gap severity)

    Tasks track their lifecycle from proposed through completion and
    can be linked to new evidence when collected.

    Requirements: 27.1, 27.2, 27.3, 27.4, 27.5
    """

    def __init__(self) -> None:
        """Initialize the InvestigationTaskGenerator.

        Maintains an internal registry of generated tasks for status
        tracking and evidence linking.
        """
        self._tasks: dict[str, InvestigationTask] = {}

    def generate_from_gaps(
        self,
        gaps: list[Gap],
        coverage: list[DataCoverageEntry],
    ) -> list[InvestigationTask]:
        """Generate investigation tasks from identified gaps.

        For each gap, creates an InvestigationTask with appropriate priority
        (derived from gap severity), suggested data sources (based on gap type
        and available coverage information), and a description of what evidence
        is expected.

        Requirement 27.1: When the Gap_Checker identifies missing or weak
        evidence, generate Investigation_Tasks.
        Requirement 27.2: Each task includes task_id, related_gap_id,
        related_claim_id, task_description, suggested_data_sources,
        expected_evidence, priority, reason, status.
        Requirement 27.3: Priority is one of: high, medium, low.

        Args:
            gaps: List of gaps identified by the GapChecker.
            coverage: Data coverage entries for suggesting data sources.

        Returns:
            List of generated InvestigationTask records.
        """
        tasks: list[InvestigationTask] = []

        for gap in gaps:
            task = self._generate_task_for_gap(gap, coverage)
            self._tasks[task.task_id] = task
            tasks.append(task)

        return tasks

    def update_task_status(
        self,
        task_id: str,
        status: str,
        reason: Optional[str] = None,
    ) -> None:
        """Update the status of an investigation task.

        Requirement 27.4: Status is one of: proposed, accepted, rejected,
        in_progress, completed, not_possible, deferred.
        Requirement 27.5: The Agent SHALL NOT automatically mark a Gap as
        resolved unless the related Investigation_Task produces approved
        Evidence or the Analyst explicitly accepts the Gap as a limitation.

        Args:
            task_id: The identifier of the task to update.
            status: New status value. Must be a valid task status.
            reason: Optional reason for the status change.

        Raises:
            ValueError: If task_id is not found or status is invalid.
        """
        if status not in _VALID_STATUSES:
            raise ValueError(
                f"Invalid task status '{status}'. "
                f"Must be one of: {', '.join(sorted(_VALID_STATUSES))}"
            )

        if task_id not in self._tasks:
            raise ValueError(
                f"Task '{task_id}' not found in task registry."
            )

        task = self._tasks[task_id]
        # Create updated task with new status
        updated_task = InvestigationTask(
            task_id=task.task_id,
            related_gap_id=task.related_gap_id,
            related_claim_id=task.related_claim_id,
            task_description=task.task_description,
            suggested_data_sources=task.suggested_data_sources,
            expected_evidence=task.expected_evidence,
            priority=task.priority,
            reason=reason if reason else task.reason,
            status=status,
        )
        self._tasks[task_id] = updated_task

        logger.info(
            "Updated task %s status to '%s' (reason: %s)",
            task_id,
            status,
            reason or "none",
        )

    def link_task_to_new_evidence(
        self,
        task_id: str,
        evidence_ids: list[str],
    ) -> None:
        """Link an investigation task to newly collected evidence.

        When new evidence is collected that addresses a task, this method
        records the link. Note that this does NOT automatically resolve the
        gap — the analyst must still explicitly approve the evidence and
        disposition the gap.

        Requirement 27.5: The Agent SHALL NOT automatically mark a Gap as
        resolved unless the related Investigation_Task produces approved
        Evidence or the Analyst explicitly accepts the Gap as a limitation.

        Args:
            task_id: The identifier of the task to link.
            evidence_ids: List of evidence IDs collected for this task.

        Raises:
            ValueError: If task_id is not found or evidence_ids is empty.
        """
        if task_id not in self._tasks:
            raise ValueError(
                f"Task '{task_id}' not found in task registry."
            )

        if not evidence_ids:
            raise ValueError(
                "evidence_ids must not be empty when linking to a task."
            )

        task = self._tasks[task_id]

        # Update expected_evidence to note the linked evidence
        linked_info = (
            f"{task.expected_evidence} "
            f"[Linked evidence: {', '.join(evidence_ids)}]"
        )

        updated_task = InvestigationTask(
            task_id=task.task_id,
            related_gap_id=task.related_gap_id,
            related_claim_id=task.related_claim_id,
            task_description=task.task_description,
            suggested_data_sources=task.suggested_data_sources,
            expected_evidence=linked_info,
            priority=task.priority,
            reason=task.reason,
            status=task.status,
        )
        self._tasks[task_id] = updated_task

        logger.info(
            "Linked task %s to evidence: %s",
            task_id,
            ", ".join(evidence_ids),
        )

    def get_task(self, task_id: str) -> Optional[InvestigationTask]:
        """Retrieve a task by its ID.

        Args:
            task_id: The task identifier.

        Returns:
            The InvestigationTask if found, None otherwise.
        """
        return self._tasks.get(task_id)

    def get_all_tasks(self) -> list[InvestigationTask]:
        """Return all generated tasks.

        Returns:
            List of all InvestigationTask records.
        """
        return list(self._tasks.values())

    # --- Private helper methods ---

    def _generate_task_for_gap(
        self,
        gap: Gap,
        coverage: list[DataCoverageEntry],
    ) -> InvestigationTask:
        """Generate a single investigation task for a gap.

        Determines priority from gap severity, builds suggested data sources
        from gap type and coverage entries, and creates the task description.

        Args:
            gap: The gap to generate a task for.
            coverage: Available data coverage entries.

        Returns:
            A new InvestigationTask record.
        """
        task_id = f"TASK-{uuid4().hex[:8]}"
        priority = _SEVERITY_TO_PRIORITY.get(gap.severity, "medium")

        # Build suggested data sources from gap type defaults and coverage
        suggested_sources = self._suggest_data_sources(gap, coverage)

        # Build task description from gap information
        task_description = self._build_task_description(gap)

        # Build expected evidence description
        expected_evidence = self._build_expected_evidence(gap)

        # Build reason from gap context
        reason = (
            f"Gap '{gap.gap_id}' ({gap.gap_type}, severity: {gap.severity}) "
            f"affects claim '{gap.related_claim_id}'. {gap.description}"
        )

        return InvestigationTask(
            task_id=task_id,
            related_gap_id=gap.gap_id,
            related_claim_id=gap.related_claim_id,
            task_description=task_description,
            suggested_data_sources=suggested_sources,
            expected_evidence=expected_evidence,
            priority=priority,
            reason=reason,
            status="proposed",
        )

    def _suggest_data_sources(
        self,
        gap: Gap,
        coverage: list[DataCoverageEntry],
    ) -> list[str]:
        """Suggest data sources for resolving a gap.

        Combines generic suggestions based on gap type with specific
        suggestions from the coverage ledger (e.g., partially available
        or pending sources that could help).

        Args:
            gap: The gap needing resolution.
            coverage: Data coverage entries for context.

        Returns:
            List of suggested data source descriptions.
        """
        suggestions: list[str] = []

        # Add gap-type-specific suggestions
        type_suggestions = _GAP_TYPE_DATA_SOURCES.get(gap.gap_type, [])
        suggestions.extend(type_suggestions)

        # Add coverage-based suggestions
        for entry in coverage:
            if entry.availability_status == "partially_available":
                suggestions.append(
                    f"Complete collection of {entry.data_source_type} "
                    f"from {entry.host_or_system}"
                )
            elif entry.availability_status == "pending_collection":
                suggestions.append(
                    f"Prioritize collection of {entry.data_source_type} "
                    f"from {entry.host_or_system}"
                )

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_suggestions: list[str] = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique_suggestions.append(s)

        return unique_suggestions

    def _build_task_description(self, gap: Gap) -> str:
        """Build a human-readable task description from gap information.

        Args:
            gap: The gap to describe.

        Returns:
            Task description string.
        """
        descriptions: dict[str, str] = {
            "missing_evidence": (
                f"Collect missing evidence for claim '{gap.related_claim_id}'. "
                f"{gap.recommended_action}"
            ),
            "weak_evidence": (
                f"Strengthen evidence for claim '{gap.related_claim_id}' "
                f"by obtaining additional corroborating sources. "
                f"{gap.recommended_action}"
            ),
            "single_source": (
                f"Obtain independent corroboration for claim "
                f"'{gap.related_claim_id}' which relies on a single source. "
                f"{gap.recommended_action}"
            ),
            "unavailable_logs": (
                f"Attempt to obtain unavailable log data relevant to claim "
                f"'{gap.related_claim_id}'. {gap.recommended_action}"
            ),
            "logs_outside_scope": (
                f"Evaluate whether out-of-scope logs for claim "
                f"'{gap.related_claim_id}' should be included. "
                f"{gap.recommended_action}"
            ),
            "logs_not_analyzed": (
                f"Prioritize analysis of pending data sources relevant to "
                f"claim '{gap.related_claim_id}'. {gap.recommended_action}"
            ),
            "contradictory_evidence": (
                f"Resolve contradictory evidence affecting claim "
                f"'{gap.related_claim_id}'. {gap.recommended_action}"
            ),
        }

        return descriptions.get(
            gap.gap_type,
            f"Address gap for claim '{gap.related_claim_id}'. "
            f"{gap.recommended_action}",
        )

    def _build_expected_evidence(self, gap: Gap) -> str:
        """Build a description of expected evidence outcome.

        Args:
            gap: The gap to describe expected evidence for.

        Returns:
            Expected evidence description string.
        """
        expected: dict[str, str] = {
            "missing_evidence": (
                "Evidence confirming or refuting the claim assertion, "
                "or documentation that the evidence cannot be obtained."
            ),
            "weak_evidence": (
                "Additional independent evidence sources that corroborate "
                "or contradict the current assertion."
            ),
            "single_source": (
                "At least one independent source corroborating the existing "
                "evidence, or documented justification for single-source reliance."
            ),
            "unavailable_logs": (
                "The missing log data, an alternative data source providing "
                "equivalent information, or documentation of unavailability."
            ),
            "logs_outside_scope": (
                "Scope expansion approval and relevant log data, or "
                "documented justification for maintaining current scope."
            ),
            "logs_not_analyzed": (
                "Analysis results from the pending data source, identifying "
                "any relevant evidence for the claim."
            ),
            "contradictory_evidence": (
                "Resolution of the contradiction through additional evidence, "
                "expert analysis, or documented acceptance of uncertainty."
            ),
        }

        return expected.get(
            gap.gap_type,
            "Evidence addressing the identified gap, or documentation "
            "that the gap cannot be resolved.",
        )
