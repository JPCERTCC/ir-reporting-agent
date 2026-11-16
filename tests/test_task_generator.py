"""Unit tests for InvestigationTaskGenerator.

Tests task generation from gaps, status updates, and evidence linking.

Requirements: 27.1, 27.2, 27.3, 27.4, 27.5
"""

import pytest

from ir_agent.analysis.task_generator import InvestigationTaskGenerator
from ir_agent.models.analysis import DataCoverageEntry, Gap


def _make_gap(
    gap_id: str = "GAP-001",
    related_claim_id: str = "CLM-001",
    gap_type: str = "missing_evidence",
    severity: str = "critical",
    description: str = "Missing evidence for claim CLM-001",
    recommended_action: str = "Collect additional data",
    disposition: str | None = None,
) -> Gap:
    """Helper to create a Gap for testing."""
    return Gap(
        gap_id=gap_id,
        related_claim_id=related_claim_id,
        gap_type=gap_type,
        severity=severity,
        description=description,
        recommended_action=recommended_action,
        disposition=disposition,
    )


def _make_coverage(
    data_source_id: str = "DC-host01-firewall_log",
    host_or_system: str = "host01",
    data_source_type: str = "firewall_log",
    availability_status: str = "partially_available",
) -> DataCoverageEntry:
    """Helper to create a DataCoverageEntry for testing."""
    return DataCoverageEntry(
        data_source_id=data_source_id,
        host_or_system=host_or_system,
        data_source_type=data_source_type,
        availability_status=availability_status,
    )


class TestGenerateFromGaps:
    """Tests for InvestigationTaskGenerator.generate_from_gaps."""

    def test_generates_task_for_each_gap(self) -> None:
        """Each gap should produce exactly one investigation task."""
        generator = InvestigationTaskGenerator()
        gaps = [
            _make_gap(gap_id="GAP-001", severity="critical"),
            _make_gap(gap_id="GAP-002", severity="major"),
            _make_gap(gap_id="GAP-003", severity="minor"),
        ]

        tasks = generator.generate_from_gaps(gaps, [])

        assert len(tasks) == 3

    def test_task_has_required_fields(self) -> None:
        """Generated tasks must include all required fields per Req 27.2."""
        generator = InvestigationTaskGenerator()
        gap = _make_gap(gap_id="GAP-001", related_claim_id="CLM-042")

        tasks = generator.generate_from_gaps([gap], [])
        task = tasks[0]

        assert task.task_id.startswith("TASK-")
        assert task.related_gap_id == "GAP-001"
        assert task.related_claim_id == "CLM-042"
        assert task.task_description != ""
        assert isinstance(task.suggested_data_sources, list)
        assert task.expected_evidence != ""
        assert task.priority in ("high", "medium", "low")
        assert task.reason != ""
        assert task.status == "proposed"

    def test_priority_maps_from_severity(self) -> None:
        """Task priority should be derived from gap severity. Req 27.3."""
        generator = InvestigationTaskGenerator()

        critical_gap = _make_gap(gap_id="GAP-C", severity="critical")
        major_gap = _make_gap(gap_id="GAP-M", severity="major")
        minor_gap = _make_gap(gap_id="GAP-m", severity="minor")

        tasks = generator.generate_from_gaps(
            [critical_gap, major_gap, minor_gap], []
        )

        assert tasks[0].priority == "high"
        assert tasks[1].priority == "medium"
        assert tasks[2].priority == "low"

    def test_suggested_data_sources_from_gap_type(self) -> None:
        """Tasks should include gap-type-specific data source suggestions."""
        generator = InvestigationTaskGenerator()
        gap = _make_gap(gap_type="unavailable_logs")

        tasks = generator.generate_from_gaps([gap], [])
        task = tasks[0]

        assert len(task.suggested_data_sources) > 0

    def test_suggested_data_sources_include_coverage_suggestions(self) -> None:
        """Tasks should suggest partially available or pending sources."""
        generator = InvestigationTaskGenerator()
        gap = _make_gap(gap_type="missing_evidence")
        coverage = [
            _make_coverage(
                data_source_id="DC-host01-edr",
                host_or_system="host01",
                data_source_type="edr_telemetry",
                availability_status="partially_available",
            ),
            _make_coverage(
                data_source_id="DC-host02-dns",
                host_or_system="host02",
                data_source_type="dns_log",
                availability_status="pending_collection",
            ),
        ]

        tasks = generator.generate_from_gaps([gap], coverage)
        task = tasks[0]

        # Should include coverage-based suggestions
        sources_text = " ".join(task.suggested_data_sources)
        assert "host01" in sources_text or "host02" in sources_text

    def test_initial_status_is_proposed(self) -> None:
        """All generated tasks should start with status 'proposed'. Req 27.4."""
        generator = InvestigationTaskGenerator()
        gap = _make_gap()

        tasks = generator.generate_from_gaps([gap], [])

        assert tasks[0].status == "proposed"

    def test_task_description_varies_by_gap_type(self) -> None:
        """Task descriptions should be tailored to the gap type."""
        generator = InvestigationTaskGenerator()

        gap_missing = _make_gap(gap_id="GAP-A", gap_type="missing_evidence")
        gap_contradiction = _make_gap(gap_id="GAP-B", gap_type="contradictory_evidence")

        tasks = generator.generate_from_gaps([gap_missing, gap_contradiction], [])

        # Descriptions should differ based on gap type
        assert tasks[0].task_description != tasks[1].task_description


class TestUpdateTaskStatus:
    """Tests for InvestigationTaskGenerator.update_task_status."""

    def test_update_status_to_accepted(self) -> None:
        """Task status can be updated to 'accepted'."""
        generator = InvestigationTaskGenerator()
        gap = _make_gap()
        tasks = generator.generate_from_gaps([gap], [])
        task_id = tasks[0].task_id

        generator.update_task_status(task_id, "accepted", "Analyst approved")

        updated = generator.get_task(task_id)
        assert updated is not None
        assert updated.status == "accepted"

    def test_update_status_all_valid_values(self) -> None:
        """All valid status values should be accepted. Req 27.4."""
        valid_statuses = [
            "proposed", "accepted", "rejected", "in_progress",
            "completed", "not_possible", "deferred",
        ]
        generator = InvestigationTaskGenerator()
        gap = _make_gap()
        tasks = generator.generate_from_gaps([gap], [])
        task_id = tasks[0].task_id

        for status in valid_statuses:
            generator.update_task_status(task_id, status, f"Testing {status}")
            updated = generator.get_task(task_id)
            assert updated is not None
            assert updated.status == status

    def test_update_status_invalid_raises_error(self) -> None:
        """Invalid status values should raise ValueError."""
        generator = InvestigationTaskGenerator()
        gap = _make_gap()
        tasks = generator.generate_from_gaps([gap], [])
        task_id = tasks[0].task_id

        with pytest.raises(ValueError, match="Invalid task status"):
            generator.update_task_status(task_id, "invalid_status")

    def test_update_unknown_task_raises_error(self) -> None:
        """Updating a non-existent task should raise ValueError."""
        generator = InvestigationTaskGenerator()

        with pytest.raises(ValueError, match="not found"):
            generator.update_task_status("TASK-nonexistent", "accepted")

    def test_update_preserves_other_fields(self) -> None:
        """Status update should not modify other task fields."""
        generator = InvestigationTaskGenerator()
        gap = _make_gap(gap_id="GAP-X", related_claim_id="CLM-X")
        tasks = generator.generate_from_gaps([gap], [])
        task_id = tasks[0].task_id
        original_description = tasks[0].task_description

        generator.update_task_status(task_id, "in_progress", "Starting work")

        updated = generator.get_task(task_id)
        assert updated is not None
        assert updated.related_gap_id == "GAP-X"
        assert updated.related_claim_id == "CLM-X"
        assert updated.task_description == original_description


class TestLinkTaskToNewEvidence:
    """Tests for InvestigationTaskGenerator.link_task_to_new_evidence."""

    def test_link_evidence_to_task(self) -> None:
        """Linking evidence should record the evidence IDs on the task."""
        generator = InvestigationTaskGenerator()
        gap = _make_gap()
        tasks = generator.generate_from_gaps([gap], [])
        task_id = tasks[0].task_id

        generator.link_task_to_new_evidence(task_id, ["EV-001", "EV-002"])

        updated = generator.get_task(task_id)
        assert updated is not None
        assert "EV-001" in updated.expected_evidence
        assert "EV-002" in updated.expected_evidence

    def test_link_unknown_task_raises_error(self) -> None:
        """Linking evidence to a non-existent task should raise ValueError."""
        generator = InvestigationTaskGenerator()

        with pytest.raises(ValueError, match="not found"):
            generator.link_task_to_new_evidence("TASK-nonexistent", ["EV-001"])

    def test_link_empty_evidence_raises_error(self) -> None:
        """Linking empty evidence list should raise ValueError."""
        generator = InvestigationTaskGenerator()
        gap = _make_gap()
        tasks = generator.generate_from_gaps([gap], [])
        task_id = tasks[0].task_id

        with pytest.raises(ValueError, match="must not be empty"):
            generator.link_task_to_new_evidence(task_id, [])

    def test_link_does_not_auto_resolve_gap(self) -> None:
        """Linking evidence should NOT change task status. Req 27.5."""
        generator = InvestigationTaskGenerator()
        gap = _make_gap()
        tasks = generator.generate_from_gaps([gap], [])
        task_id = tasks[0].task_id

        generator.link_task_to_new_evidence(task_id, ["EV-001"])

        updated = generator.get_task(task_id)
        assert updated is not None
        # Status should remain 'proposed' — not auto-completed
        assert updated.status == "proposed"
