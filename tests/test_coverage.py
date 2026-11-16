"""Unit tests for DataCoverageService.

Validates Requirements 14.1, 14.2, 14.3, 14.4, 14.5:
- Data coverage ledger maintenance (14.1)
- Expected sources initialized from manifest (14.2)
- Availability status values (14.3)
- not_observed blocked when data unavailable or not analyzed (14.4)
- Unavailable data expressed as limitation, not not_observed (14.5)
"""

from pathlib import Path

import pytest

from ir_agent.analysis.coverage import DataCoverageService, DEFAULT_DATA_SOURCE_TYPES
from ir_agent.models.analysis import DataCoverageEntry
from ir_agent.models.base import TimeRange
from ir_agent.steering.manifest import CaseManifest
from ir_agent.storage.store import AppendOnlyStore


# --- Fixtures ---


@pytest.fixture
def tmp_store(tmp_path: Path) -> AppendOnlyStore[DataCoverageEntry]:
    """Create a temporary AppendOnlyStore for DataCoverageEntry."""
    store_path = tmp_path / "data_coverage.jsonl"
    return AppendOnlyStore(file_path=store_path, model_class=DataCoverageEntry)


@pytest.fixture
def service(tmp_store: AppendOnlyStore[DataCoverageEntry]) -> DataCoverageService:
    """Create a DataCoverageService with temporary storage."""
    return DataCoverageService(store=tmp_store)


@pytest.fixture
def sample_manifest() -> CaseManifest:
    """Create a sample CaseManifest for testing."""
    return CaseManifest(
        case_id="CASE-001",
        case_name="Test Investigation",
        scope="Investigate lateral movement on host01 and host02",
        hosts=["host01", "host02"],
        time_range=TimeRange(
            start="2025-05-01T00:00:00Z",
            end="2025-05-31T23:59:59Z",
        ),
    )


@pytest.fixture
def single_host_manifest() -> CaseManifest:
    """Create a manifest with a single host."""
    return CaseManifest(
        case_id="CASE-002",
        case_name="Single Host Case",
        scope="Investigate host01",
        hosts=["host01"],
        time_range=TimeRange(
            start="2025-06-01T00:00:00Z",
            end="2025-06-15T23:59:59Z",
        ),
    )


# --- Tests for initialize_expected_sources ---


class TestInitializeExpectedSources:
    """Tests for DataCoverageService.initialize_expected_sources."""

    def test_creates_entries_for_all_hosts_and_types(
        self, service: DataCoverageService, sample_manifest: CaseManifest
    ):
        """Each host gets an entry for each default data source type."""
        entries = service.initialize_expected_sources(sample_manifest)
        expected_count = len(sample_manifest.hosts) * len(DEFAULT_DATA_SOURCE_TYPES)
        assert len(entries) == expected_count

    def test_entries_have_correct_host(
        self, service: DataCoverageService, sample_manifest: CaseManifest
    ):
        """Each entry references the correct host."""
        entries = service.initialize_expected_sources(sample_manifest)
        hosts_in_entries = {e.host_or_system for e in entries}
        assert hosts_in_entries == set(sample_manifest.hosts)

    def test_entries_have_unknown_status(
        self, service: DataCoverageService, sample_manifest: CaseManifest
    ):
        """New entries start with 'unknown' availability status."""
        entries = service.initialize_expected_sources(sample_manifest)
        for entry in entries:
            assert entry.availability_status == "unknown"

    def test_entries_have_manifest_time_range(
        self, service: DataCoverageService, sample_manifest: CaseManifest
    ):
        """Entries inherit the time range from the manifest."""
        entries = service.initialize_expected_sources(sample_manifest)
        for entry in entries:
            assert entry.covered_time_range == sample_manifest.time_range

    def test_entries_persisted_to_store(
        self,
        service: DataCoverageService,
        sample_manifest: CaseManifest,
        tmp_store: AppendOnlyStore[DataCoverageEntry],
    ):
        """Entries are written to the JSONL store."""
        service.initialize_expected_sources(sample_manifest)
        stored = tmp_store.read_all()
        expected_count = len(sample_manifest.hosts) * len(DEFAULT_DATA_SOURCE_TYPES)
        assert len(stored) == expected_count

    def test_idempotent_initialization(
        self, service: DataCoverageService, sample_manifest: CaseManifest
    ):
        """Calling initialize twice does not duplicate entries."""
        first = service.initialize_expected_sources(sample_manifest)
        second = service.initialize_expected_sources(sample_manifest)
        assert len(second) == 0
        assert len(first) > 0

    def test_data_source_id_format(
        self, service: DataCoverageService, single_host_manifest: CaseManifest
    ):
        """Data source IDs follow DC-{host}-{type} format."""
        entries = service.initialize_expected_sources(single_host_manifest)
        for entry in entries:
            assert entry.data_source_id.startswith("DC-host01-")
            assert entry.data_source_type in entry.data_source_id


# --- Tests for update_from_file_inventory ---


class TestUpdateFromFileInventory:
    """Tests for DataCoverageService.update_from_file_inventory."""

    def test_updates_status_to_available(
        self, service: DataCoverageService, single_host_manifest: CaseManifest
    ):
        """When inventory has matching files, status becomes available."""
        service.initialize_expected_sources(single_host_manifest)

        inventory = [
            {
                "file_id": "FI-001",
                "path": "host01/windows_security.evtx",
                "sha256": "abc123",
                "host": "host01",
                "file_type": "evtx",
                "encoding": "utf-8",
                "line_count": 5000,
                "time_range": {
                    "start": "2025-06-01T00:00:00Z",
                    "end": "2025-06-15T23:59:59Z",
                },
            }
        ]
        updated = service.update_from_file_inventory(inventory)
        assert len(updated) > 0
        assert any(e.availability_status == "available" for e in updated)

    def test_partially_available_when_range_insufficient(
        self, service: DataCoverageService, single_host_manifest: CaseManifest
    ):
        """When files only cover part of expected range, status is partially_available."""
        service.initialize_expected_sources(single_host_manifest)

        # File only covers 3 days of a 15-day investigation
        inventory = [
            {
                "file_id": "FI-001",
                "path": "host01/windows_security.evtx",
                "sha256": "abc123",
                "host": "host01",
                "file_type": "evtx",
                "encoding": "utf-8",
                "line_count": 1000,
                "time_range": {
                    "start": "2025-06-01T00:00:00Z",
                    "end": "2025-06-03T23:59:59Z",
                },
            }
        ]
        updated = service.update_from_file_inventory(inventory)
        assert any(e.availability_status == "partially_available" for e in updated)

    def test_creates_new_entries_for_unknown_sources(
        self, service: DataCoverageService, single_host_manifest: CaseManifest
    ):
        """If inventory has a host not in manifest, creates new entry."""
        service.initialize_expected_sources(single_host_manifest)

        inventory = [
            {
                "file_id": "FI-002",
                "path": "host03/firewall.log",
                "sha256": "def456",
                "host": "host03",
                "file_type": "firewall",
                "encoding": "utf-8",
                "line_count": 2000,
                "time_range": None,
            }
        ]
        updated = service.update_from_file_inventory(inventory)
        host03_entries = [e for e in updated if e.host_or_system == "host03"]
        assert len(host03_entries) > 0


# --- Tests for mark_analyzed ---


class TestMarkAnalyzed:
    """Tests for DataCoverageService.mark_analyzed."""

    def test_marks_source_as_analyzed(self, service: DataCoverageService):
        """After marking analyzed, the range is tracked internally."""
        time_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-15T23:59:59Z"
        )
        service.mark_analyzed("DC-host01-edr_telemetry", time_range)
        # Verify via internal state
        assert "DC-host01-edr_telemetry" in service._analyzed_ranges
        assert len(service._analyzed_ranges["DC-host01-edr_telemetry"]) == 1

    def test_multiple_ranges_accumulated(self, service: DataCoverageService):
        """Multiple calls accumulate analyzed ranges."""
        range1 = TimeRange(start="2025-06-01T00:00:00Z", end="2025-06-07T23:59:59Z")
        range2 = TimeRange(start="2025-06-08T00:00:00Z", end="2025-06-15T23:59:59Z")
        service.mark_analyzed("DC-host01-edr_telemetry", range1)
        service.mark_analyzed("DC-host01-edr_telemetry", range2)
        assert len(service._analyzed_ranges["DC-host01-edr_telemetry"]) == 2


# --- Tests for mark_unavailable ---


class TestMarkUnavailable:
    """Tests for DataCoverageService.mark_unavailable."""

    def test_marks_existing_source_unavailable(
        self, service: DataCoverageService, single_host_manifest: CaseManifest
    ):
        """An existing source can be marked as unavailable."""
        service.initialize_expected_sources(single_host_manifest)
        ds_id = "DC-host01-dns_log"
        service.mark_unavailable(
            ds_id,
            reason="DNS logs not collected by customer",
            impact="Cannot confirm or deny DNS-based C2 communication",
        )
        # Get latest state
        entries = service.get_all_entries()
        dns_entry = next(e for e in entries if e.data_source_id == ds_id)
        assert dns_entry.availability_status == "unavailable"
        assert dns_entry.reason_for_unavailability == "DNS logs not collected by customer"
        assert dns_entry.impact_on_findings == "Cannot confirm or deny DNS-based C2 communication"

    def test_unknown_source_id_logs_warning(
        self, service: DataCoverageService, caplog
    ):
        """Marking an unknown data_source_id logs a warning."""
        service.mark_unavailable(
            "DC-nonexistent-type",
            reason="Test",
            impact="None",
        )
        assert "Cannot mark unknown data_source_id" in caplog.text


# --- Tests for can_support_not_observed (CRITICAL) ---


class TestCanSupportNotObserved:
    """Tests for DataCoverageService.can_support_not_observed.

    This is the critical method that prevents claims of 'not observed'
    when data isn't available or hasn't been analyzed.
    """

    def test_returns_false_when_no_entries_exist(
        self, service: DataCoverageService
    ):
        """Returns False when there are no coverage entries at all."""
        time_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-15T23:59:59Z"
        )
        result = service.can_support_not_observed("host01", "edr_telemetry", time_range)
        assert result is False

    def test_returns_false_when_source_unavailable(
        self, service: DataCoverageService, single_host_manifest: CaseManifest
    ):
        """Returns False when the data source is marked unavailable (Req 14.4)."""
        service.initialize_expected_sources(single_host_manifest)
        ds_id = "DC-host01-edr_telemetry"
        service.mark_unavailable(ds_id, "Not collected", "Cannot confirm")

        time_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-15T23:59:59Z"
        )
        result = service.can_support_not_observed("host01", "edr_telemetry", time_range)
        assert result is False

    def test_returns_false_when_source_unknown(
        self, service: DataCoverageService, single_host_manifest: CaseManifest
    ):
        """Returns False when status is 'unknown' (not yet confirmed available)."""
        service.initialize_expected_sources(single_host_manifest)

        time_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-15T23:59:59Z"
        )
        result = service.can_support_not_observed("host01", "edr_telemetry", time_range)
        assert result is False

    def test_returns_false_when_available_but_not_analyzed(
        self,
        service: DataCoverageService,
        single_host_manifest: CaseManifest,
    ):
        """Returns False when source is available but NOT analyzed (Req 14.4)."""
        service.initialize_expected_sources(single_host_manifest)

        # Update to available via inventory
        inventory = [
            {
                "file_id": "FI-001",
                "path": "host01/edr.csv",
                "sha256": "abc",
                "host": "host01",
                "file_type": "edr_csv",
                "encoding": "utf-8",
                "line_count": 1000,
                "time_range": {
                    "start": "2025-06-01T00:00:00Z",
                    "end": "2025-06-15T23:59:59Z",
                },
            }
        ]
        service.update_from_file_inventory(inventory)

        time_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-15T23:59:59Z"
        )
        # Available but NOT analyzed
        result = service.can_support_not_observed("host01", "edr_telemetry", time_range)
        assert result is False

    def test_returns_true_when_available_and_analyzed(
        self,
        service: DataCoverageService,
        single_host_manifest: CaseManifest,
    ):
        """Returns True ONLY when data is available AND analyzed (Req 14.4)."""
        service.initialize_expected_sources(single_host_manifest)

        # Update to available
        inventory = [
            {
                "file_id": "FI-001",
                "path": "host01/edr.csv",
                "sha256": "abc",
                "host": "host01",
                "file_type": "edr_csv",
                "encoding": "utf-8",
                "line_count": 1000,
                "time_range": {
                    "start": "2025-06-01T00:00:00Z",
                    "end": "2025-06-15T23:59:59Z",
                },
            }
        ]
        service.update_from_file_inventory(inventory)

        # Mark as analyzed
        analyzed_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-15T23:59:59Z"
        )
        service.mark_analyzed("DC-host01-edr_telemetry", analyzed_range)

        time_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-15T23:59:59Z"
        )
        result = service.can_support_not_observed("host01", "edr_telemetry", time_range)
        assert result is True

    def test_returns_false_when_partially_available(
        self,
        service: DataCoverageService,
        single_host_manifest: CaseManifest,
    ):
        """Returns False for partially_available sources (Req 14.5)."""
        service.initialize_expected_sources(single_host_manifest)

        # Only partial coverage
        inventory = [
            {
                "file_id": "FI-001",
                "path": "host01/edr.csv",
                "sha256": "abc",
                "host": "host01",
                "file_type": "edr_csv",
                "encoding": "utf-8",
                "line_count": 100,
                "time_range": {
                    "start": "2025-06-01T00:00:00Z",
                    "end": "2025-06-03T23:59:59Z",
                },
            }
        ]
        service.update_from_file_inventory(inventory)

        # Even if analyzed
        analyzed_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-03T23:59:59Z"
        )
        service.mark_analyzed("DC-host01-edr_telemetry", analyzed_range)

        # Request covers full investigation period
        time_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-15T23:59:59Z"
        )
        result = service.can_support_not_observed("host01", "edr_telemetry", time_range)
        assert result is False

    def test_returns_false_when_analyzed_range_insufficient(
        self,
        service: DataCoverageService,
        single_host_manifest: CaseManifest,
    ):
        """Returns False when analyzed range doesn't cover the requested range."""
        service.initialize_expected_sources(single_host_manifest)

        # Full coverage available
        inventory = [
            {
                "file_id": "FI-001",
                "path": "host01/edr.csv",
                "sha256": "abc",
                "host": "host01",
                "file_type": "edr_csv",
                "encoding": "utf-8",
                "line_count": 5000,
                "time_range": {
                    "start": "2025-06-01T00:00:00Z",
                    "end": "2025-06-15T23:59:59Z",
                },
            }
        ]
        service.update_from_file_inventory(inventory)

        # Only analyzed first week
        analyzed_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-07T23:59:59Z"
        )
        service.mark_analyzed("DC-host01-edr_telemetry", analyzed_range)

        # Request covers full 15 days
        time_range = TimeRange(
            start="2025-06-01T00:00:00Z", end="2025-06-15T23:59:59Z"
        )
        result = service.can_support_not_observed("host01", "edr_telemetry", time_range)
        assert result is False


# --- Tests for get_relevant_coverage ---


class TestGetRelevantCoverage:
    """Tests for DataCoverageService.get_relevant_coverage."""

    def test_returns_matching_entries(
        self, service: DataCoverageService, sample_manifest: CaseManifest
    ):
        """Returns entries matching host and type."""
        service.initialize_expected_sources(sample_manifest)
        time_range = TimeRange(
            start="2025-05-10T00:00:00Z", end="2025-05-20T23:59:59Z"
        )
        entries = service.get_relevant_coverage("host01", "edr_telemetry", time_range)
        assert len(entries) == 1
        assert entries[0].host_or_system == "host01"
        assert entries[0].data_source_type == "edr_telemetry"

    def test_returns_empty_for_nonexistent_host(
        self, service: DataCoverageService, sample_manifest: CaseManifest
    ):
        """Returns empty list for a host not in the coverage ledger."""
        service.initialize_expected_sources(sample_manifest)
        time_range = TimeRange(
            start="2025-05-10T00:00:00Z", end="2025-05-20T23:59:59Z"
        )
        entries = service.get_relevant_coverage("host99", "edr_telemetry", time_range)
        assert entries == []


# --- Tests for get_all_entries ---


class TestGetAllEntries:
    """Tests for DataCoverageService.get_all_entries."""

    def test_returns_latest_state(
        self, service: DataCoverageService, single_host_manifest: CaseManifest
    ):
        """Returns latest state per data source after updates."""
        service.initialize_expected_sources(single_host_manifest)
        ds_id = "DC-host01-dns_log"
        service.mark_unavailable(ds_id, "Not collected", "Impact")

        entries = service.get_all_entries()
        dns_entry = next(e for e in entries if e.data_source_id == ds_id)
        assert dns_entry.availability_status == "unavailable"
