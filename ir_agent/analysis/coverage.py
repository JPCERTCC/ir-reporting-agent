"""Data Coverage Service for the Analysis Layer.

Manages a data coverage ledger that tracks available/unavailable data sources
for an investigation. Distinguishes between "not observed" (data analyzed but
event not found) and "not available" (data source missing or inaccessible).

The critical method `can_support_not_observed()` returns True ONLY when the
data source is available for the relevant time range AND has been analyzed.
This prevents claims of "not observed" when data isn't even available.

Requirements: 14.1, 14.2, 14.3, 14.4, 14.5
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional
from uuid import uuid4

from dateutil import parser as dateutil_parser

from ir_agent.models.analysis import DataCoverageEntry
from ir_agent.models.base import TimeRange
from ir_agent.steering.manifest import CaseManifest
from ir_agent.storage.store import AppendOnlyStore

logger = logging.getLogger(__name__)

# Default expected data source types for hosts in an investigation
DEFAULT_DATA_SOURCE_TYPES = [
    "windows_event_log",
    "edr_telemetry",
    "network_flow",
    "firewall_log",
    "dns_log",
    "proxy_log",
]

# Ordered (substring, data_source_type) rules for inferring the data source
# type of an artifact from its source path. First match wins. Used both to
# derive coverage from analyzed evidence and to determine which coverage
# entries are relevant to a claim's supporting evidence, so both sides agree
# on the type of a given source. Requirement UP-02.
_DS_TYPE_PATH_RULES: list[tuple[str, str]] = [
    ("ssl-vpn", "network_flow"),
    ("vpn", "network_flow"),
    ("fw_session", "firewall_log"),
    ("firewall", "firewall_log"),
    ("edr", "edr_telemetry"),
    ("process_network", "edr_telemetry"),
    ("dns", "dns_log"),
    ("proxy", "proxy_log"),
    ("bash_history", "shell_history"),
    ("syslog", "syslog"),
    ("file_access", "file_access"),
    ("amcache", "amcache"),
    ("registry", "registry"),
    (".reg", "registry"),
    ("netstat", "netstat"),
    ("task", "scheduled_tasks"),
    ("mft", "mft"),
    (".e01", "disk_image"),
    ("forensic", "disk_image"),
    ("evtx", "windows_event_log"),
    ("security", "windows_event_log"),
    ("event", "windows_event_log"),
]


def latest_coverage(entries: list[DataCoverageEntry]) -> list[DataCoverageEntry]:
    """Collapse an append-only coverage log to the current state per source.

    ``data_coverage.jsonl`` is append-only, so a source that was first
    recorded as ``unknown`` and later reclassified (for example to
    ``outside_scope`` once the artifact set showed it was never provided)
    has several records. Consumers that read every line would count the
    same data source twice under contradictory statuses, so the last
    record per ``data_source_id`` wins.
    """
    latest: dict[str, DataCoverageEntry] = {}
    for entry in entries:
        latest[entry.data_source_id] = entry
    return list(latest.values())


def infer_data_source_type(source_path: str) -> str:
    """Infer a data source type from an artifact source path.

    Returns a stable data_source_type string for the given path. The exact
    value matters less than its consistency: the same path always maps to the
    same type, so coverage derived from analyzed evidence and the coverage
    relevant to a claim built from that evidence agree. Unrecognized paths map
    to ``host_artifact``.
    """
    p = (source_path or "").lower()
    for needle, ds_type in _DS_TYPE_PATH_RULES:
        if needle in p:
            return ds_type
    return "host_artifact"


class DataCoverageService:
    """Manages the data coverage ledger for investigation data sources.

    Tracks which data sources are available, unavailable, or partially
    available for each host in the investigation. Uses an AppendOnlyStore
    backed by JSONL for persistence.

    Requirements: 14.1, 14.2, 14.3, 14.4, 14.5
    """

    def __init__(self, store: AppendOnlyStore[DataCoverageEntry]) -> None:
        """Initialize the DataCoverageService.

        Args:
            store: An AppendOnlyStore configured for DataCoverageEntry records.
        """
        self._store = store
        # Internal tracking of analyzed time ranges per data_source_id.
        # This supplements the JSONL store to track which sources have
        # been fully analyzed.
        self._analyzed_ranges: dict[str, list[TimeRange]] = {}

    @classmethod
    def from_case_dir(cls, case_dir: Path) -> DataCoverageService:
        """Create a DataCoverageService with storage at the standard path.

        Args:
            case_dir: Path to the case working directory.

        Returns:
            A configured DataCoverageService instance.
        """
        store_path = case_dir / "data" / "data_coverage.jsonl"
        store = AppendOnlyStore(file_path=store_path, model_class=DataCoverageEntry)
        return cls(store=store)

    def initialize_expected_sources(
        self, manifest: CaseManifest
    ) -> list[DataCoverageEntry]:
        """Create initial coverage entries from manifest hosts.

        For each host in the manifest, creates a DataCoverageEntry for
        each expected data source type with status 'unknown'. These entries
        represent what data SHOULD be available for a complete investigation.

        Requirement 14.2: Expected data sources defined by Case_Manifest
        hosts and data_source_types fields.

        Args:
            manifest: The case manifest containing hosts and time_range.

        Returns:
            List of newly created DataCoverageEntry records.
        """
        entries: list[DataCoverageEntry] = []
        existing = self._store.read_all()
        existing_ids = {entry.data_source_id for entry in existing}

        for host in manifest.hosts:
            for ds_type in DEFAULT_DATA_SOURCE_TYPES:
                data_source_id = f"DC-{host}-{ds_type}"

                # Skip if already initialized
                if data_source_id in existing_ids:
                    continue

                entry = DataCoverageEntry(
                    data_source_id=data_source_id,
                    host_or_system=host,
                    data_source_type=ds_type,
                    availability_status="unknown",
                    covered_time_range=manifest.time_range,
                    collection_time=None,
                    known_gaps=[],
                    reason_for_unavailability=None,
                    impact_on_findings=None,
                )
                self._store.append(entry)
                entries.append(entry)

        return entries

    def update_from_file_inventory(
        self, inventory: list[dict]
    ) -> list[DataCoverageEntry]:
        """Update availability status from ingested file inventory.

        Maps ingested files to their corresponding data source entries
        and updates availability_status to 'available' or 'partially_available'
        based on what was actually collected.

        Args:
            inventory: List of file inventory records (dicts with keys:
                file_id, path, sha256, host, file_type, encoding,
                line_count, time_range).

        Returns:
            List of updated DataCoverageEntry records.
        """
        updated_entries: list[DataCoverageEntry] = []
        existing = self._store.read_all()

        # Build a lookup: (host, data_source_type) -> entry
        entry_lookup: dict[tuple[str, str], DataCoverageEntry] = {}
        for entry in existing:
            key = (entry.host_or_system, entry.data_source_type)
            entry_lookup[key] = entry

        # Map file types to data source types
        file_type_mapping = self._get_file_type_mapping()

        # Track which (host, ds_type) pairs have files
        covered: dict[tuple[str, str], list[dict]] = {}

        for file_record in inventory:
            host = file_record.get("host", "")
            file_type = file_record.get("file_type", "")

            ds_types = file_type_mapping.get(file_type, [])
            for ds_type in ds_types:
                key = (host, ds_type)
                if key not in covered:
                    covered[key] = []
                covered[key].append(file_record)

        # Update entries based on coverage
        for key, files in covered.items():
            host, ds_type = key

            if key in entry_lookup:
                existing_entry = entry_lookup[key]
                # Determine time coverage
                time_range = self._compute_time_range_from_files(files)
                availability = self._determine_availability(
                    files, existing_entry.covered_time_range
                )

                updated_entry = DataCoverageEntry(
                    data_source_id=existing_entry.data_source_id,
                    host_or_system=host,
                    data_source_type=ds_type,
                    availability_status=availability,
                    covered_time_range=time_range or existing_entry.covered_time_range,
                    collection_time=None,
                    known_gaps=existing_entry.known_gaps,
                    reason_for_unavailability=None,
                    impact_on_findings=None,
                )
                self._store.append(updated_entry)
                updated_entries.append(updated_entry)
            else:
                # Create a new entry for this (host, ds_type) found in inventory
                data_source_id = f"DC-{host}-{ds_type}"
                time_range = self._compute_time_range_from_files(files)
                entry = DataCoverageEntry(
                    data_source_id=data_source_id,
                    host_or_system=host,
                    data_source_type=ds_type,
                    availability_status="available",
                    covered_time_range=time_range,
                    collection_time=None,
                    known_gaps=[],
                    reason_for_unavailability=None,
                    impact_on_findings=None,
                )
                self._store.append(entry)
                updated_entries.append(entry)

        return updated_entries

    def derive_from_evidence(
        self, evidence_entries: list, analyzed_time_range: TimeRange
    ) -> list[DataCoverageEntry]:
        """Mark data sources analyzed based on approved evidence.

        Any (host, data_source_type) pair from which evidence was extracted has
        demonstrably been analyzed, so it is recorded as ``available`` and
        marked analyzed for the investigation time range. This is the signal
        that keeps directly-analyzed sources from being treated as ``unknown``
        (which would otherwise drive a blanket confidence downgrade).

        The data_source_type is inferred from each source_ref path via
        :func:`infer_data_source_type`, so it agrees with the relevance filter
        used when building claims.

        Requirement UP-02.

        Args:
            evidence_entries: Approved evidence ledger entries (objects with
                ``observed_event`` and ``source_refs``).
            analyzed_time_range: The investigation time range considered
                analyzed for these sources (typically the manifest range).

        Returns:
            List of DataCoverageEntry records marked available from evidence.
        """
        seen: dict[tuple[str, str], set[str]] = {}
        for ev in evidence_entries:
            observed = getattr(ev, "observed_event", None) or {}
            host = observed.get("host") or ""
            for sr in getattr(ev, "source_refs", []) or []:
                path = getattr(sr, "source_path", "") or ""
                host_h = host or (path.split("/", 1)[0] if "/" in path else "")
                ds_type = infer_data_source_type(path)
                seen.setdefault((host_h, ds_type), set()).add(path)

        derived: list[DataCoverageEntry] = []
        for (host, ds_type), _paths in seen.items():
            if not host:
                continue
            data_source_id = f"DC-{host}-{ds_type}"
            entry = DataCoverageEntry(
                data_source_id=data_source_id,
                host_or_system=host,
                data_source_type=ds_type,
                availability_status="available",
                covered_time_range=analyzed_time_range,
                collection_time=None,
                known_gaps=[],
                reason_for_unavailability=None,
                impact_on_findings=None,
            )
            self._store.append(entry)
            self.mark_analyzed(data_source_id, analyzed_time_range)
            derived.append(entry)

        return derived

    def mark_unobserved_outside_scope(
        self, reason: str = "本ケースの提供資料に含まれないデータソース"
    ) -> list[DataCoverageEntry]:
        """Reclassify still-unknown expected sources as outside_scope.

        After coverage has been derived from evidence, any expected source
        that remains ``unknown`` was neither collected nor analyzed (e.g.
        DNS/proxy logs never provided). Marking them ``outside_scope`` keeps
        them visible as explicit out-of-scope items rather than as major
        ``logs_not_analyzed`` gaps, and prevents them driving a confidence
        downgrade. Requirement UP-02 / UP-07.
        """
        reclassified: list[DataCoverageEntry] = []
        for entry in self.get_all_entries():
            if entry.availability_status != "unknown":
                continue
            updated = DataCoverageEntry(
                data_source_id=entry.data_source_id,
                host_or_system=entry.host_or_system,
                data_source_type=entry.data_source_type,
                availability_status="outside_scope",
                covered_time_range=entry.covered_time_range,
                collection_time=entry.collection_time,
                known_gaps=entry.known_gaps,
                reason_for_unavailability=reason,
                impact_on_findings=None,
            )
            self._store.append(updated)
            reclassified.append(updated)
        return reclassified

    def mark_analyzed(
        self, data_source_id: str, analyzed_time_range: TimeRange
    ) -> None:
        """Mark a data source as analyzed for a given time range.

        This records that an analyst or automated process has reviewed
        the data source for the specified time range. A data source must
        be both available AND analyzed for `can_support_not_observed()`
        to return True.

        Args:
            data_source_id: The identifier of the data source.
            analyzed_time_range: The time range that has been analyzed.
        """
        if data_source_id not in self._analyzed_ranges:
            self._analyzed_ranges[data_source_id] = []
        self._analyzed_ranges[data_source_id].append(analyzed_time_range)
        logger.info(
            "Marked %s as analyzed for range %s to %s",
            data_source_id,
            analyzed_time_range.start,
            analyzed_time_range.end,
        )

    def mark_unavailable(
        self, data_source_id: str, reason: str, impact: str
    ) -> None:
        """Mark a data source as unavailable with reason and impact.

        Requirement 14.5: If a relevant data source is unavailable,
        the Agent SHALL express the result as unknown or limitation,
        not as not_observed.

        Args:
            data_source_id: The identifier of the data source.
            reason: Why the data source is unavailable.
            impact: Impact on investigation findings.
        """
        existing = self._store.read_all()
        target_entry: Optional[DataCoverageEntry] = None

        for entry in existing:
            if entry.data_source_id == data_source_id:
                target_entry = entry

        if target_entry is None:
            logger.warning(
                "Cannot mark unknown data_source_id %s as unavailable",
                data_source_id,
            )
            return

        updated_entry = DataCoverageEntry(
            data_source_id=data_source_id,
            host_or_system=target_entry.host_or_system,
            data_source_type=target_entry.data_source_type,
            availability_status="unavailable",
            covered_time_range=target_entry.covered_time_range,
            collection_time=target_entry.collection_time,
            known_gaps=target_entry.known_gaps,
            reason_for_unavailability=reason,
            impact_on_findings=impact,
        )
        self._store.append(updated_entry)
        logger.info(
            "Marked %s as unavailable: %s", data_source_id, reason
        )

    def get_relevant_coverage(
        self, host: str, data_source_type: str, time_range: TimeRange
    ) -> list[DataCoverageEntry]:
        """Get coverage entries relevant to a specific host, type, and time range.

        Returns the latest state of entries matching the host and data
        source type, filtering to those whose covered_time_range overlaps
        with the requested time_range.

        Args:
            host: The host or system name.
            data_source_type: The type of data source.
            time_range: The time range of interest.

        Returns:
            List of relevant DataCoverageEntry records (latest state per source).
        """
        all_entries = self._store.read_all()
        # Get latest entry per data_source_id
        latest_by_id: dict[str, DataCoverageEntry] = {}
        for entry in all_entries:
            latest_by_id[entry.data_source_id] = entry

        relevant: list[DataCoverageEntry] = []
        for entry in latest_by_id.values():
            if entry.host_or_system != host:
                continue
            if entry.data_source_type != data_source_type:
                continue
            # Check time range overlap
            if entry.covered_time_range and self._ranges_overlap(
                entry.covered_time_range, time_range
            ):
                relevant.append(entry)
            elif entry.covered_time_range is None:
                # If no time range specified, include it as potentially relevant
                relevant.append(entry)

        return relevant

    def can_support_not_observed(
        self, host: str, data_source_type: str, time_range: TimeRange
    ) -> bool:
        """Determine if a 'not_observed' claim can be made.

        Returns True ONLY when:
        1. A relevant data source exists for the host and type
        2. The data source is 'available' (not partially_available,
           unavailable, etc.)
        3. The data source has been analyzed for the relevant time range

        Requirement 14.4: The Agent SHALL NOT generate a not_observed
        Claim unless the relevant data source is available for the
        relevant time range and has been analyzed.

        Requirement 14.5: If unavailable or partially available, express
        as unknown or limitation, not as not_observed.

        Args:
            host: The host or system name.
            data_source_type: The type of data source.
            time_range: The time range for the claim.

        Returns:
            True only if data is available AND analyzed for the time range.
        """
        relevant_entries = self.get_relevant_coverage(
            host, data_source_type, time_range
        )

        if not relevant_entries:
            return False

        for entry in relevant_entries:
            # Must be fully available
            if entry.availability_status != "available":
                continue

            # Must have been analyzed for the relevant time range
            if not self._is_analyzed_for_range(
                entry.data_source_id, time_range
            ):
                continue

            # Both conditions met
            return True

        return False

    def get_all_entries(self) -> list[DataCoverageEntry]:
        """Return all coverage entries (latest state per source).

        Returns:
            List of DataCoverageEntry records representing current state.
        """
        all_entries = self._store.read_all()
        latest_by_id: dict[str, DataCoverageEntry] = {}
        for entry in all_entries:
            latest_by_id[entry.data_source_id] = entry
        return list(latest_by_id.values())

    def _is_analyzed_for_range(
        self, data_source_id: str, time_range: TimeRange
    ) -> bool:
        """Check if a data source has been analyzed for a given time range.

        The time range is considered analyzed if the union of analyzed
        ranges covers the requested time range.

        Args:
            data_source_id: The data source identifier.
            time_range: The time range to check.

        Returns:
            True if the data source has been analyzed for the full range.
        """
        analyzed = self._analyzed_ranges.get(data_source_id, [])
        if not analyzed:
            return False

        # Parse the target range
        try:
            target_start = dateutil_parser.parse(time_range.start)
            target_end = dateutil_parser.parse(time_range.end)
        except (ValueError, TypeError):
            return False

        # Check if any analyzed range covers the target range
        for ar in analyzed:
            try:
                ar_start = dateutil_parser.parse(ar.start)
                ar_end = dateutil_parser.parse(ar.end)
            except (ValueError, TypeError):
                continue

            # The analyzed range covers the target if it starts at or before
            # the target start and ends at or after the target end
            if ar_start <= target_start and ar_end >= target_end:
                return True

        return False

    def _ranges_overlap(self, range_a: TimeRange, range_b: TimeRange) -> bool:
        """Check if two time ranges overlap.

        Args:
            range_a: First time range.
            range_b: Second time range.

        Returns:
            True if the ranges overlap.
        """
        try:
            a_start = dateutil_parser.parse(range_a.start)
            a_end = dateutil_parser.parse(range_a.end)
            b_start = dateutil_parser.parse(range_b.start)
            b_end = dateutil_parser.parse(range_b.end)
        except (ValueError, TypeError):
            return False

        return a_start <= b_end and b_start <= a_end

    def _get_file_type_mapping(self) -> dict[str, list[str]]:
        """Return a mapping from file_type to data_source_type(s).

        Maps ingested file classifications to the expected data source
        types used in the coverage ledger.

        Returns:
            Dict mapping file_type strings to lists of data_source_type strings.
        """
        return {
            "windows_event_log": ["windows_event_log"],
            "evtx": ["windows_event_log"],
            "syslog": ["windows_event_log"],
            "edr_csv": ["edr_telemetry"],
            "edr_json": ["edr_telemetry"],
            "csv": ["edr_telemetry"],
            "pcap": ["network_flow"],
            "netflow": ["network_flow"],
            "firewall_log": ["firewall_log"],
            "firewall": ["firewall_log"],
            "dns_log": ["dns_log"],
            "dns": ["dns_log"],
            "proxy_log": ["proxy_log"],
            "proxy": ["proxy_log"],
            "vpn_log": ["network_flow"],
            "text": [],  # Generic text needs manual classification
            "unknown": [],
        }

    def _compute_time_range_from_files(
        self, files: list[dict]
    ) -> Optional[TimeRange]:
        """Compute the overall time range covered by a list of files.

        Args:
            files: List of file inventory records.

        Returns:
            TimeRange covering all files, or None if no time data available.
        """
        starts: list[str] = []
        ends: list[str] = []

        for f in files:
            tr = f.get("time_range")
            if tr and isinstance(tr, dict):
                if "start" in tr:
                    starts.append(tr["start"])
                if "end" in tr:
                    ends.append(tr["end"])

        if not starts or not ends:
            return None

        # Sort and take earliest start, latest end
        try:
            sorted_starts = sorted(starts, key=lambda s: dateutil_parser.parse(s))
            sorted_ends = sorted(ends, key=lambda s: dateutil_parser.parse(s))
            return TimeRange(start=sorted_starts[0], end=sorted_ends[-1])
        except (ValueError, TypeError):
            return None

    def _determine_availability(
        self, files: list[dict], expected_range: Optional[TimeRange]
    ) -> str:
        """Determine availability status based on collected files vs expected range.

        Args:
            files: Collected file records.
            expected_range: The expected time range from the manifest.

        Returns:
            Availability status string.
        """
        if not files:
            return "unavailable"

        if expected_range is None:
            return "available"

        # Check if files cover the expected range
        computed_range = self._compute_time_range_from_files(files)
        if computed_range is None:
            # Files exist but no time data — assume available
            return "available"

        try:
            expected_start = dateutil_parser.parse(expected_range.start)
            expected_end = dateutil_parser.parse(expected_range.end)
            computed_start = dateutil_parser.parse(computed_range.start)
            computed_end = dateutil_parser.parse(computed_range.end)
        except (ValueError, TypeError):
            return "available"

        # If computed range covers at least 90% of expected range, it's available
        expected_duration = (expected_end - expected_start).total_seconds()
        if expected_duration <= 0:
            return "available"

        overlap_start = max(expected_start, computed_start)
        overlap_end = min(expected_end, computed_end)
        if overlap_end <= overlap_start:
            return "partially_available"

        overlap_duration = (overlap_end - overlap_start).total_seconds()
        coverage_ratio = overlap_duration / expected_duration

        if coverage_ratio >= 0.9:
            return "available"
        else:
            return "partially_available"
