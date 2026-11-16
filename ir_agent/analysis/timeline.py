"""Timeline construction for the Analysis Layer.

Implements TimelineBuilder which constructs chronological timelines from
approved evidence in the Evidence Ledger, identifies timeline gaps, and
detects conflicts between causally related events.

Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.7
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4
from zoneinfo import ZoneInfo

from dateutil import parser as dateutil_parser

from ir_agent.models.analysis import TimelineEntry
from ir_agent.models.base import EventTimestamp
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry
from ir_agent.steering.manifest import CaseManifest

# Default gap threshold: flag gaps larger than 6 hours
DEFAULT_GAP_THRESHOLD_HOURS = 6

# ISO 8601 timestamps with an explicit zone (Z or ±hh:mm) inside excerpt lines.
_LINE_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})(?![\d:])"
)


class TimelineBuilder:
    """Constructs chronological timelines from approved evidence.

    Uses only event_time timestamps unless analyst explicitly approves
    otherwise. Normalizes to UTC, preserves original timestamp strings,
    and applies display timezone from the case manifest.

    Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.7
    """

    def build_timeline(
        self,
        ledger_entries: list[EvidenceLedgerEntry],
        manifest: CaseManifest,
    ) -> list[TimelineEntry]:
        """Construct a chronological timeline from approved evidence.

        Iterates through ledger entries, extracts timestamps from
        observed_event data, filters to only event_time timestamps
        (Requirement 9.7), normalizes to UTC (Requirement 9.2),
        creates TimelineEntry for each, and sorts chronologically
        (Requirement 9.1).

        Args:
            ledger_entries: Approved evidence ledger entries.
            manifest: Case manifest containing report_timezone.

        Returns:
            Chronologically sorted list of TimelineEntry objects.
        """
        display_timezone = manifest.report_timezone
        timeline_entries: list[TimelineEntry] = []
        window = self._window(manifest)

        for entry in ledger_entries:
            # Skip withdrawn entries
            if entry.withdrawn:
                continue
            first = len(timeline_entries)

            # Extract timestamps from observed_event dict
            timestamps = self._extract_timestamps(entry)

            for ts in timestamps:
                # Requirement 9.7: Only use event_time timestamps
                # unless analyst explicitly approves otherwise
                if ts.timestamp_type != "event_time":
                    continue

                # Normalize to UTC (Requirement 9.2)
                normalized_utc = self._normalize_to_utc(ts)
                if normalized_utc is None:
                    continue

                # Create TimelineEntry preserving original timestamp
                timeline_entry = TimelineEntry(
                    entry_id=str(uuid4()),
                    evidence_id=entry.evidence_id,
                    event_time=normalized_utc,
                    original_timestamp=ts.original_value,
                    display_timezone=display_timezone,
                    event_description=entry.observed_fact,
                    host=self._extract_host(entry),
                    confidence=ts.confidence,
                    event_confidence=entry.observed_fact_confidence,
                    interpretation_confidence=entry.interpretation_confidence,
                    timestamp_type=ts.timestamp_type,
                )
                timeline_entries.append(timeline_entry)

            timeline_entries += self._line_entries(
                entry, timeline_entries[first:], display_timezone, window)

        # Sort chronologically by event_time (Requirement 9.1)
        timeline_entries.sort(key=lambda e: e.event_time)

        return timeline_entries

    def identify_timeline_gaps(
        self,
        timeline: list[TimelineEntry],
        gap_threshold_hours: float = DEFAULT_GAP_THRESHOLD_HOURS,
    ) -> list[str]:
        """Identify gaps in the timeline where expected events are missing.

        Looks for significant time gaps between consecutive entries
        (e.g., >6 hours with no events) that may indicate missing
        evidence or unrecorded activity.

        Requirement 9.3: Identify gaps in the timeline where expected
        events are missing.

        Args:
            timeline: Chronologically sorted timeline entries.
            gap_threshold_hours: Minimum hours between events to flag
                as a gap. Defaults to 6 hours.

        Returns:
            List of gap description strings identifying the time periods
            with no recorded events.
        """
        if len(timeline) < 2:
            return []

        gaps: list[str] = []
        threshold = timedelta(hours=gap_threshold_hours)

        for i in range(len(timeline) - 1):
            current_entry = timeline[i]
            next_entry = timeline[i + 1]

            current_time = self._parse_utc_timestamp(current_entry.event_time)
            next_time = self._parse_utc_timestamp(next_entry.event_time)

            if current_time is None or next_time is None:
                continue

            time_diff = next_time - current_time

            if time_diff > threshold:
                gap_description = (
                    f"Timeline gap of {time_diff} between "
                    f"{current_entry.event_time} and {next_entry.event_time}"
                )

                # Add host context if events are on the same host
                if (
                    current_entry.host
                    and next_entry.host
                    and current_entry.host == next_entry.host
                ):
                    gap_description += f" on host {current_entry.host}"

                gaps.append(gap_description)

        return gaps

    def detect_conflicts(
        self,
        timeline: list[TimelineEntry],
    ) -> list[dict]:
        """Detect conflicts between causally related timeline events.

        Finds pairs of events that are causally related (same host,
        sequential event types) but have conflicting chronological order.

        Requirement 9.5: Flag conflicts for analyst review when two
        timeline entries have conflicting timestamps for causally
        related events.

        Args:
            timeline: Chronologically sorted timeline entries.

        Returns:
            List of conflict dicts with keys: entry_a, entry_b,
            evidence_ids, host, conflict_type, requires_review, description.
        """
        conflicts: list[dict] = []

        if len(timeline) < 2:
            return conflicts

        # Group entries by host for causal relationship detection
        entries_by_host: dict[str, list[TimelineEntry]] = {}
        for entry in timeline:
            host = entry.host or "__unknown__"
            if host not in entries_by_host:
                entries_by_host[host] = []
            entries_by_host[host].append(entry)

        # Check for conflicts within each host group
        for host, entries in entries_by_host.items():
            if host == "__unknown__" or len(entries) < 2:
                continue

            for i in range(len(entries)):
                for j in range(i + 1, len(entries)):
                    conflict = self._check_causal_conflict(entries[i], entries[j])
                    if conflict:
                        conflicts.append(conflict)

        return conflicts

    @staticmethod
    def _window(manifest: CaseManifest) -> tuple[datetime, datetime] | None:
        try:
            start = dateutil_parser.parse(manifest.time_range.start)
            end = dateutil_parser.parse(manifest.time_range.end)
        except (ValueError, TypeError, OverflowError, AttributeError):
            return None
        if start.tzinfo is None or end.tzinfo is None:
            return None
        return start, end

    def _line_entries(
        self,
        entry: EvidenceLedgerEntry,
        structured: list[TimelineEntry],
        display_timezone: str,
        window: tuple[datetime, datetime] | None,
    ) -> list[TimelineEntry]:
        """One row per timestamped excerpt line the structured rows do not cover.

        Evidence often spans several log lines (a logon, then a privilege
        assignment two minutes later) while ``observed_event`` carries only the
        first time. Only timestamps with an explicit offset are read, so no log
        time is reinterpreted in another zone. A structured row whose time
        matches a line is annotated with that line instead of duplicated.
        """
        out: list[TimelineEntry] = []
        unmatched = {id(t): t for t in structured}
        for ref in entry.source_refs:
            start_line = ref.source_lines[0] if ref.source_lines else 1
            for offset, text in enumerate(ref.excerpt.splitlines()):
                match = _LINE_TIMESTAMP.search(text)
                if not match:
                    continue
                try:
                    when = dateutil_parser.parse(match.group(0))
                except (ValueError, TypeError, OverflowError):
                    continue
                if window and not (window[0] <= when <= window[1]):
                    continue
                line_no, line_text = start_line + offset, text.strip()[:300]
                same = next((t for t in unmatched.values()
                             if self._parse_utc_timestamp(t.event_time) == when), None)
                if same is not None:
                    del unmatched[id(same)]
                    same.source_path, same.source_line = ref.source_path, line_no
                    same.source_text = line_text
                    continue
                if any(self._parse_utc_timestamp(t.event_time) == when
                       and t.source_text == line_text for t in out):
                    continue
                base = structured[0] if structured else None
                out.append(TimelineEntry(
                    entry_id=str(uuid4()),
                    evidence_id=entry.evidence_id,
                    event_time=when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    original_timestamp=match.group(0),
                    display_timezone=display_timezone,
                    event_description=entry.observed_fact,
                    host=self._extract_host(entry),
                    confidence=base.confidence if base else entry.observed_fact_confidence,
                    event_confidence=entry.observed_fact_confidence,
                    interpretation_confidence=entry.interpretation_confidence,
                    timestamp_type="event_time",
                    source_path=ref.source_path,
                    source_line=line_no,
                    source_text=line_text,
                ))
        return out

    def _extract_timestamps(
        self, entry: EvidenceLedgerEntry
    ) -> list[EventTimestamp]:
        """Extract EventTimestamp objects from a ledger entry.

        Looks for timestamp data in the observed_event dict.
        The observed_event may contain a 'timestamps' key with
        a list of timestamp objects, or individual timestamp fields.

        Args:
            entry: An evidence ledger entry.

        Returns:
            List of EventTimestamp objects found in the entry.
        """
        timestamps: list[EventTimestamp] = []
        observed = entry.observed_event

        if not observed:
            return timestamps

        # Check for 'timestamps' list in observed_event
        if "timestamps" in observed and isinstance(observed["timestamps"], list):
            for ts_data in observed["timestamps"]:
                ts = self._parse_timestamp_dict(ts_data)
                if ts:
                    timestamps.append(ts)

        # Check for direct timestamp fields in observed_event
        if "event_time" in observed:
            ts = self._make_event_timestamp(
                original_value=str(observed["event_time"]),
                normalized_utc=observed.get("event_time_utc"),
                timezone_str=observed.get("timezone"),
                confidence_str=observed.get("confidence", "probable"),
            )
            if ts:
                timestamps.append(ts)

        # Check for 'timestamp' field (singular)
        if "timestamp" in observed and "event_time" not in observed:
            ts = self._make_event_timestamp(
                original_value=str(observed["timestamp"]),
                normalized_utc=observed.get("timestamp_utc"),
                timezone_str=observed.get("timezone"),
                confidence_str=observed.get("confidence", "probable"),
            )
            if ts:
                timestamps.append(ts)

        return timestamps

    def _parse_timestamp_dict(self, ts_data: dict) -> Optional[EventTimestamp]:
        """Parse a dict into an EventTimestamp.

        Args:
            ts_data: Dictionary with timestamp fields.

        Returns:
            EventTimestamp if valid, None otherwise.
        """
        if not isinstance(ts_data, dict):
            return None

        original_value = ts_data.get("original_value")
        if not original_value:
            return None

        confidence_str = ts_data.get("confidence", "probable")
        confidence = self._parse_confidence(confidence_str)

        return EventTimestamp(
            original_value=str(original_value),
            normalized_utc=ts_data.get("normalized_utc"),
            timezone=ts_data.get("timezone"),
            timestamp_type=ts_data.get("timestamp_type", "event_time"),
            confidence=confidence,
            parsing_notes=ts_data.get("parsing_notes"),
        )

    def _make_event_timestamp(
        self,
        original_value: str,
        normalized_utc: Optional[str] = None,
        timezone_str: Optional[str] = None,
        confidence_str: str = "probable",
    ) -> Optional[EventTimestamp]:
        """Create an EventTimestamp from individual fields.

        Args:
            original_value: The original timestamp string.
            normalized_utc: Pre-normalized UTC string if available.
            timezone_str: Timezone string if known.
            confidence_str: Confidence level string.

        Returns:
            EventTimestamp or None if original_value is empty.
        """
        if not original_value:
            return None

        confidence = self._parse_confidence(confidence_str)

        return EventTimestamp(
            original_value=original_value,
            normalized_utc=normalized_utc,
            timezone=timezone_str,
            timestamp_type="event_time",
            confidence=confidence,
        )

    def _normalize_to_utc(self, ts: EventTimestamp) -> Optional[str]:
        """Normalize a timestamp to UTC ISO 8601 format.

        If normalized_utc is already available, uses it directly.
        Otherwise attempts to parse the original_value and convert to UTC.

        Requirement 9.2: Normalize all timestamps into a canonical UTC
        representation.

        Args:
            ts: EventTimestamp to normalize.

        Returns:
            ISO 8601 UTC timestamp string, or None if parsing fails.
        """
        # If already normalized, use it
        if ts.normalized_utc:
            return ts.normalized_utc

        # Attempt to parse original_value
        try:
            parsed = dateutil_parser.parse(ts.original_value)

            # If no timezone info, assume the specified timezone or UTC
            if parsed.tzinfo is None:
                if ts.timezone:
                    try:
                        tz = ZoneInfo(ts.timezone)
                        parsed = parsed.replace(tzinfo=tz)
                    except (KeyError, ValueError):
                        # Fall back to UTC if timezone is invalid
                        parsed = parsed.replace(tzinfo=timezone.utc)
                else:
                    parsed = parsed.replace(tzinfo=timezone.utc)

            # Convert to UTC
            utc_time = parsed.astimezone(timezone.utc)
            return utc_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        except (ValueError, TypeError, OverflowError):
            return None

    def _extract_host(self, entry: EvidenceLedgerEntry) -> Optional[str]:
        """Extract host information from a ledger entry.

        Checks observed_event dict for host-related fields.

        Args:
            entry: Evidence ledger entry.

        Returns:
            Host string if found, None otherwise.
        """
        observed = entry.observed_event
        if not observed:
            return None

        # Check common host field names
        for field_name in ("host", "hostname", "computer_name", "system"):
            if field_name in observed:
                return str(observed[field_name])

        return None

    def _parse_confidence(self, value: str) -> ConfidenceLevel:
        """Parse a confidence level string into ConfidenceLevel enum.

        Args:
            value: Confidence level string.

        Returns:
            ConfidenceLevel enum value, defaults to PROBABLE.
        """
        if isinstance(value, ConfidenceLevel):
            return value

        try:
            return ConfidenceLevel(value.lower())
        except (ValueError, AttributeError):
            return ConfidenceLevel.PROBABLE

    def _parse_utc_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse a UTC timestamp string into a datetime object.

        Args:
            timestamp_str: ISO 8601 UTC timestamp string.

        Returns:
            datetime object in UTC, or None if parsing fails.
        """
        try:
            parsed = dateutil_parser.parse(timestamp_str)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (ValueError, TypeError):
            return None

    def _check_causal_conflict(
        self,
        entry_a: TimelineEntry,
        entry_b: TimelineEntry,
    ) -> Optional[dict]:
        """Check if two entries on the same host have a causal conflict.

        A causal conflict occurs when two events that should logically
        happen in a specific order appear in the wrong chronological
        sequence, or when the same evidence produces conflicting timestamps.

        Args:
            entry_a: First timeline entry (earlier in sorted order).
            entry_b: Second timeline entry (later in sorted order).

        Returns:
            Conflict dict if detected, None otherwise.
        """
        # Check for duplicate evidence with different timestamps. Rows read
        # from different excerpt lines are separate log records, not a conflict.
        if entry_a.evidence_id == entry_b.evidence_id:
            separate_lines = (
                entry_a.source_line is not None
                and entry_b.source_line is not None
                and (entry_a.source_path, entry_a.source_line)
                != (entry_b.source_path, entry_b.source_line)
            )
            if entry_a.event_time != entry_b.event_time and not separate_lines:
                return {
                    "entry_a": entry_a.entry_id,
                    "entry_b": entry_b.entry_id,
                    "evidence_ids": [entry_a.evidence_id],
                    "host": entry_a.host,
                    "event_times": [entry_a.event_time, entry_b.event_time],
                    "conflict_type": "same_evidence_different_timestamps",
                    "requires_review": True,
                    "description": (
                        f"Evidence {entry_a.evidence_id} has conflicting "
                        f"timestamps: {entry_a.event_time} vs {entry_b.event_time}"
                    ),
                }

        # Check for causal ordering conflicts based on event descriptions
        # If event_b logically must happen before event_a but has a later
        # timestamp, flag a conflict
        time_a = self._parse_utc_timestamp(entry_a.event_time)
        time_b = self._parse_utc_timestamp(entry_b.event_time)

        if time_a is None or time_b is None:
            return None

        # Detect simultaneous events (within 1 second) that reference
        # different evidence - potential clock skew or conflict
        time_diff = abs((time_b - time_a).total_seconds())
        if (
            time_diff < 1.0
            and entry_a.evidence_id != entry_b.evidence_id
            and entry_a.confidence != ConfidenceLevel.CONFIRMED
            and entry_b.confidence != ConfidenceLevel.CONFIRMED
        ):
            return {
                "entry_a": entry_a.entry_id,
                "entry_b": entry_b.entry_id,
                "evidence_ids": [entry_a.evidence_id, entry_b.evidence_id],
                "host": entry_a.host,
                "conflict_type": "near_simultaneous_different_evidence",
                # Two records of one moment usually corroborate each other;
                # kept for the analyst, but not a gap by itself.
                "requires_review": False,
                "description": (
                    f"Events from different evidence sources occur within "
                    f"1 second on host {entry_a.host}: "
                    f"'{entry_a.event_description[:80]}' and "
                    f"'{entry_b.event_description[:80]}' — "
                    f"possible clock skew or conflicting timestamps"
                ),
            }

        return None


CONFLICTS_FILE = "timeline_conflicts.jsonl"


def conflict_gap_specs(conflicts: list[dict], claims: list) -> list[dict]:
    """Gap fields for each timeline conflict that needs the analyst's review.

    The gap is attached to the first claim citing the evidence, or to the whole
    case (``CASE-SCOPE``) when no claim cites it.
    """
    specs = []
    for conflict in conflicts:
        if not conflict.get("requires_review"):
            continue
        evidence = set(conflict.get("evidence_ids") or [])
        claim_id = next((c.claim_id for c in claims
                         if evidence & set(c.supporting_evidence)), "CASE-SCOPE")
        times = " と ".join(str(t) for t in conflict.get("event_times") or [])
        host = conflict.get("host") or "対象ホスト"
        specs.append({
            "related_claim_id": claim_id,
            "gap_type": "contradictory_evidence",
            "severity": "major",
            "description": (
                f"{host} の同一の記録について、異なる時刻({times})が確認されました。"
                "時刻の取り違えまたは時計のずれの可能性があり、この記録の時刻は確定できていません。"
            ),
            "recommended_action": (
                "元のログで当該記録の時刻と時刻帯を確認し、時系列上の位置を確定してください。"
            ),
        })
    return specs

