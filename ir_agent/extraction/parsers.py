"""Rule-based parsers for structured log formats.

Implements parsers for syslog, Windows Event Log, CSV, firewall,
and VPN log formats. Each parser produces NormalizedEvent objects
with proper SourceReference and EventTimestamp metadata.

Requirements: 4.2, 26.1, 26.2
"""

import csv
import hashlib
import io
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from dateutil import parser as dateutil_parser

from ir_agent.models.base import EventTimestamp, SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.events import NormalizedEvent

PARSER_VERSION = "1.0.0"


def _sha256(text: str) -> str:
    """Compute SHA-256 hex digest of text content."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _make_source_ref(
    file_id: str,
    line_start: int,
    line_end: int,
    excerpt: str,
    parser_name: str,
) -> SourceReference:
    """Create a SourceReference with computed SHA-256."""
    return SourceReference(
        source_ref_id=str(uuid4()),
        source_file_id=file_id,
        source_path="",
        source_lines=(line_start, line_end),
        excerpt=excerpt,
        excerpt_sha256=_sha256(excerpt),
        parser_name=parser_name,
        parser_version=PARSER_VERSION,
    )


def _make_timestamp(
    original_value: str,
    normalized_utc: Optional[str],
    timezone_str: Optional[str] = None,
    confidence: ConfidenceLevel = ConfidenceLevel.PROBABLE,
    parsing_notes: Optional[str] = None,
) -> EventTimestamp:
    """Create an EventTimestamp for event_time."""
    return EventTimestamp(
        original_value=original_value,
        normalized_utc=normalized_utc,
        timezone=timezone_str,
        timestamp_type="event_time",
        confidence=confidence,
        parsing_notes=parsing_notes,
    )


def _try_normalize_timestamp(raw: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Attempt to parse a timestamp string into ISO 8601 UTC.

    Returns (normalized_utc, timezone_str, parsing_notes).
    """
    try:
        dt = dateutil_parser.parse(raw, fuzzy=True)
        if dt.tzinfo is not None:
            utc_dt = dt.astimezone(timezone.utc)
            tz_str = str(dt.tzinfo)
        else:
            utc_dt = dt.replace(tzinfo=timezone.utc)
            tz_str = None
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ"), tz_str, None
    except (ValueError, OverflowError) as e:
        return None, None, f"Failed to parse timestamp: {e}"


# Syslog timestamp pattern: "Jan 15 10:30:00"
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\[:\s]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# Firewall log pattern: "2024-01-15 10:30:00 ACTION PROTO SRC -> DST"
_FIREWALL_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>\S+)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<src>[^:\s]+):(?P<src_port>\d+)\s*->\s*"
    r"(?P<dst>[^:\s]+):(?P<dst_port>\d+)"
    r"(?:\s+(?P<extra>.*))?$"
)

# VPN log pattern: "2024-01-15 10:30:00 user@vpn ACTION from IP"
_VPN_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<user>\S+?)@(?P<vpn_host>\S+)\s+"
    r"(?P<action>\w+)"
    r"(?:\s+from\s+(?P<src_ip>\S+))?"
    r"(?:\s+(?P<extra>.*))?$"
)


class RuleBasedParser:
    """Rule-based parser for structured log formats.

    Produces NormalizedEvent objects from known log formats using
    regex and structural parsing rather than LLM interpretation.
    """

    def parse_syslog(self, content: str, file_id: str) -> list[NormalizedEvent]:
        """Parse syslog-format content into NormalizedEvents.

        Handles lines like:
        "Jan 15 10:30:00 host01 sshd[1234]: Accepted publickey for user from 192.168.1.1"
        """
        events: list[NormalizedEvent] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            match = _SYSLOG_RE.match(line_stripped)
            if not match:
                continue

            raw_ts = match.group("timestamp")
            host = match.group("host")
            process = match.group("process")
            message = match.group("message")

            # Attempt to normalize timestamp (syslog has no year, assume current)
            normalized_utc, tz_str, notes = _try_normalize_timestamp(raw_ts)
            if notes is None:
                notes = "Syslog timestamp lacks year; assumed current year"

            timestamp = _make_timestamp(
                original_value=raw_ts,
                normalized_utc=normalized_utc,
                timezone_str=tz_str,
                confidence=ConfidenceLevel.PROBABLE,
                parsing_notes=notes,
            )

            source_ref = _make_source_ref(
                file_id=file_id,
                line_start=line_num,
                line_end=line_num,
                excerpt=line_stripped,
                parser_name="syslog",
            )

            # Extract optional fields from message
            src_ip = _extract_ip_from_message(message, prefix="from")
            user = _extract_user_from_message(message)

            event = NormalizedEvent(
                event_id=str(uuid4()),
                source_refs=[source_ref],
                timestamps=[timestamp],
                host=host,
                user=user,
                process_name=process,
                command_line=None,
                src_ip=src_ip,
                dst_ip=None,
                dst_port=None,
                file_path=None,
                event_type=_classify_syslog_event(message, process),
                raw_excerpt=line_stripped,
            )
            events.append(event)

        return events

    def parse_windows_event_log(self, content: str, file_id: str) -> list[NormalizedEvent]:
        """Parse Windows Event Log XML content into NormalizedEvents.

        Handles XML format with <Event xmlns=...> elements.
        """
        events: list[NormalizedEvent] = []
        content_lines = content.splitlines()

        # Wrap in root element if not already wrapped
        xml_content = content.strip()
        if not xml_content.startswith("<Events"):
            xml_content = f"<Events>{xml_content}</Events>"

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            # Try parsing individual Event elements
            return self._parse_windows_events_individually(content, file_id)

        # Detect namespace from root or children
        ns_uri = "http://schemas.microsoft.com/win/2004/08/events/event"
        ns = {"ns": ns_uri}

        # Collect all Event elements - check with and without namespace
        event_elements = root.findall(f".//{{{ns_uri}}}Event")
        if not event_elements:
            event_elements = root.findall(".//Event")
        # If root itself is an Event element (wrapped single event)
        if not event_elements:
            # The children of our wrapper are the events
            event_elements = list(root)

        for idx, event_elem in enumerate(event_elements):
            event = self._parse_single_windows_event(
                event_elem, ns, file_id, content_lines, idx
            )
            if event:
                events.append(event)

        return events

    def _parse_windows_events_individually(
        self, content: str, file_id: str
    ) -> list[NormalizedEvent]:
        """Fallback: parse individual <Event> blocks from content."""
        events: list[NormalizedEvent] = []
        lines = content.splitlines()

        # Find <Event blocks by scanning lines
        event_blocks: list[tuple[int, int, str]] = []
        block_start: Optional[int] = None
        block_lines: list[str] = []

        for line_num, line in enumerate(lines, start=1):
            if "<Event" in line:
                block_start = line_num
                block_lines = [line]
            elif block_start is not None:
                block_lines.append(line)
                if "</Event>" in line:
                    event_blocks.append(
                        (block_start, line_num, "\n".join(block_lines))
                    )
                    block_start = None
                    block_lines = []

        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

        for start_line, end_line, block_xml in event_blocks:
            try:
                elem = ET.fromstring(block_xml)
            except ET.ParseError:
                continue

            event = self._parse_single_windows_event_from_elem(
                elem, ns, file_id, start_line, end_line, block_xml
            )
            if event:
                events.append(event)

        return events

    def _parse_single_windows_event(
        self,
        event_elem: ET.Element,
        ns: dict[str, str],
        file_id: str,
        content_lines: list[str],
        idx: int,
    ) -> Optional[NormalizedEvent]:
        """Parse a single Windows Event XML element."""
        # Estimate line positions
        event_xml = ET.tostring(event_elem, encoding="unicode")
        line_start = 1 + idx * 10  # approximate
        line_end = line_start + event_xml.count("\n")

        return self._parse_single_windows_event_from_elem(
            event_elem, ns, file_id, line_start, line_end, event_xml
        )

    def _parse_single_windows_event_from_elem(
        self,
        elem: ET.Element,
        ns: dict[str, str],
        file_id: str,
        line_start: int,
        line_end: int,
        raw_xml: str,
    ) -> Optional[NormalizedEvent]:
        """Extract NormalizedEvent from a parsed Event XML element."""
        ns_uri = ns.get("ns", "")

        # Try with full namespace URI first, then prefix, then bare
        system = (
            elem.find(f"{{{ns_uri}}}System") if ns_uri
            else None
        )
        if system is None:
            system = elem.find("ns:System", ns)
        if system is None:
            system = elem.find("System")
        if system is None:
            return None

        # Extract timestamp
        time_created = (
            system.find(f"{{{ns_uri}}}TimeCreated") if ns_uri
            else None
        )
        if time_created is None:
            time_created = system.find("ns:TimeCreated", ns)
        if time_created is None:
            time_created = system.find("TimeCreated")
        raw_ts = ""
        normalized_utc = None
        tz_str = None
        notes = None
        if time_created is not None:
            raw_ts = time_created.get("SystemTime", "")
            normalized_utc, tz_str, notes = _try_normalize_timestamp(raw_ts)

        # Extract event ID
        event_id_elem = (
            system.find(f"{{{ns_uri}}}EventID") if ns_uri
            else None
        )
        if event_id_elem is None:
            event_id_elem = system.find("ns:EventID", ns)
        if event_id_elem is None:
            event_id_elem = system.find("EventID")
        win_event_id = event_id_elem.text if event_id_elem is not None else "unknown"

        # Extract computer
        computer_elem = (
            system.find(f"{{{ns_uri}}}Computer") if ns_uri
            else None
        )
        if computer_elem is None:
            computer_elem = system.find("ns:Computer", ns)
        if computer_elem is None:
            computer_elem = system.find("Computer")
        host = computer_elem.text if computer_elem is not None else None

        # Extract channel
        channel_elem = (
            system.find(f"{{{ns_uri}}}Channel") if ns_uri
            else None
        )
        if channel_elem is None:
            channel_elem = system.find("ns:Channel", ns)
        if channel_elem is None:
            channel_elem = system.find("Channel")
        channel = channel_elem.text if channel_elem is not None else ""

        # Extract EventData
        event_data = (
            elem.find(f"{{{ns_uri}}}EventData") if ns_uri
            else None
        )
        if event_data is None:
            event_data = elem.find("ns:EventData", ns)
        if event_data is None:
            event_data = elem.find("EventData")
        data_fields: dict[str, str] = {}
        if event_data is not None:
            for data_elem in event_data:
                name = data_elem.get("Name", "")
                value = data_elem.text or ""
                if name:
                    data_fields[name] = value

        excerpt = raw_xml[:500] if len(raw_xml) > 500 else raw_xml

        timestamp = _make_timestamp(
            original_value=raw_ts,
            normalized_utc=normalized_utc,
            timezone_str=tz_str,
            confidence=ConfidenceLevel.CONFIRMED if normalized_utc else ConfidenceLevel.UNKNOWN,
            parsing_notes=notes,
        )

        source_ref = _make_source_ref(
            file_id=file_id,
            line_start=line_start,
            line_end=line_end,
            excerpt=excerpt,
            parser_name="windows_event_log",
        )

        return NormalizedEvent(
            event_id=str(uuid4()),
            source_refs=[source_ref],
            timestamps=[timestamp],
            host=host,
            user=data_fields.get("TargetUserName") or data_fields.get("SubjectUserName"),
            process_name=data_fields.get("ProcessName") or data_fields.get("NewProcessName"),
            command_line=data_fields.get("CommandLine"),
            src_ip=data_fields.get("IpAddress") or data_fields.get("SourceAddress"),
            dst_ip=data_fields.get("DestAddress"),
            dst_port=_safe_int(data_fields.get("DestPort")),
            file_path=data_fields.get("ObjectName") or data_fields.get("TargetFilename"),
            event_type=f"windows_event_{win_event_id}",
            raw_excerpt=excerpt,
        )

    def parse_csv(self, content: str, file_id: str) -> list[NormalizedEvent]:
        """Parse CSV-based log exports into NormalizedEvents.

        Expects first row as header. Maps columns to NormalizedEvent fields
        using common column name patterns.
        """
        events: list[NormalizedEvent] = []
        reader = csv.DictReader(io.StringIO(content))

        if reader.fieldnames is None:
            return events

        # Build column mapping from header names to NormalizedEvent fields
        col_map = _build_csv_column_map(reader.fieldnames)

        for row_num, row in enumerate(reader, start=2):  # row 1 is header
            raw_line = ",".join(row.values())
            excerpt = raw_line[:500]

            # Extract timestamp
            ts_value = _get_csv_value(row, col_map, "timestamp")
            normalized_utc = None
            tz_str = None
            notes = None
            if ts_value:
                normalized_utc, tz_str, notes = _try_normalize_timestamp(ts_value)

            timestamp = _make_timestamp(
                original_value=ts_value or "",
                normalized_utc=normalized_utc,
                timezone_str=tz_str,
                confidence=ConfidenceLevel.CONFIRMED if normalized_utc else ConfidenceLevel.UNKNOWN,
                parsing_notes=notes,
            )

            source_ref = _make_source_ref(
                file_id=file_id,
                line_start=row_num,
                line_end=row_num,
                excerpt=excerpt,
                parser_name="csv",
            )

            dst_port_raw = _get_csv_value(row, col_map, "dst_port")

            event = NormalizedEvent(
                event_id=str(uuid4()),
                source_refs=[source_ref],
                timestamps=[timestamp],
                host=_get_csv_value(row, col_map, "host"),
                user=_get_csv_value(row, col_map, "user"),
                process_name=_get_csv_value(row, col_map, "process_name"),
                command_line=_get_csv_value(row, col_map, "command_line"),
                src_ip=_get_csv_value(row, col_map, "src_ip"),
                dst_ip=_get_csv_value(row, col_map, "dst_ip"),
                dst_port=_safe_int(dst_port_raw),
                file_path=_get_csv_value(row, col_map, "file_path"),
                event_type=_get_csv_value(row, col_map, "event_type") or "csv_event",
                raw_excerpt=excerpt,
            )
            events.append(event)

        return events

    def parse_firewall_log(self, content: str, file_id: str) -> list[NormalizedEvent]:
        """Parse firewall log format into NormalizedEvents.

        Handles lines like:
        "2024-01-15 10:30:00 ALLOW TCP 192.168.1.1:12345 -> 10.0.0.1:443"
        """
        events: list[NormalizedEvent] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            match = _FIREWALL_RE.match(line_stripped)
            if not match:
                continue

            raw_ts = match.group("timestamp")
            action = match.group("action")
            proto = match.group("proto")
            src_ip = match.group("src")
            dst_ip = match.group("dst")
            dst_port = int(match.group("dst_port"))

            normalized_utc, tz_str, notes = _try_normalize_timestamp(raw_ts)

            timestamp = _make_timestamp(
                original_value=raw_ts,
                normalized_utc=normalized_utc,
                timezone_str=tz_str,
                confidence=ConfidenceLevel.CONFIRMED if normalized_utc else ConfidenceLevel.UNKNOWN,
                parsing_notes=notes,
            )

            source_ref = _make_source_ref(
                file_id=file_id,
                line_start=line_num,
                line_end=line_num,
                excerpt=line_stripped,
                parser_name="firewall_log",
            )

            event = NormalizedEvent(
                event_id=str(uuid4()),
                source_refs=[source_ref],
                timestamps=[timestamp],
                host=None,
                user=None,
                process_name=None,
                command_line=None,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                file_path=None,
                event_type=f"firewall_{action.lower()}_{proto.lower()}",
                raw_excerpt=line_stripped,
            )
            events.append(event)

        return events

    def parse_vpn_log(self, content: str, file_id: str) -> list[NormalizedEvent]:
        """Parse VPN log format into NormalizedEvents.

        Handles lines like:
        "2024-01-15 10:30:00 user@vpn connected from 203.0.113.1"
        """
        events: list[NormalizedEvent] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            match = _VPN_RE.match(line_stripped)
            if not match:
                continue

            raw_ts = match.group("timestamp")
            user = match.group("user")
            vpn_host = match.group("vpn_host")
            action = match.group("action")
            src_ip = match.group("src_ip")

            normalized_utc, tz_str, notes = _try_normalize_timestamp(raw_ts)

            timestamp = _make_timestamp(
                original_value=raw_ts,
                normalized_utc=normalized_utc,
                timezone_str=tz_str,
                confidence=ConfidenceLevel.CONFIRMED if normalized_utc else ConfidenceLevel.UNKNOWN,
                parsing_notes=notes,
            )

            source_ref = _make_source_ref(
                file_id=file_id,
                line_start=line_num,
                line_end=line_num,
                excerpt=line_stripped,
                parser_name="vpn_log",
            )

            event = NormalizedEvent(
                event_id=str(uuid4()),
                source_refs=[source_ref],
                timestamps=[timestamp],
                host=vpn_host,
                user=user,
                process_name=None,
                command_line=None,
                src_ip=src_ip,
                dst_ip=None,
                dst_port=None,
                file_path=None,
                event_type=f"vpn_{action.lower()}",
                raw_excerpt=line_stripped,
            )
            events.append(event)

        return events


# --- Helper functions ---


def _extract_ip_from_message(message: str, prefix: str = "from") -> Optional[str]:
    """Extract an IP address following a given prefix in a message string."""
    pattern = rf"\b{prefix}\s+(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}})"
    match = re.search(pattern, message)
    return match.group(1) if match else None


def _extract_user_from_message(message: str) -> Optional[str]:
    """Extract username from common syslog message patterns."""
    # "for user" pattern (e.g., "Accepted publickey for user from ...")
    match = re.search(r"\bfor\s+(\S+?)(?:\s+from|\s*$)", message)
    if match:
        return match.group(1)
    # "user=" pattern
    match = re.search(r"\buser=(\S+)", message)
    if match:
        return match.group(1)
    return None


def _classify_syslog_event(message: str, process: str) -> str:
    """Classify a syslog event based on message content and process name."""
    msg_lower = message.lower()
    if "accepted" in msg_lower and ("publickey" in msg_lower or "password" in msg_lower):
        return "authentication_success"
    if "failed" in msg_lower and ("password" in msg_lower or "auth" in msg_lower):
        return "authentication_failure"
    if "session opened" in msg_lower:
        return "session_start"
    if "session closed" in msg_lower:
        return "session_end"
    if "connection" in msg_lower and "closed" in msg_lower:
        return "connection_closed"
    if "connection" in msg_lower:
        return "connection"
    if "error" in msg_lower or "fail" in msg_lower:
        return "error"
    return f"syslog_{process.lower()}"


def _build_csv_column_map(fieldnames: list[str]) -> dict[str, str]:
    """Build a mapping from NormalizedEvent fields to CSV column names.

    Handles common column naming patterns.
    """
    field_patterns: dict[str, list[str]] = {
        "timestamp": [
            "timestamp", "time", "datetime", "date_time", "event_time",
            "created", "created_at", "log_time", "eventtime",
        ],
        "host": [
            "host", "hostname", "computer", "computer_name", "server",
            "machine", "source_host", "system",
        ],
        "user": [
            "user", "username", "user_name", "account", "account_name",
            "subject_user", "target_user",
        ],
        "process_name": [
            "process", "process_name", "processname", "program",
            "application", "app", "service",
        ],
        "command_line": [
            "command_line", "commandline", "cmd", "command",
            "process_command_line",
        ],
        "src_ip": [
            "src_ip", "source_ip", "source_address", "srcip",
            "client_ip", "remote_ip", "ip_address",
        ],
        "dst_ip": [
            "dst_ip", "dest_ip", "destination_ip", "destination_address",
            "dstip", "target_ip", "server_ip",
        ],
        "dst_port": [
            "dst_port", "dest_port", "destination_port", "dstport",
            "target_port", "port",
        ],
        "file_path": [
            "file_path", "filepath", "file", "path", "object_name",
            "filename", "target_filename",
        ],
        "event_type": [
            "event_type", "eventtype", "type", "action", "event_name",
            "category", "event_category",
        ],
    }

    col_map: dict[str, str] = {}
    normalized_fields = {name.lower().strip(): name for name in fieldnames}

    for field, patterns in field_patterns.items():
        for pattern in patterns:
            if pattern in normalized_fields:
                col_map[field] = normalized_fields[pattern]
                break

    return col_map


def _get_csv_value(
    row: dict[str, str], col_map: dict[str, str], field: str
) -> Optional[str]:
    """Get a value from a CSV row using the column mapping."""
    col_name = col_map.get(field)
    if col_name is None:
        return None
    value = row.get(col_name, "").strip()
    return value if value else None


def _safe_int(value: Optional[str]) -> Optional[int]:
    """Safely convert a string to int, returning None on failure."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
