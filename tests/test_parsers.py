"""Unit tests for RuleBasedParser.

Tests cover:
- Syslog parsing: standard syslog format with timestamps, hosts, processes
- Windows Event Log parsing: XML-based event log format
- CSV parsing: header-based CSV log exports
- Firewall log parsing: ALLOW/DENY with protocol and IP:port
- VPN log parsing: user@host connected from IP
- SourceReference correctness: sha256, line numbers, parser_name
- EventTimestamp correctness: normalized_utc, confidence

Requirements: 4.2, 26.1, 26.2
"""

import hashlib

import pytest

from ir_agent.extraction.parsers import RuleBasedParser
from ir_agent.models.enums import ConfidenceLevel


@pytest.fixture
def parser() -> RuleBasedParser:
    return RuleBasedParser()


class TestParseSyslog:
    """Tests for syslog format parsing."""

    def test_parses_standard_syslog_line(self, parser: RuleBasedParser):
        content = "Jan 15 10:30:00 host01 sshd[1234]: Accepted publickey for user from 192.168.1.1"
        events = parser.parse_syslog(content, "file-001")

        assert len(events) == 1
        ev = events[0]
        assert ev.host == "host01"
        assert ev.process_name == "sshd"
        assert ev.src_ip == "192.168.1.1"
        assert ev.user == "user"
        assert ev.event_type == "authentication_success"

    def test_source_reference_fields(self, parser: RuleBasedParser):
        content = "Jan 15 10:30:00 host01 sshd[1234]: Accepted publickey for admin from 10.0.0.1"
        events = parser.parse_syslog(content, "file-001")

        ref = events[0].source_refs[0]
        assert ref.source_file_id == "file-001"
        assert ref.source_lines == (1, 1)
        assert ref.parser_name == "syslog"
        assert ref.parser_version == "1.0.0"
        # Verify SHA-256 integrity
        expected_sha = hashlib.sha256(ref.excerpt.encode("utf-8")).hexdigest()
        assert ref.excerpt_sha256 == expected_sha

    def test_timestamp_parsing(self, parser: RuleBasedParser):
        content = "Jan 15 10:30:00 host01 sshd[1234]: test message"
        events = parser.parse_syslog(content, "file-001")

        ts = events[0].timestamps[0]
        assert ts.original_value == "Jan 15 10:30:00"
        assert ts.timestamp_type == "event_time"
        assert ts.confidence == ConfidenceLevel.PROBABLE

    def test_multiple_lines(self, parser: RuleBasedParser):
        content = (
            "Jan 15 10:30:00 host01 sshd[1234]: Accepted publickey for user from 10.0.0.1\n"
            "Jan 15 10:30:01 host01 sshd[1235]: session opened for user\n"
            "Jan 15 10:30:02 host02 kernel: error message\n"
        )
        events = parser.parse_syslog(content, "file-001")

        assert len(events) == 3
        assert events[0].source_refs[0].source_lines == (1, 1)
        assert events[1].source_refs[0].source_lines == (2, 2)
        assert events[2].source_refs[0].source_lines == (3, 3)

    def test_skips_empty_lines(self, parser: RuleBasedParser):
        content = "\n\nJan 15 10:30:00 host01 sshd[1234]: test\n\n"
        events = parser.parse_syslog(content, "file-001")
        assert len(events) == 1

    def test_failed_auth_event_type(self, parser: RuleBasedParser):
        content = "Jan 15 10:30:00 host01 sshd[1234]: Failed password for admin from 10.0.0.1"
        events = parser.parse_syslog(content, "file-001")
        assert events[0].event_type == "authentication_failure"

    def test_event_id_is_uuid(self, parser: RuleBasedParser):
        content = "Jan 15 10:30:00 host01 sshd[1234]: test message"
        events = parser.parse_syslog(content, "file-001")
        assert len(events[0].event_id) == 36  # UUID format


class TestParseWindowsEventLog:
    """Tests for Windows Event Log XML parsing."""

    def test_parses_single_event(self, parser: RuleBasedParser):
        content = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2024-01-15T10:30:00.000Z"/>
    <Computer>WORKSTATION01</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="IpAddress">192.168.1.100</Data>
    <Data Name="ProcessName">C:\\Windows\\System32\\lsass.exe</Data>
  </EventData>
</Event>"""
        events = parser.parse_windows_event_log(content, "file-002")

        assert len(events) == 1
        ev = events[0]
        assert ev.host == "WORKSTATION01"
        assert ev.user == "admin"
        assert ev.src_ip == "192.168.1.100"
        assert ev.process_name == "C:\\Windows\\System32\\lsass.exe"
        assert ev.event_type == "windows_event_4624"

    def test_timestamp_confirmed_confidence(self, parser: RuleBasedParser):
        content = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2024-01-15T10:30:00.000Z"/>
    <Computer>WS01</Computer>
  </System>
  <EventData/>
</Event>"""
        events = parser.parse_windows_event_log(content, "file-002")

        ts = events[0].timestamps[0]
        assert ts.normalized_utc is not None
        assert ts.confidence == ConfidenceLevel.CONFIRMED

    def test_source_reference_parser_name(self, parser: RuleBasedParser):
        content = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2024-01-15T10:30:00Z"/>
    <Computer>SRV01</Computer>
  </System>
  <EventData/>
</Event>"""
        events = parser.parse_windows_event_log(content, "file-002")
        assert events[0].source_refs[0].parser_name == "windows_event_log"

    def test_parses_multiple_events(self, parser: RuleBasedParser):
        content = """<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4624</EventID><TimeCreated SystemTime="2024-01-15T10:30:00Z"/><Computer>WS01</Computer></System>
  <EventData><Data Name="TargetUserName">user1</Data></EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4625</EventID><TimeCreated SystemTime="2024-01-15T10:31:00Z"/><Computer>WS02</Computer></System>
  <EventData><Data Name="TargetUserName">user2</Data></EventData>
</Event>
</Events>"""
        events = parser.parse_windows_event_log(content, "file-002")
        assert len(events) == 2
        assert events[0].user == "user1"
        assert events[1].user == "user2"


class TestParseCsv:
    """Tests for CSV log export parsing."""

    def test_parses_basic_csv(self, parser: RuleBasedParser):
        content = (
            "timestamp,host,user,src_ip,event_type\n"
            "2024-01-15 10:30:00,host01,admin,192.168.1.1,login\n"
        )
        events = parser.parse_csv(content, "file-003")

        assert len(events) == 1
        ev = events[0]
        assert ev.host == "host01"
        assert ev.user == "admin"
        assert ev.src_ip == "192.168.1.1"
        assert ev.event_type == "login"

    def test_csv_timestamp_normalization(self, parser: RuleBasedParser):
        content = (
            "timestamp,host,event_type\n"
            "2024-01-15 10:30:00,host01,test\n"
        )
        events = parser.parse_csv(content, "file-003")
        ts = events[0].timestamps[0]
        assert ts.normalized_utc is not None
        assert "2024-01-15" in ts.normalized_utc

    def test_csv_column_mapping_variations(self, parser: RuleBasedParser):
        content = (
            "datetime,hostname,username,source_ip,destination_ip,dest_port,action\n"
            "2024-01-15 10:30:00,srv01,bob,10.0.0.1,10.0.0.2,443,allow\n"
        )
        events = parser.parse_csv(content, "file-003")

        ev = events[0]
        assert ev.host == "srv01"
        assert ev.user == "bob"
        assert ev.src_ip == "10.0.0.1"
        assert ev.dst_ip == "10.0.0.2"
        assert ev.dst_port == 443
        assert ev.event_type == "allow"

    def test_csv_source_reference(self, parser: RuleBasedParser):
        content = (
            "timestamp,host,event_type\n"
            "2024-01-15 10:30:00,host01,test\n"
            "2024-01-15 10:31:00,host02,test2\n"
        )
        events = parser.parse_csv(content, "file-003")
        # Row 2 (0-indexed line 2, 1-indexed line 2 after header)
        assert events[0].source_refs[0].source_lines == (2, 2)
        assert events[1].source_refs[0].source_lines == (3, 3)
        assert events[0].source_refs[0].parser_name == "csv"

    def test_empty_csv_returns_no_events(self, parser: RuleBasedParser):
        events = parser.parse_csv("", "file-003")
        assert events == []


class TestParseFirewallLog:
    """Tests for firewall log parsing."""

    def test_parses_allow_rule(self, parser: RuleBasedParser):
        content = "2024-01-15 10:30:00 ALLOW TCP 192.168.1.1:12345 -> 10.0.0.1:443"
        events = parser.parse_firewall_log(content, "file-004")

        assert len(events) == 1
        ev = events[0]
        assert ev.src_ip == "192.168.1.1"
        assert ev.dst_ip == "10.0.0.1"
        assert ev.dst_port == 443
        assert ev.event_type == "firewall_allow_tcp"

    def test_parses_deny_rule(self, parser: RuleBasedParser):
        content = "2024-01-15 10:30:00 DENY UDP 10.0.0.5:53000 -> 8.8.8.8:53"
        events = parser.parse_firewall_log(content, "file-004")

        ev = events[0]
        assert ev.event_type == "firewall_deny_udp"
        assert ev.dst_port == 53

    def test_timestamp_normalized(self, parser: RuleBasedParser):
        content = "2024-01-15 10:30:00 ALLOW TCP 192.168.1.1:12345 -> 10.0.0.1:443"
        events = parser.parse_firewall_log(content, "file-004")

        ts = events[0].timestamps[0]
        assert ts.original_value == "2024-01-15 10:30:00"
        assert ts.normalized_utc is not None
        assert ts.confidence == ConfidenceLevel.CONFIRMED

    def test_multiple_firewall_entries(self, parser: RuleBasedParser):
        content = (
            "2024-01-15 10:30:00 ALLOW TCP 192.168.1.1:12345 -> 10.0.0.1:443\n"
            "2024-01-15 10:30:01 DENY TCP 192.168.1.2:54321 -> 10.0.0.1:22\n"
        )
        events = parser.parse_firewall_log(content, "file-004")
        assert len(events) == 2

    def test_source_reference_correctness(self, parser: RuleBasedParser):
        content = "2024-01-15 10:30:00 ALLOW TCP 192.168.1.1:12345 -> 10.0.0.1:443"
        events = parser.parse_firewall_log(content, "file-004")

        ref = events[0].source_refs[0]
        assert ref.parser_name == "firewall_log"
        assert ref.source_file_id == "file-004"
        expected_sha = hashlib.sha256(ref.excerpt.encode("utf-8")).hexdigest()
        assert ref.excerpt_sha256 == expected_sha


class TestParseVpnLog:
    """Tests for VPN log parsing."""

    def test_parses_connected_event(self, parser: RuleBasedParser):
        content = "2024-01-15 10:30:00 user@vpn connected from 203.0.113.1"
        events = parser.parse_vpn_log(content, "file-005")

        assert len(events) == 1
        ev = events[0]
        assert ev.user == "user"
        assert ev.host == "vpn"
        assert ev.src_ip == "203.0.113.1"
        assert ev.event_type == "vpn_connected"

    def test_parses_disconnected_event(self, parser: RuleBasedParser):
        content = "2024-01-15 10:35:00 admin@corp-vpn disconnected from 198.51.100.1"
        events = parser.parse_vpn_log(content, "file-005")

        ev = events[0]
        assert ev.user == "admin"
        assert ev.host == "corp-vpn"
        assert ev.event_type == "vpn_disconnected"
        assert ev.src_ip == "198.51.100.1"

    def test_timestamp_normalized(self, parser: RuleBasedParser):
        content = "2024-01-15 10:30:00 user@vpn connected from 203.0.113.1"
        events = parser.parse_vpn_log(content, "file-005")

        ts = events[0].timestamps[0]
        assert ts.normalized_utc is not None
        assert ts.confidence == ConfidenceLevel.CONFIRMED

    def test_source_reference_correctness(self, parser: RuleBasedParser):
        content = "2024-01-15 10:30:00 user@vpn connected from 203.0.113.1"
        events = parser.parse_vpn_log(content, "file-005")

        ref = events[0].source_refs[0]
        assert ref.parser_name == "vpn_log"
        assert ref.source_file_id == "file-005"
        assert ref.source_lines == (1, 1)

    def test_multiple_vpn_entries(self, parser: RuleBasedParser):
        content = (
            "2024-01-15 10:30:00 user1@vpn connected from 203.0.113.1\n"
            "2024-01-15 10:35:00 user2@vpn connected from 203.0.113.2\n"
            "2024-01-15 10:40:00 user1@vpn disconnected from 203.0.113.1\n"
        )
        events = parser.parse_vpn_log(content, "file-005")
        assert len(events) == 3
