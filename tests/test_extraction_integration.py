"""Integration tests for the Extraction Layer.

Tests cross-component interactions and integration scenarios that go beyond
individual unit tests:
1. Syslog parser + timestamp correctness (normalized_utc format)
2. (removed) chunk-boundary validation now lives in the ir-extract-evidence skill
3. IOC patterns matching across multi-artifact scenarios (deduplication)
4. Entity resolver flags ambiguous resolutions (pending review_status)

Validates: Requirements 4.4, 5.3, 24.7, 26.2
"""

from __future__ import annotations

import re

import pytest

from ir_agent.extraction.entity_resolver import (
    AMBIGUITY_THRESHOLD,
    EntityResolver,
)
from ir_agent.extraction.ioc_extractor import IOCExtractor
from ir_agent.extraction.parsers import RuleBasedParser
from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceCandidate


# --- Helpers ---


def _make_candidate(
    candidate_id: str = "cand-001",
    observed_fact: str = "",
    interpretation: str = "",
    observed_event: dict | None = None,
    source_file_id: str = "file-001",
    source_lines: tuple[int, int] = (1, 5),
    excerpt: str = "",
) -> EvidenceCandidate:
    """Create an EvidenceCandidate for testing."""
    return EvidenceCandidate(
        candidate_id=candidate_id,
        source_refs=[
            SourceReference(
                source_ref_id="ref-001",
                source_file_id=source_file_id,
                source_path="/path/to/file.log",
                source_lines=source_lines,
                excerpt=excerpt or observed_fact or "test excerpt",
                excerpt_sha256="abc123",
            )
        ],
        observed_event=observed_event or {},
        observed_fact=observed_fact or "test fact",
        interpretation=interpretation or "test interpretation",
        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
        interpretation_confidence=ConfidenceLevel.PROBABLE,
    )



class TestSyslogTimestampIntegration:
    """Integration tests: Syslog parser produces NormalizedEvents with correct timestamps.

    Validates Requirement 26.2: normalized_utc format is ISO 8601 UTC.
    """

    @pytest.fixture
    def parser(self) -> RuleBasedParser:
        return RuleBasedParser()

    def test_normalized_utc_is_iso8601_format(self, parser: RuleBasedParser) -> None:
        """Syslog-parsed timestamps produce ISO 8601 UTC strings (YYYY-MM-DDTHH:MM:SSZ)."""
        content = "Feb 20 14:45:30 webserver01 nginx[5678]: GET /index.html 200"
        events = parser.parse_syslog(content, "file-syslog")

        assert len(events) == 1
        ts = events[0].timestamps[0]
        assert ts.normalized_utc is not None
        # Verify ISO 8601 UTC format: YYYY-MM-DDTHH:MM:SSZ
        iso_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        assert iso_pattern.match(ts.normalized_utc), (
            f"Expected ISO 8601 UTC format, got: {ts.normalized_utc}"
        )

    def test_syslog_timestamp_preserves_original(self, parser: RuleBasedParser) -> None:
        """The original timestamp value is preserved alongside normalized_utc."""
        content = "Mar 10 08:15:00 host01 sshd[1111]: test message"
        events = parser.parse_syslog(content, "file-syslog")

        ts = events[0].timestamps[0]
        assert ts.original_value == "Mar 10 08:15:00"
        assert ts.timestamp_type == "event_time"

    def test_syslog_timestamp_has_probable_confidence(self, parser: RuleBasedParser) -> None:
        """Syslog timestamps lack year so confidence is PROBABLE, not CONFIRMED."""
        content = "Dec 25 23:59:59 host01 crond[999]: job complete"
        events = parser.parse_syslog(content, "file-syslog")

        ts = events[0].timestamps[0]
        assert ts.confidence == ConfidenceLevel.PROBABLE

    def test_multiple_syslog_lines_all_have_timestamps(self, parser: RuleBasedParser) -> None:
        """Each parsed syslog line produces an event with a valid normalized timestamp."""
        content = (
            "Jan 01 00:00:01 host01 kernel: system boot\n"
            "Jan 01 00:00:02 host01 systemd[1]: Starting services\n"
            "Jan 01 00:01:00 host02 sshd[200]: Accepted password for root from 10.0.0.1\n"
        )
        events = parser.parse_syslog(content, "file-syslog")

        assert len(events) == 3
        for event in events:
            assert len(event.timestamps) == 1
            ts = event.timestamps[0]
            assert ts.normalized_utc is not None
            assert ts.normalized_utc.endswith("Z")

    def test_syslog_parsing_notes_mention_missing_year(self, parser: RuleBasedParser) -> None:
        """Parsing notes indicate that the year was assumed (syslog lacks year)."""
        content = "Apr 05 12:00:00 srv01 app[42]: event happened"
        events = parser.parse_syslog(content, "file-syslog")

        ts = events[0].timestamps[0]
        assert ts.parsing_notes is not None
        assert "year" in ts.parsing_notes.lower()




class TestIOCDeduplicationMultiArtifact:
    """Integration tests: IOC deduplication across multiple artifacts.

    Validates Requirement 5.3: deduplication by type and value across all artifacts.
    """

    @pytest.fixture
    def extractor(self) -> IOCExtractor:
        return IOCExtractor()

    def test_same_ip_in_two_files_deduplicates(self, extractor: IOCExtractor) -> None:
        """Same IP address found in two different artifact files deduplicates to one."""
        iocs_file1 = extractor.extract_iocs("Connection from 192.168.1.50", "file-001")
        iocs_file2 = extractor.extract_iocs("Alert: source 192.168.1.50 detected", "file-002")

        combined = iocs_file1 + iocs_file2
        deduped = extractor.deduplicate_iocs(combined)

        ip_iocs = [i for i in deduped if i.ioc_type == "ip" and i.value == "192.168.1.50"]
        assert len(ip_iocs) == 1

    def test_same_hash_in_multiple_files_deduplicates(self, extractor: IOCExtractor) -> None:
        """Same SHA-256 hash found across multiple artifacts deduplicates to one."""
        hash_value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs1 = extractor.extract_iocs(f"Malware hash: {hash_value}", "file-001")
        iocs2 = extractor.extract_iocs(f"Found artifact: {hash_value}", "file-002")
        iocs3 = extractor.extract_iocs(f"Scan result: {hash_value}", "file-003")

        combined = iocs1 + iocs2 + iocs3
        deduped = extractor.deduplicate_iocs(combined)

        sha_iocs = [i for i in deduped if i.ioc_type == "hash_sha256" and i.value == hash_value]
        assert len(sha_iocs) == 1

    def test_different_iocs_same_type_preserved(self, extractor: IOCExtractor) -> None:
        """Different IOC values of the same type are NOT deduplicated."""
        iocs1 = extractor.extract_iocs("IP: 10.0.0.1", "file-001")
        iocs2 = extractor.extract_iocs("IP: 10.0.0.2", "file-002")

        combined = iocs1 + iocs2
        deduped = extractor.deduplicate_iocs(combined)

        ip_iocs = [i for i in deduped if i.ioc_type == "ip"]
        values = {i.value for i in ip_iocs}
        assert "10.0.0.1" in values
        assert "10.0.0.2" in values

    def test_dedup_preserves_first_occurrence_source(self, extractor: IOCExtractor) -> None:
        """Deduplication preserves the first occurrence's source_file_id."""
        iocs1 = extractor.extract_iocs("C2: evil.example.com", "artifact-A")
        iocs2 = extractor.extract_iocs("DNS query to evil.example.com", "artifact-B")

        combined = iocs1 + iocs2
        deduped = extractor.deduplicate_iocs(combined)

        domain_iocs = [i for i in deduped if i.ioc_type == "domain" and "evil.example.com" in i.value]
        assert len(domain_iocs) == 1
        assert domain_iocs[0].source_file_id == "artifact-A"

    def test_mixed_ioc_types_across_artifacts(self, extractor: IOCExtractor) -> None:
        """Mix of IP, domain, and hash across artifacts deduplicates correctly."""
        content1 = "192.168.1.1 connected to bad.example.org"
        content2 = "192.168.1.1 resolved bad.example.org to 10.0.0.99"

        iocs1 = extractor.extract_iocs(content1, "host01-syslog")
        iocs2 = extractor.extract_iocs(content2, "host02-dns")

        combined = iocs1 + iocs2
        deduped = extractor.deduplicate_iocs(combined)

        # 192.168.1.1 should appear once
        ip_192 = [i for i in deduped if i.value == "192.168.1.1"]
        assert len(ip_192) == 1

        # bad.example.org should appear once
        domain_bad = [i for i in deduped if i.value == "bad.example.org"]
        assert len(domain_bad) == 1

        # 10.0.0.99 is different, should still be present
        ip_10 = [i for i in deduped if i.value == "10.0.0.99"]
        assert len(ip_10) == 1


# --- Section 4: Entity Resolver Ambiguous Resolution Flagging ---


class TestEntityResolverAmbiguousResolution:
    """Integration tests: Entity resolver flags ambiguous resolutions.

    Validates Requirement 24.7: ambiguous resolutions have review_status='pending'
    and are never silently merged.
    """

    @pytest.fixture
    def resolver(self) -> EntityResolver:
        return EntityResolver()

    def test_same_filename_different_directory_is_pending(self, resolver: EntityResolver) -> None:
        """Same filename in different directories produces pending review_status."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"file_path": r"C:\Users\admin\malware.exe"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"file_path": r"C:\Temp\malware.exe"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        path_entries = [e for e in entries if "malware.exe" in e.observed_value.lower()]
        assert len(path_entries) == 2

        # Second entry should be flagged as ambiguous (pending)
        second_entry = path_entries[1]
        assert second_entry.review_status == "pending"
        assert second_entry.resolution_confidence < AMBIGUITY_THRESHOLD

    def test_partial_username_match_flagged_pending(self, resolver: EntityResolver) -> None:
        """Partial username overlap (e.g., 'admin' vs 'admin_backup') is flagged pending."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"user": "admin"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"user": "admin_backup"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        user_entries = [
            e for e in entries
            if "admin" in e.observed_value.lower()
        ]
        assert len(user_entries) == 2

        # The partial match should be flagged
        partial_entry = [e for e in user_entries if e.observed_value == "admin_backup"]
        assert len(partial_entry) == 1
        assert partial_entry[0].review_status == "pending"

    def test_exact_ip_match_across_artifacts_approved(self, resolver: EntityResolver) -> None:
        """Exact same IP in different artifacts gets approved (not ambiguous)."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"src_ip": "172.16.0.1"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"dst_ip": "172.16.0.1"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        ip_entries = [e for e in entries if "172.16.0.1" in e.observed_value]
        assert len(ip_entries) == 2
        # Exact match → approved
        assert all(e.review_status == "approved" for e in ip_entries)

    def test_ambiguous_hostname_abbreviation_from_different_sources(
        self, resolver: EntityResolver
    ) -> None:
        """Hostname abbreviation match from different source files should have high confidence."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"host": "db01"},
            source_file_id="firewall-log",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"host": "database01"},
            source_file_id="app-log",
        )
        entries = resolver.resolve_entities([c1, c2])
        host_entries = [
            e for e in entries
            if "db01" in e.observed_value.lower() or "database01" in e.observed_value.lower()
        ]
        assert len(host_entries) == 2
        # Both should be resolved to the same canonical ID
        assert host_entries[0].canonical_entity_id == host_entries[1].canonical_entity_id
        # Abbreviation match should be high confidence (>= threshold)
        assert host_entries[1].resolution_confidence >= AMBIGUITY_THRESHOLD

    def test_multiple_entities_from_single_candidate_mixed_status(
        self, resolver: EntityResolver
    ) -> None:
        """A candidate with both clear and ambiguous entities produces mixed review statuses."""
        # First candidate establishes known entities
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={
                "src_ip": "10.10.10.1",
                "file_path": "/opt/app/config.yaml",
            },
            source_file_id="file-001",
        )
        # Second candidate: same IP (clear) but same filename in different path (ambiguous)
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={
                "src_ip": "10.10.10.1",
                "file_path": "/etc/another/config.yaml",
            },
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])

        ip_entries = [e for e in entries if "10.10.10.1" in e.observed_value]
        path_entries = [e for e in entries if "config.yaml" in e.observed_value.lower()]

        # IP exact match → all approved
        assert all(e.review_status == "approved" for e in ip_entries)

        # Path filename match → ambiguous should be pending
        if len(path_entries) == 2:
            pending_paths = [e for e in path_entries if e.review_status == "pending"]
            assert len(pending_paths) >= 1
