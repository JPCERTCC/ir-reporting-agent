"""Unit tests for EntityResolver.

Validates Requirements 24.1, 24.2, 24.3, 24.4, 24.5, 24.7, 24.8:
- Entity identification (hostnames, IPs, users, file paths)
- Resolution across different artifacts
- Entity resolution table maintenance
- Ambiguity flagging for analyst review
- Confidence scoring
- Never silently merging entities
- Resolution entry fields
"""

from __future__ import annotations

import pytest

from ir_agent.extraction.entity_resolver import (
    AMBIGUITY_THRESHOLD,
    CONFIDENCE_CASE_INSENSITIVE,
    CONFIDENCE_EXACT,
    CONFIDENCE_PARTIAL,
    EntityResolver,
)
from ir_agent.models.base import SourceReference
from ir_agent.models.evidence import EntityResolutionEntry, EvidenceCandidate
from ir_agent.models.enums import ConfidenceLevel


def _make_candidate(
    candidate_id: str = "cand-001",
    observed_fact: str = "",
    interpretation: str = "",
    observed_event: dict | None = None,
    source_file_id: str = "file-001",
    source_lines: tuple[int, int] = (1, 5),
    excerpt: str = "",
) -> EvidenceCandidate:
    """Helper to create an EvidenceCandidate for testing."""
    return EvidenceCandidate(
        candidate_id=candidate_id,
        source_refs=[
            SourceReference(
                source_ref_id="ref-001",
                source_file_id=source_file_id,
                source_path="/path/to/file.log",
                source_lines=source_lines,
                excerpt=excerpt or observed_fact,
                excerpt_sha256="abc123",
            )
        ],
        observed_event=observed_event or {},
        observed_fact=observed_fact,
        interpretation=interpretation,
        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
        interpretation_confidence=ConfidenceLevel.PROBABLE,
    )


@pytest.fixture
def resolver() -> EntityResolver:
    return EntityResolver()


class TestResolveHostnames:
    """Test hostname entity resolution."""

    def test_same_hostname_different_case(self, resolver: EntityResolver) -> None:
        """Same hostname in different cases resolves to same canonical ID."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"host": "WS01"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"host": "ws01"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        hostname_entries = [e for e in entries if "ws01" in e.observed_value.lower()]
        assert len(hostname_entries) == 2
        # Both should map to the same canonical ID
        assert hostname_entries[0].canonical_entity_id == hostname_entries[1].canonical_entity_id

    def test_hostname_abbreviation_resolution(self, resolver: EntityResolver) -> None:
        """Abbreviated hostnames (e.g., WS01 vs WORKSTATION01) are resolved."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"host": "ws01"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"host": "workstation01"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        hostname_entries = [
            e for e in entries if "ws01" in e.observed_value.lower() or "workstation01" in e.observed_value.lower()
        ]
        assert len(hostname_entries) == 2
        assert hostname_entries[0].canonical_entity_id == hostname_entries[1].canonical_entity_id
        # Second entry should have high confidence abbreviation match
        assert hostname_entries[1].resolution_confidence >= AMBIGUITY_THRESHOLD

    def test_different_hostnames_get_different_ids(self, resolver: EntityResolver) -> None:
        """Different hostnames get different canonical IDs."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"host": "WS01"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"host": "SRV02"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        hostname_entries = [e for e in entries if "ws01" in e.observed_value.lower() or "srv02" in e.observed_value.lower()]
        assert len(hostname_entries) == 2
        assert hostname_entries[0].canonical_entity_id != hostname_entries[1].canonical_entity_id


class TestResolveIPAddresses:
    """Test IP address entity resolution."""

    def test_same_ip_resolves_to_same_id(self, resolver: EntityResolver) -> None:
        """Same IP in different candidates resolves to same canonical ID."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"src_ip": "192.168.1.100"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"dst_ip": "192.168.1.100"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        ip_entries = [e for e in entries if "192.168.1.100" in e.observed_value]
        assert len(ip_entries) == 2
        assert ip_entries[0].canonical_entity_id == ip_entries[1].canonical_entity_id

    def test_different_ips_get_different_ids(self, resolver: EntityResolver) -> None:
        """Different IP addresses get different canonical IDs."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"src_ip": "192.168.1.100"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"src_ip": "10.0.0.1"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        ip_entries = [e for e in entries if "192.168" in e.observed_value or "10.0.0" in e.observed_value]
        assert len(ip_entries) == 2
        assert ip_entries[0].canonical_entity_id != ip_entries[1].canonical_entity_id

    def test_ip_extracted_from_text(self, resolver: EntityResolver) -> None:
        """IPs are extracted from observed_fact text."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_fact="Connection from 10.0.0.5 to external host",
        )
        entries = resolver.resolve_entities([c1])
        ip_entries = [e for e in entries if "10.0.0.5" in e.observed_value]
        assert len(ip_entries) >= 1


class TestResolveUsers:
    """Test user account entity resolution."""

    def test_user_alias_resolution(self, resolver: EntityResolver) -> None:
        """Known user aliases (e.g., admin vs Administrator) are resolved."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"user": "admin"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"user": "Administrator"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        user_entries = [
            e for e in entries
            if "admin" in e.observed_value.lower()
        ]
        assert len(user_entries) == 2
        assert user_entries[0].canonical_entity_id == user_entries[1].canonical_entity_id

    def test_domain_user_resolution(self, resolver: EntityResolver) -> None:
        """DOMAIN\\user resolves to same entity as bare username."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"user": "jsmith"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"user": "CORP\\jsmith"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        user_entries = [
            e for e in entries
            if "jsmith" in e.observed_value.lower()
        ]
        assert len(user_entries) == 2
        assert user_entries[0].canonical_entity_id == user_entries[1].canonical_entity_id

    def test_different_users_get_different_ids(self, resolver: EntityResolver) -> None:
        """Different usernames get different canonical IDs."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"user": "alice"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"user": "bob"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        user_entries = [
            e for e in entries
            if e.observed_value.lower() in ("alice", "bob")
        ]
        assert len(user_entries) == 2
        assert user_entries[0].canonical_entity_id != user_entries[1].canonical_entity_id


class TestResolveFilePaths:
    """Test file path entity resolution."""

    def test_same_path_different_case(self, resolver: EntityResolver) -> None:
        """Same Windows path in different cases resolves to same ID."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"file_path": r"C:\Windows\System32\evil.dll"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"file_path": r"c:\windows\system32\evil.dll"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        path_entries = [e for e in entries if "evil.dll" in e.observed_value.lower()]
        assert len(path_entries) == 2
        assert path_entries[0].canonical_entity_id == path_entries[1].canonical_entity_id

    def test_same_filename_different_dir_flagged_ambiguous(self, resolver: EntityResolver) -> None:
        """Same filename in different directories is flagged as ambiguous."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"file_path": r"C:\Temp\payload.exe"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"file_path": r"C:\Users\Admin\payload.exe"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        path_entries = [e for e in entries if "payload.exe" in e.observed_value.lower()]
        assert len(path_entries) == 2
        # The second entry should be flagged as ambiguous (confidence < 0.8)
        second = path_entries[1]
        assert second.resolution_confidence < AMBIGUITY_THRESHOLD
        assert second.review_status == "pending"


class TestAmbiguityFlagging:
    """Test that ambiguous resolutions are flagged for analyst review."""

    def test_low_confidence_flagged_pending(self, resolver: EntityResolver) -> None:
        """Resolutions with confidence < 0.8 have review_status='pending'."""
        # Partial match scenario: same filename, different path
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"file_path": "/opt/app/config.yaml"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"file_path": "/etc/app/config.yaml"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        ambiguous_entries = [e for e in entries if e.review_status == "pending"]
        assert len(ambiguous_entries) >= 1

    def test_high_confidence_approved(self, resolver: EntityResolver) -> None:
        """Exact match resolutions have review_status='approved'."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"src_ip": "192.168.1.1"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"src_ip": "192.168.1.1"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        ip_entries = [e for e in entries if "192.168.1.1" in e.observed_value]
        assert all(e.review_status == "approved" for e in ip_entries)

    def test_never_silently_merges(self, resolver: EntityResolver) -> None:
        """Ambiguous entities are never merged without flagging."""
        # Partial username match (one is substring of other)
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"user": "john"},
            source_file_id="file-001",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_event={"user": "johnson"},
            source_file_id="file-002",
        )
        entries = resolver.resolve_entities([c1, c2])
        user_entries = [
            e for e in entries
            if e.observed_value.lower() in ("john", "johnson")
        ]
        # If merged, the second should have pending review_status
        if len(user_entries) == 2 and user_entries[0].canonical_entity_id == user_entries[1].canonical_entity_id:
            assert user_entries[1].review_status == "pending"


class TestGetCanonicalId:
    """Test get_canonical_id lookup method."""

    def test_returns_id_for_resolved_entity(self, resolver: EntityResolver) -> None:
        """get_canonical_id returns the canonical ID for a resolved entity."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"host": "SERVER01"},
        )
        resolver.resolve_entities([c1])
        canonical_id = resolver.get_canonical_id("SERVER01")
        assert canonical_id is not None

    def test_returns_none_for_unknown(self, resolver: EntityResolver) -> None:
        """get_canonical_id returns None for an unknown observed value."""
        assert resolver.get_canonical_id("unknown-entity") is None

    def test_case_insensitive_lookup(self, resolver: EntityResolver) -> None:
        """get_canonical_id is case-insensitive."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"host": "MyHost"},
        )
        resolver.resolve_entities([c1])
        id1 = resolver.get_canonical_id("MyHost")
        id2 = resolver.get_canonical_id("myhost")
        id3 = resolver.get_canonical_id("MYHOST")
        assert id1 == id2 == id3


class TestResolutionEntryFields:
    """Test that EntityResolutionEntry fields are populated correctly (Req 24.8)."""

    def test_entry_has_all_required_fields(self, resolver: EntityResolver) -> None:
        """Each entry has canonical_entity_id, observed_value, source_file_id,
        source_lines, resolution_confidence, resolution_reason, review_status."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"host": "DC01"},
            source_file_id="my-file",
            source_lines=(10, 20),
        )
        entries = resolver.resolve_entities([c1])
        assert len(entries) >= 1
        entry = entries[0]
        assert entry.canonical_entity_id
        assert entry.observed_value == "DC01"
        assert entry.source_file_id == "my-file"
        assert entry.source_lines == (10, 20)
        assert 0.0 <= entry.resolution_confidence <= 1.0
        assert entry.resolution_reason
        assert entry.review_status in ("pending", "approved", "rejected")

    def test_confidence_scores_range(self, resolver: EntityResolver) -> None:
        """Confidence scores are within valid range [0.0, 1.0]."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_event={"host": "WS01", "user": "admin", "src_ip": "10.0.0.1"},
            source_file_id="file-001",
        )
        entries = resolver.resolve_entities([c1])
        for entry in entries:
            assert 0.0 <= entry.resolution_confidence <= 1.0


class TestEmptyInput:
    """Test behavior with empty or minimal inputs."""

    def test_empty_candidates_list(self, resolver: EntityResolver) -> None:
        """Empty candidate list returns empty entries list."""
        entries = resolver.resolve_entities([])
        assert entries == []

    def test_candidate_with_no_entities(self, resolver: EntityResolver) -> None:
        """A candidate with no extractable entities returns no entries."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_fact="No entities here.",
            observed_event={},
        )
        entries = resolver.resolve_entities([c1])
        assert entries == []
