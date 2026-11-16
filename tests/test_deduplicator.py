"""Unit tests for EvidenceDeduplicator.

Validates Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
- 6.1: Identify candidates describing same observed event from same/overlapping source data
- 6.2: Merge duplicates into single candidate preserving all source references
- 6.3: Recalculate confidence (NOT auto-highest) based on multi-factor analysis
- 6.4: Record merge operation with references to all original candidate_ids
- 6.5: Preserve each original candidate_id, source_file_id, source_lines, excerpt
- 6.6: Group related but non-duplicate candidates as corroborating evidence
"""

from __future__ import annotations

import pytest

from ir_agent.evidence.deduplicator import (
    CORROBORATING_SIMILARITY_THRESHOLD,
    DUPLICATE_SIMILARITY_THRESHOLD,
    EvidenceDeduplicator,
    _source_refs_overlap,
    _word_overlap_similarity,
)
from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceCandidate


def _make_source_ref(
    source_ref_id: str = "ref-001",
    source_file_id: str = "file-001",
    source_path: str = "/path/to/file.log",
    source_lines: tuple[int, int] = (1, 5),
    excerpt: str = "sample log entry",
    excerpt_sha256: str = "abc123",
    parser_name: str | None = None,
) -> SourceReference:
    """Helper to create a SourceReference for testing."""
    return SourceReference(
        source_ref_id=source_ref_id,
        source_file_id=source_file_id,
        source_path=source_path,
        source_lines=source_lines,
        excerpt=excerpt,
        excerpt_sha256=excerpt_sha256,
        parser_name=parser_name,
    )


def _make_candidate(
    candidate_id: str = "cand-001",
    source_refs: list[SourceReference] | None = None,
    observed_event: dict | None = None,
    observed_fact: str = "Malicious process executed on host",
    interpretation: str = "Possible lateral movement attempt",
    observed_fact_confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
    interpretation_confidence: ConfidenceLevel = ConfidenceLevel.PROBABLE,
    from_normalized_event_ids: list[str] | None = None,
) -> EvidenceCandidate:
    """Helper to create an EvidenceCandidate for testing."""
    if source_refs is None:
        source_refs = [_make_source_ref()]
    return EvidenceCandidate(
        candidate_id=candidate_id,
        source_refs=source_refs,
        observed_event=observed_event or {},
        observed_fact=observed_fact,
        interpretation=interpretation,
        observed_fact_confidence=observed_fact_confidence,
        interpretation_confidence=interpretation_confidence,
        from_normalized_event_ids=from_normalized_event_ids or [],
    )


@pytest.fixture
def deduplicator() -> EvidenceDeduplicator:
    return EvidenceDeduplicator()


class TestWordOverlapSimilarity:
    """Test the word overlap similarity function."""

    def test_identical_texts(self) -> None:
        assert _word_overlap_similarity("hello world", "hello world") == 1.0

    def test_completely_different(self) -> None:
        assert _word_overlap_similarity("hello world", "foo bar") == 0.0

    def test_partial_overlap(self) -> None:
        sim = _word_overlap_similarity("hello world foo", "hello world bar")
        assert 0.0 < sim < 1.0

    def test_empty_strings(self) -> None:
        assert _word_overlap_similarity("", "") == 1.0

    def test_one_empty(self) -> None:
        assert _word_overlap_similarity("hello", "") == 0.0

    def test_case_insensitive(self) -> None:
        assert _word_overlap_similarity("Hello World", "hello world") == 1.0


class TestSourceRefsOverlap:
    """Test source reference overlap detection."""

    def test_same_file_overlapping_lines(self) -> None:
        ref_a = _make_source_ref(source_file_id="f1", source_lines=(1, 10))
        ref_b = _make_source_ref(source_file_id="f1", source_lines=(5, 15))
        assert _source_refs_overlap([ref_a], [ref_b]) is True

    def test_same_file_no_overlap(self) -> None:
        ref_a = _make_source_ref(source_file_id="f1", source_lines=(1, 5))
        ref_b = _make_source_ref(source_file_id="f1", source_lines=(10, 15))
        assert _source_refs_overlap([ref_a], [ref_b]) is False

    def test_different_files(self) -> None:
        ref_a = _make_source_ref(source_file_id="f1", source_lines=(1, 10))
        ref_b = _make_source_ref(source_file_id="f2", source_lines=(1, 10))
        assert _source_refs_overlap([ref_a], [ref_b]) is False

    def test_adjacent_lines(self) -> None:
        ref_a = _make_source_ref(source_file_id="f1", source_lines=(1, 5))
        ref_b = _make_source_ref(source_file_id="f1", source_lines=(5, 10))
        assert _source_refs_overlap([ref_a], [ref_b]) is True

    def test_empty_refs(self) -> None:
        ref_a = _make_source_ref(source_file_id="f1", source_lines=(1, 5))
        assert _source_refs_overlap([], [ref_a]) is False
        assert _source_refs_overlap([ref_a], []) is False


class TestFindDuplicates:
    """Test find_duplicates identifying candidates describing same event (Req 6.1)."""

    def test_empty_list(self, deduplicator: EvidenceDeduplicator) -> None:
        assert deduplicator.find_duplicates([]) == []

    def test_single_candidate(self, deduplicator: EvidenceDeduplicator) -> None:
        c1 = _make_candidate(candidate_id="c1")
        assert deduplicator.find_duplicates([c1]) == []

    def test_identical_candidates_same_source(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Two candidates with same observed_fact and overlapping sources are duplicates."""
        ref = _make_source_ref(source_file_id="f1", source_lines=(1, 10))
        c1 = _make_candidate(
            candidate_id="c1",
            source_refs=[ref],
            observed_fact="Process cmd.exe spawned by malicious macro",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            source_refs=[_make_source_ref(source_ref_id="ref-002", source_file_id="f1", source_lines=(5, 15))],
            observed_fact="Process cmd.exe spawned by malicious macro",
        )
        groups = deduplicator.find_duplicates([c1, c2])
        assert len(groups) == 1
        assert set(groups[0][0]) == {"c1", "c2"}

    def test_similar_candidates_overlapping_source(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Candidates with similar observed_fact and overlapping sources are duplicates."""
        c1 = _make_candidate(
            candidate_id="c1",
            source_refs=[_make_source_ref(source_file_id="f1", source_lines=(1, 10))],
            observed_fact="Malicious process cmd.exe executed on host WS01 at timestamp X",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            source_refs=[_make_source_ref(source_ref_id="ref-002", source_file_id="f1", source_lines=(5, 15))],
            observed_fact="Malicious process cmd.exe executed on host WS01 at timestamp X observed",
        )
        groups = deduplicator.find_duplicates([c1, c2])
        assert len(groups) == 1

    def test_different_candidates_not_grouped(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Candidates with different observed_facts are NOT duplicates."""
        c1 = _make_candidate(
            candidate_id="c1",
            source_refs=[_make_source_ref(source_file_id="f1", source_lines=(1, 10))],
            observed_fact="SSH login from external IP 10.0.0.1",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            source_refs=[_make_source_ref(source_ref_id="ref-002", source_file_id="f1", source_lines=(50, 60))],
            observed_fact="Firewall blocked outbound connection to C2 server",
        )
        groups = deduplicator.find_duplicates([c1, c2])
        assert len(groups) == 0

    def test_high_similarity_different_source(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Very high similarity (>=0.9) counts as duplicate even without source overlap."""
        c1 = _make_candidate(
            candidate_id="c1",
            source_refs=[_make_source_ref(source_file_id="f1", source_lines=(1, 10))],
            observed_fact="Process cmd.exe spawned by malicious macro on host WS01",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            source_refs=[_make_source_ref(source_ref_id="ref-002", source_file_id="f2", source_lines=(1, 10))],
            observed_fact="Process cmd.exe spawned by malicious macro on host WS01",
        )
        groups = deduplicator.find_duplicates([c1, c2])
        assert len(groups) == 1

    def test_three_duplicates(self, deduplicator: EvidenceDeduplicator) -> None:
        """Three duplicate candidates are grouped together."""
        fact = "Suspicious PowerShell execution detected on host DC01"
        c1 = _make_candidate(
            candidate_id="c1",
            source_refs=[_make_source_ref(source_file_id="f1", source_lines=(1, 10))],
            observed_fact=fact,
        )
        c2 = _make_candidate(
            candidate_id="c2",
            source_refs=[_make_source_ref(source_ref_id="ref-002", source_file_id="f1", source_lines=(5, 15))],
            observed_fact=fact,
        )
        c3 = _make_candidate(
            candidate_id="c3",
            source_refs=[_make_source_ref(source_ref_id="ref-003", source_file_id="f1", source_lines=(8, 18))],
            observed_fact=fact,
        )
        groups = deduplicator.find_duplicates([c1, c2, c3])
        assert len(groups) == 1
        assert set(groups[0][0]) == {"c1", "c2", "c3"}


class TestMergeCandidates:
    """Test merge_candidates preserving all source references (Req 6.2, 6.4, 6.5)."""

    def test_merge_preserves_all_source_refs(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Merged candidate preserves all source references from originals."""
        ref1 = _make_source_ref(
            source_ref_id="ref-001",
            source_file_id="f1",
            source_lines=(1, 10),
            excerpt="First excerpt from file 1",
        )
        ref2 = _make_source_ref(
            source_ref_id="ref-002",
            source_file_id="f2",
            source_lines=(20, 30),
            excerpt="Second excerpt from file 2",
        )
        c1 = _make_candidate(candidate_id="c1", source_refs=[ref1])
        c2 = _make_candidate(candidate_id="c2", source_refs=[ref2])

        merged = deduplicator.merge_candidates(["c1", "c2"], [c1, c2])

        assert len(merged.source_refs) == 2
        ref_ids = {r.source_ref_id for r in merged.source_refs}
        assert ref_ids == {"ref-001", "ref-002"}

    def test_merge_generates_new_id(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Merged candidate gets a new candidate_id starting with 'merged-'."""
        c1 = _make_candidate(candidate_id="c1")
        c2 = _make_candidate(candidate_id="c2")

        merged = deduplicator.merge_candidates(["c1", "c2"], [c1, c2])

        assert merged.candidate_id.startswith("merged-")
        assert merged.candidate_id not in ("c1", "c2")

    def test_merge_status_is_merged(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Merged candidate has candidate_status='merged'."""
        c1 = _make_candidate(candidate_id="c1")
        c2 = _make_candidate(candidate_id="c2")

        merged = deduplicator.merge_candidates(["c1", "c2"], [c1, c2])

        assert merged.candidate_status == "merged"

    def test_merge_deduplicates_source_refs(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Source refs with same source_ref_id are not duplicated."""
        ref = _make_source_ref(source_ref_id="ref-shared")
        c1 = _make_candidate(candidate_id="c1", source_refs=[ref])
        c2 = _make_candidate(candidate_id="c2", source_refs=[ref])

        merged = deduplicator.merge_candidates(["c1", "c2"], [c1, c2])

        assert len(merged.source_refs) == 1

    def test_merge_raises_on_empty_ids(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """ValueError raised when no candidates match provided IDs."""
        c1 = _make_candidate(candidate_id="c1")
        with pytest.raises(ValueError):
            deduplicator.merge_candidates(["nonexistent"], [c1])

    def test_merge_preserves_observed_fact(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Merged candidate preserves the observed_fact from the first candidate."""
        c1 = _make_candidate(
            candidate_id="c1",
            observed_fact="Primary observation about the event",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            observed_fact="Secondary observation about the event",
        )

        merged = deduplicator.merge_candidates(["c1", "c2"], [c1, c2])

        assert merged.observed_fact == "Primary observation about the event"

    def test_merge_combines_attack_mappings(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Merged candidate has ATT&CK mappings from all originals (deduplicated)."""
        from ir_agent.models.events import ATTCKMapping

        c1 = _make_candidate(candidate_id="c1")
        c1.attack_mapping_candidates = [
            ATTCKMapping(
                tactic="Execution",
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                confidence=ConfidenceLevel.PROBABLE,
            )
        ]
        c2 = _make_candidate(candidate_id="c2")
        c2.attack_mapping_candidates = [
            ATTCKMapping(
                tactic="Persistence",
                technique_id="T1547",
                technique_name="Boot or Logon Autostart Execution",
                confidence=ConfidenceLevel.POSSIBLE,
            )
        ]

        merged = deduplicator.merge_candidates(["c1", "c2"], [c1, c2])

        assert len(merged.attack_mapping_candidates) == 2
        technique_ids = {m.technique_id for m in merged.attack_mapping_candidates}
        assert technique_ids == {"T1059", "T1547"}

    def test_merge_combines_normalized_event_ids(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Merged candidate has from_normalized_event_ids from all originals."""
        c1 = _make_candidate(
            candidate_id="c1", from_normalized_event_ids=["evt-001", "evt-002"]
        )
        c2 = _make_candidate(
            candidate_id="c2", from_normalized_event_ids=["evt-002", "evt-003"]
        )

        merged = deduplicator.merge_candidates(["c1", "c2"], [c1, c2])

        assert set(merged.from_normalized_event_ids) == {"evt-001", "evt-002", "evt-003"}


class TestRecalculateConfidence:
    """Test confidence recalculation (Req 6.3) - NOT auto-highest."""

    def test_single_source_not_confirmed(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """A single source without parser should NOT yield CONFIRMED."""
        ref = _make_source_ref(source_file_id="f1", excerpt="short")
        candidates = [
            _make_candidate(
                candidate_id="c1",
                source_refs=[ref],
                observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            )
        ]
        confidence, rationale = deduplicator.recalculate_confidence(
            [ref], candidates
        )
        # Single source with no parser and short excerpt shouldn't be confirmed
        assert confidence != ConfidenceLevel.CONFIRMED
        assert "independent_sources=1" in rationale

    def test_multiple_independent_sources_boost_confidence(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Multiple independent sources with parsers boost confidence."""
        refs = [
            _make_source_ref(
                source_ref_id=f"ref-{i}",
                source_file_id=f"f{i}",
                excerpt="A" * 250,  # Long excerpt = direct observation
                parser_name="syslog_parser",
            )
            for i in range(3)
        ]
        candidates = [
            _make_candidate(
                candidate_id=f"c{i}",
                source_refs=[refs[i]],
                observed_fact="Consistent observation across sources",
            )
            for i in range(3)
        ]
        confidence, rationale = deduplicator.recalculate_confidence(
            refs, candidates
        )
        assert confidence == ConfidenceLevel.CONFIRMED
        assert "independent_sources=3" in rationale

    def test_does_not_auto_take_highest(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Confidence is recalculated, not taken from the highest original."""
        # One candidate has CONFIRMED but has limitations in interpretation
        ref = _make_source_ref(
            source_file_id="f1",
            excerpt="short",
        )
        candidates = [
            _make_candidate(
                candidate_id="c1",
                source_refs=[ref],
                observed_fact_confidence=ConfidenceLevel.CONFIRMED,
                interpretation="However this is unclear and contradicts other evidence",
            )
        ]
        confidence, rationale = deduplicator.recalculate_confidence(
            [ref], candidates
        )
        # Should NOT just use CONFIRMED because of single source with limitations
        assert confidence in (
            ConfidenceLevel.PROBABLE,
            ConfidenceLevel.POSSIBLE,
            ConfidenceLevel.UNKNOWN,
        )

    def test_empty_sources_returns_unknown(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """No sources yields UNKNOWN confidence."""
        confidence, rationale = deduplicator.recalculate_confidence([])
        assert confidence == ConfidenceLevel.UNKNOWN
        assert "No source references" in rationale

    def test_rationale_includes_all_factors(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Rationale string includes all assessment factors."""
        ref = _make_source_ref(source_file_id="f1", excerpt="A" * 100)
        candidates = [_make_candidate(candidate_id="c1", source_refs=[ref])]
        _, rationale = deduplicator.recalculate_confidence([ref], candidates)
        assert "independent_sources" in rationale
        assert "reliability" in rationale
        assert "directness" in rationale
        assert "consistency" in rationale
        assert "total_score" in rationale

    def test_limitation_penalty_applied(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Limitation keywords in interpretation reduce confidence score."""
        ref = _make_source_ref(
            source_file_id="f1",
            excerpt="A" * 200,
            parser_name="parser",
        )
        cand_no_limit = _make_candidate(
            candidate_id="c1",
            source_refs=[ref],
            interpretation="Clear lateral movement attempt",
        )
        cand_with_limit = _make_candidate(
            candidate_id="c2",
            source_refs=[ref],
            interpretation="However this is unclear and insufficient evidence",
        )

        _, rationale_clean = deduplicator.recalculate_confidence(
            [ref], [cand_no_limit]
        )
        _, rationale_limited = deduplicator.recalculate_confidence(
            [ref], [cand_with_limit]
        )

        assert "limitation_penalty" in rationale_limited


class TestGroupCorroborating:
    """Test group_corroborating for related non-duplicate grouping (Req 6.6)."""

    def test_empty_list(self, deduplicator: EvidenceDeduplicator) -> None:
        assert deduplicator.group_corroborating([]) == []

    def test_single_candidate(self, deduplicator: EvidenceDeduplicator) -> None:
        c1 = _make_candidate(candidate_id="c1")
        assert deduplicator.group_corroborating([c1]) == []

    def test_related_candidates_grouped(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Candidates with moderate similarity are grouped as corroborating."""
        c1 = _make_candidate(
            candidate_id="c1",
            source_refs=[_make_source_ref(source_file_id="f1", source_lines=(1, 10))],
            observed_fact="SSH login from external IP to host WS01 at 14:00 UTC",
            interpretation="Possible unauthorized lateral movement via SSH to WS01",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            source_refs=[_make_source_ref(source_ref_id="ref-002", source_file_id="f2", source_lines=(20, 30))],
            observed_fact="Outbound connection from WS01 to external IP at 14:05 UTC",
            interpretation="Possible unauthorized lateral movement from WS01 to external host",
        )
        groups = deduplicator.group_corroborating([c1, c2])
        # They should be corroborating (related but different observed facts)
        assert len(groups) >= 1

    def test_unrelated_candidates_not_grouped(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Completely unrelated candidates are NOT grouped."""
        c1 = _make_candidate(
            candidate_id="c1",
            source_refs=[_make_source_ref(source_file_id="f1", source_lines=(1, 5))],
            observed_fact="DNS query for known malicious domain evil.com",
            interpretation="C2 communication detected",
        )
        c2 = _make_candidate(
            candidate_id="c2",
            source_refs=[_make_source_ref(source_ref_id="ref-002", source_file_id="f3", source_lines=(100, 110))],
            observed_fact="User account locked after 5 failed password attempts",
            interpretation="Possible brute force attack",
        )
        groups = deduplicator.group_corroborating([c1, c2])
        assert len(groups) == 0

    def test_duplicates_excluded_from_corroboration(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Exact duplicates are NOT placed in corroborating groups."""
        fact = "Identical observation that should be merged not corroborated"
        c1 = _make_candidate(
            candidate_id="c1",
            source_refs=[_make_source_ref(source_file_id="f1", source_lines=(1, 10))],
            observed_fact=fact,
        )
        c2 = _make_candidate(
            candidate_id="c2",
            source_refs=[_make_source_ref(source_ref_id="ref-002", source_file_id="f1", source_lines=(5, 15))],
            observed_fact=fact,
        )
        groups = deduplicator.group_corroborating([c1, c2])
        # These are duplicates, not corroborating
        assert len(groups) == 0

    def test_shared_normalized_events_corroborating(
        self, deduplicator: EvidenceDeduplicator
    ) -> None:
        """Candidates sharing normalized event IDs are corroborating."""
        c1 = _make_candidate(
            candidate_id="c1",
            source_refs=[_make_source_ref(source_file_id="f1", source_lines=(1, 5))],
            observed_fact="Network connection to external IP detected",
            from_normalized_event_ids=["evt-001", "evt-002"],
        )
        c2 = _make_candidate(
            candidate_id="c2",
            source_refs=[_make_source_ref(source_ref_id="ref-002", source_file_id="f2", source_lines=(50, 60))],
            observed_fact="File transfer activity observed outbound",
            from_normalized_event_ids=["evt-002", "evt-003"],
        )
        groups = deduplicator.group_corroborating([c1, c2])
        assert len(groups) >= 1
        assert {"c1", "c2"}.issubset(set(groups[0]))
