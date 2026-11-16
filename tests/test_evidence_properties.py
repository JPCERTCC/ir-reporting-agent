"""Property-based tests for the Evidence Layer.

**Validates: Requirements 7.6, 8.4, 8.6**

Property 2: Approval Gate Integrity
- No candidate enters ledger without explicit approval (promote call)
- Withdrawn/superseded evidence is excluded from active view

Property 4: Active View Consistency
- Active view never includes withdrawn or superseded entries
"""

from __future__ import annotations

import uuid
from pathlib import Path

from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from ir_agent.evidence.ledger_service import EvidenceLedgerService
from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceCandidate, EvidenceLedgerEntry


# Candidate generation is legitimately heavy (nested models); on a loaded
# machine Hypothesis' input-speed health checks fail without any invariant
# being violated.
SLOW_GENERATION = [HealthCheck.large_base_example, HealthCheck.too_slow,
                   HealthCheck.data_too_large]

# --- Strategies ---

confidence_st = st.sampled_from(list(ConfidenceLevel))

analyst_id_st = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_"),
    min_size=1,
    max_size=15,
)

# Non-empty short strings for IDs and textual fields
short_text_st = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_"),
    min_size=1,
    max_size=30,
)

fact_text_st = st.text(
    alphabet=st.characters(whitelist_categories=("L", "Nd", "Zs"), whitelist_characters=".-_,"),
    min_size=1,
    max_size=100,
).filter(lambda s: s.strip() != "")


def _make_source_ref(file_id: str = "file-001") -> SourceReference:
    """Create a minimal SourceReference for testing."""
    return SourceReference(
        source_ref_id=f"ref-{uuid.uuid4().hex[:8]}",
        source_file_id=file_id,
        source_path="/artifacts/test.log",
        source_lines=(1, 10),
        excerpt="test excerpt data",
        excerpt_sha256="deadbeef" * 8,
    )


@st.composite
def evidence_candidate_st(draw):
    """Strategy to generate a valid EvidenceCandidate."""
    candidate_id = draw(short_text_st)
    observed_fact = draw(fact_text_st)
    interpretation = draw(fact_text_st)
    observed_fact_confidence = draw(confidence_st)
    interpretation_confidence = draw(confidence_st)

    return EvidenceCandidate(
        candidate_id=candidate_id,
        source_refs=[_make_source_ref()],
        observed_event={"type": "test_event"},
        observed_fact=observed_fact,
        interpretation=interpretation,
        observed_fact_confidence=observed_fact_confidence,
        interpretation_confidence=interpretation_confidence,
    )


@st.composite
def candidate_list_st(draw, min_size=1, max_size=10):
    """Strategy for a list of candidates with unique IDs."""
    n = draw(st.integers(min_value=min_size, max_value=max_size))
    candidates = []
    used_ids = set()
    for _ in range(n):
        c = draw(evidence_candidate_st())
        # Ensure unique candidate IDs
        while c.candidate_id in used_ids:
            c = draw(evidence_candidate_st())
        used_ids.add(c.candidate_id)
        candidates.append(c)
    return candidates


# --- Property 2: Approval Gate Integrity ---


class TestApprovalGateIntegrity:
    """Property 2: Approval Gate Integrity.

    **Validates: Requirements 7.6, 8.4**

    - No candidate enters the ledger without explicit approval (promote call).
    - After withdrawing any entry, it disappears from get_active_entries.
    - After superseding any entry, the old one disappears from get_active_entries.
    """

    @given(
        candidates=candidate_list_st(min_size=1, max_size=8),
        analyst=analyst_id_st,
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=SLOW_GENERATION)
    def test_only_promoted_candidates_appear_in_ledger(
        self,
        candidates: list[EvidenceCandidate],
        analyst: str,
        tmp_path_factory,
    ):
        """After promoting N candidates, get_active_entries returns exactly N entries.

        No candidate auto-enters the ledger without an explicit promote call.

        **Validates: Requirements 7.6, 8.4**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_approval")
        service = EvidenceLedgerService(tmp_dir)

        # Promote each candidate explicitly
        promoted_ids = []
        for candidate in candidates:
            entry = service.promote(candidate, approved_by=analyst)
            promoted_ids.append(entry.evidence_id)

        active = service.get_active_entries()

        # Exactly N entries (one per promote call)
        assert len(active) == len(candidates), (
            f"Expected {len(candidates)} active entries, got {len(active)}"
        )

        # All active entries must have been explicitly promoted
        active_ids = {e.evidence_id for e in active}
        assert active_ids == set(promoted_ids)

    @given(
        candidates=candidate_list_st(min_size=2, max_size=8),
        analyst=analyst_id_st,
        withdraw_index=st.integers(min_value=0, max_value=7),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=SLOW_GENERATION)
    def test_withdrawn_entry_excluded_from_active(
        self,
        candidates: list[EvidenceCandidate],
        analyst: str,
        withdraw_index: int,
        tmp_path_factory,
    ):
        """After withdrawing any entry, it disappears from get_active_entries.

        **Validates: Requirements 7.6, 8.4**
        """
        assume(withdraw_index < len(candidates))

        tmp_dir = tmp_path_factory.mktemp("prop_withdraw")
        service = EvidenceLedgerService(tmp_dir)

        # Promote all candidates
        entries = []
        for candidate in candidates:
            entry = service.promote(candidate, approved_by=analyst)
            entries.append(entry)

        # Withdraw one entry
        target = entries[withdraw_index]
        service.withdraw(
            target.evidence_id,
            withdrawn_by=analyst,
            reason="Property test withdrawal",
        )

        active = service.get_active_entries()
        active_ids = {e.evidence_id for e in active}

        # The withdrawn entry must not appear in active view
        assert target.evidence_id not in active_ids, (
            f"Withdrawn entry {target.evidence_id} still in active view"
        )

        # All other entries should still be active
        for entry in entries:
            if entry.evidence_id != target.evidence_id:
                assert entry.evidence_id in active_ids

    @given(
        candidates=candidate_list_st(min_size=2, max_size=8),
        analyst=analyst_id_st,
        supersede_index=st.integers(min_value=0, max_value=7),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=SLOW_GENERATION)
    def test_superseded_entry_excluded_from_active(
        self,
        candidates: list[EvidenceCandidate],
        analyst: str,
        supersede_index: int,
        tmp_path_factory,
    ):
        """After superseding any entry, the old one disappears from get_active_entries.

        **Validates: Requirements 7.6, 8.4**
        """
        assume(supersede_index < len(candidates))

        tmp_dir = tmp_path_factory.mktemp("prop_supersede")
        service = EvidenceLedgerService(tmp_dir)

        # Promote all candidates
        entries = []
        for candidate in candidates:
            entry = service.promote(candidate, approved_by=analyst)
            entries.append(entry)

        # Supersede one entry with a new one
        old_entry = entries[supersede_index]
        new_entry = EvidenceLedgerEntry(
            evidence_id=str(uuid.uuid4()),
            promoted_from=old_entry.promoted_from,
            approval_timestamp="2024-02-01T00:00:00+00:00",
            approved_by=analyst,
            source_refs=[_make_source_ref()],
            observed_event={"type": "superseding_event"},
            observed_fact="Updated observed fact",
            interpretation="Updated interpretation",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.PROBABLE,
        )

        service.supersede(old_entry.evidence_id, new_entry)

        active = service.get_active_entries()
        active_ids = {e.evidence_id for e in active}

        # The superseded entry must not appear in active view
        assert old_entry.evidence_id not in active_ids, (
            f"Superseded entry {old_entry.evidence_id} still in active view"
        )

        # The new superseding entry should be active
        assert new_entry.evidence_id in active_ids


# --- Property 4: Active View Consistency ---


class TestActiveViewConsistency:
    """Property 4: Active View Consistency.

    **Validates: Requirements 8.4, 8.6**

    Active view never includes withdrawn or superseded entries,
    regardless of the sequence of operations performed.
    """

    @given(
        candidates=candidate_list_st(min_size=1, max_size=6),
        analyst=analyst_id_st,
        withdraw_indices=st.lists(st.integers(min_value=0, max_value=5), max_size=4),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=SLOW_GENERATION)
    def test_active_view_never_contains_withdrawn(
        self,
        candidates: list[EvidenceCandidate],
        analyst: str,
        withdraw_indices: list[int],
        tmp_path_factory,
    ):
        """Active view never includes any entry with withdrawn=True,
        regardless of how many entries are withdrawn.

        **Validates: Requirements 8.4, 8.6**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_consistency_w")
        service = EvidenceLedgerService(tmp_dir)

        # Promote all candidates
        entries = []
        for candidate in candidates:
            entry = service.promote(candidate, approved_by=analyst)
            entries.append(entry)

        # Withdraw entries at valid indices (dedup indices)
        withdrawn_ids: set[str] = set()
        for idx in withdraw_indices:
            if idx < len(entries):
                eid = entries[idx].evidence_id
                if eid not in withdrawn_ids:
                    service.withdraw(eid, withdrawn_by=analyst, reason="test")
                    withdrawn_ids.add(eid)

        active = service.get_active_entries()

        # Core invariant: no active entry has withdrawn=True
        for entry in active:
            assert entry.withdrawn is False, (
                f"Active view contains withdrawn entry: {entry.evidence_id}"
            )

        # Also verify withdrawn IDs are not in active view
        active_ids = {e.evidence_id for e in active}
        for wid in withdrawn_ids:
            assert wid not in active_ids, (
                f"Withdrawn entry {wid} still in active view"
            )

    @given(
        candidates=candidate_list_st(min_size=2, max_size=6),
        analyst=analyst_id_st,
        supersede_indices=st.lists(st.integers(min_value=0, max_value=5), max_size=3),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=SLOW_GENERATION)
    def test_active_view_never_contains_superseded(
        self,
        candidates: list[EvidenceCandidate],
        analyst: str,
        supersede_indices: list[int],
        tmp_path_factory,
    ):
        """Active view never includes an entry whose evidence_id appears in
        another entry's supersedes field.

        **Validates: Requirements 8.4, 8.6**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_consistency_s")
        service = EvidenceLedgerService(tmp_dir)

        # Promote all candidates
        entries = []
        for candidate in candidates:
            entry = service.promote(candidate, approved_by=analyst)
            entries.append(entry)

        # Supersede entries at valid indices (dedup)
        superseded_ids: set[str] = set()
        for idx in supersede_indices:
            if idx < len(entries):
                old_entry = entries[idx]
                if old_entry.evidence_id not in superseded_ids:
                    new_entry = EvidenceLedgerEntry(
                        evidence_id=str(uuid.uuid4()),
                        promoted_from=old_entry.promoted_from,
                        approval_timestamp="2024-03-01T00:00:00+00:00",
                        approved_by=analyst,
                        source_refs=[_make_source_ref()],
                        observed_event={"type": "supersede_test"},
                        observed_fact="Superseding fact",
                        interpretation="Superseding interpretation",
                        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
                        interpretation_confidence=ConfidenceLevel.PROBABLE,
                    )
                    service.supersede(old_entry.evidence_id, new_entry)
                    superseded_ids.add(old_entry.evidence_id)

        active = service.get_active_entries()
        active_ids = {e.evidence_id for e in active}

        # Core invariant: no superseded ID appears in active view
        for sid in superseded_ids:
            assert sid not in active_ids, (
                f"Superseded entry {sid} still in active view"
            )

    @given(
        candidates=candidate_list_st(min_size=2, max_size=5),
        analyst=analyst_id_st,
        withdraw_indices=st.lists(st.integers(min_value=0, max_value=4), max_size=3),
        supersede_indices=st.lists(st.integers(min_value=0, max_value=4), max_size=2),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=SLOW_GENERATION)
    def test_active_view_consistency_mixed_operations(
        self,
        candidates: list[EvidenceCandidate],
        analyst: str,
        withdraw_indices: list[int],
        supersede_indices: list[int],
        tmp_path_factory,
    ):
        """Active view remains consistent after a mix of withdrawals and supersessions.

        No entry that has been withdrawn or superseded ever appears in active view.

        **Validates: Requirements 8.4, 8.6**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_consistency_mix")
        service = EvidenceLedgerService(tmp_dir)

        # Promote all candidates
        entries = []
        for candidate in candidates:
            entry = service.promote(candidate, approved_by=analyst)
            entries.append(entry)

        # Track inactive IDs
        inactive_ids: set[str] = set()

        # Withdraw some entries
        for idx in withdraw_indices:
            if idx < len(entries):
                eid = entries[idx].evidence_id
                if eid not in inactive_ids:
                    service.withdraw(eid, withdrawn_by=analyst, reason="mixed test")
                    inactive_ids.add(eid)

        # Supersede some entries (only those not already withdrawn)
        for idx in supersede_indices:
            if idx < len(entries):
                old_entry = entries[idx]
                if old_entry.evidence_id not in inactive_ids:
                    new_entry = EvidenceLedgerEntry(
                        evidence_id=str(uuid.uuid4()),
                        promoted_from=old_entry.promoted_from,
                        approval_timestamp="2024-04-01T00:00:00+00:00",
                        approved_by=analyst,
                        source_refs=[_make_source_ref()],
                        observed_event={"type": "mixed_test"},
                        observed_fact="Mixed test fact",
                        interpretation="Mixed test interpretation",
                        observed_fact_confidence=ConfidenceLevel.PROBABLE,
                        interpretation_confidence=ConfidenceLevel.POSSIBLE,
                    )
                    service.supersede(old_entry.evidence_id, new_entry)
                    inactive_ids.add(old_entry.evidence_id)

        active = service.get_active_entries()
        active_ids = {e.evidence_id for e in active}

        # Core invariant: no inactive ID appears in active view
        for iid in inactive_ids:
            assert iid not in active_ids, (
                f"Inactive entry {iid} still in active view after mixed operations"
            )

        # Additional invariant: no withdrawn flag in active view
        for entry in active:
            assert entry.withdrawn is False, (
                f"Entry {entry.evidence_id} in active view has withdrawn=True"
            )
