"""Unit tests for EvidenceLedgerService.

Validates Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9:
- Promote candidates to the evidence ledger
- Assign unique evidence_id to each promoted item
- Append-only semantics (no modification or deletion)
- Withdraw entries with reason and optional replacement
- Supersede entries with a new entry
- Active view excludes withdrawn and superseded entries
- Separately store observed_fact_confidence and interpretation_confidence
- Full audit trail via get_entry_history
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from ir_agent.evidence.ledger_service import EvidenceLedgerService
from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceCandidate, EvidenceLedgerEntry


# --- Fixtures ---


def _make_source_ref(file_id: str = "file-001") -> SourceReference:
    """Create a minimal SourceReference for testing."""
    return SourceReference(
        source_ref_id="ref-001",
        source_file_id=file_id,
        source_path="/artifacts/test.log",
        source_lines=(10, 15),
        excerpt="suspicious activity detected",
        excerpt_sha256="abc123def456",
    )


def _make_candidate(
    candidate_id: str = "cand-001",
    observed_fact_confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
    interpretation_confidence: ConfidenceLevel = ConfidenceLevel.PROBABLE,
) -> EvidenceCandidate:
    """Create a minimal EvidenceCandidate for testing."""
    return EvidenceCandidate(
        candidate_id=candidate_id,
        source_refs=[_make_source_ref()],
        observed_event={"type": "process_execution", "name": "cmd.exe"},
        observed_fact="Process cmd.exe was executed at 2024-01-15T10:00:00Z",
        interpretation="Attacker spawned a command shell for lateral movement",
        observed_fact_confidence=observed_fact_confidence,
        interpretation_confidence=interpretation_confidence,
    )


@pytest.fixture
def case_dir(tmp_path: Path) -> Path:
    """Return a temporary case directory."""
    return tmp_path / "case01"


@pytest.fixture
def service(case_dir: Path) -> EvidenceLedgerService:
    """Return an EvidenceLedgerService with a temporary case directory."""
    return EvidenceLedgerService(case_dir)


# --- Promote Tests ---


class TestPromote:
    def test_promote_creates_ledger_entry(self, service: EvidenceLedgerService):
        """Promoting a candidate creates an EvidenceLedgerEntry."""
        candidate = _make_candidate()
        entry = service.promote(candidate, approved_by="analyst-1")

        assert isinstance(entry, EvidenceLedgerEntry)
        assert entry.approved_by == "analyst-1"

    def test_promote_assigns_unique_evidence_id(self, service: EvidenceLedgerService):
        """Each promotion assigns a unique evidence_id (uuid4)."""
        c1 = _make_candidate("cand-001")
        c2 = _make_candidate("cand-002")

        e1 = service.promote(c1, approved_by="analyst-1")
        e2 = service.promote(c2, approved_by="analyst-1")

        assert e1.evidence_id != e2.evidence_id
        # Verify they are valid UUIDs
        uuid.UUID(e1.evidence_id)
        uuid.UUID(e2.evidence_id)

    def test_promote_copies_candidate_fields(self, service: EvidenceLedgerService):
        """Promoted entry copies source_refs, observed_fact, interpretation from candidate."""
        candidate = _make_candidate()
        entry = service.promote(candidate, approved_by="analyst-1")

        assert entry.promoted_from == ["cand-001"]
        assert entry.source_refs == candidate.source_refs
        assert entry.observed_event == candidate.observed_event
        assert entry.observed_fact == candidate.observed_fact
        assert entry.interpretation == candidate.interpretation

    def test_promote_sets_approval_timestamp(self, service: EvidenceLedgerService):
        """Promoted entry has an ISO 8601 UTC approval_timestamp."""
        candidate = _make_candidate()
        entry = service.promote(candidate, approved_by="analyst-1")

        # Should be a valid ISO 8601 timestamp
        assert "T" in entry.approval_timestamp
        assert "+" in entry.approval_timestamp or "Z" in entry.approval_timestamp

    def test_promote_stores_separate_confidences(self, service: EvidenceLedgerService):
        """Observed_fact_confidence and interpretation_confidence are stored separately."""
        candidate = _make_candidate(
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.POSSIBLE,
        )
        entry = service.promote(candidate, approved_by="analyst-1")

        assert entry.observed_fact_confidence == ConfidenceLevel.CONFIRMED
        assert entry.interpretation_confidence == ConfidenceLevel.POSSIBLE

    def test_promote_appends_to_jsonl(self, service: EvidenceLedgerService):
        """Promoted entries are persisted to the JSONL file."""
        candidate = _make_candidate()
        service.promote(candidate, approved_by="analyst-1")

        assert service.ledger_path.exists()
        entries = service.get_active_entries()
        assert len(entries) == 1

    def test_promote_not_withdrawn(self, service: EvidenceLedgerService):
        """Promoted entries start with withdrawn=False."""
        candidate = _make_candidate()
        entry = service.promote(candidate, approved_by="analyst-1")

        assert entry.withdrawn is False
        assert entry.withdrawn_at is None


# --- Withdraw Tests ---


class TestWithdraw:
    def test_withdraw_marks_entry_as_withdrawn(self, service: EvidenceLedgerService):
        """Withdrawing an entry appends a record with withdrawn=True."""
        candidate = _make_candidate()
        entry = service.promote(candidate, approved_by="analyst-1")

        withdrawal = service.withdraw(
            entry.evidence_id,
            withdrawn_by="analyst-2",
            reason="Evidence was misattributed",
        )

        assert withdrawal.withdrawn is True
        assert withdrawal.withdrawn_by == "analyst-2"
        assert withdrawal.withdrawal_reason == "Evidence was misattributed"
        assert withdrawal.evidence_id == entry.evidence_id

    def test_withdraw_sets_withdrawn_at_timestamp(self, service: EvidenceLedgerService):
        """Withdrawal record includes a withdrawn_at ISO 8601 timestamp."""
        candidate = _make_candidate()
        entry = service.promote(candidate, approved_by="analyst-1")

        withdrawal = service.withdraw(
            entry.evidence_id,
            withdrawn_by="analyst-2",
            reason="Incorrect",
        )

        assert withdrawal.withdrawn_at is not None
        assert "T" in withdrawal.withdrawn_at

    def test_withdraw_with_replacement_id(self, service: EvidenceLedgerService):
        """Withdrawal can include a replacement_evidence_id."""
        c1 = _make_candidate("cand-001")
        c2 = _make_candidate("cand-002")

        e1 = service.promote(c1, approved_by="analyst-1")
        e2 = service.promote(c2, approved_by="analyst-1")

        withdrawal = service.withdraw(
            e1.evidence_id,
            withdrawn_by="analyst-1",
            reason="Replaced with better evidence",
            replacement_id=e2.evidence_id,
        )

        assert withdrawal.replacement_evidence_id == e2.evidence_id

    def test_withdraw_preserves_original_record(self, service: EvidenceLedgerService):
        """Original record remains in the store (append-only)."""
        candidate = _make_candidate()
        entry = service.promote(candidate, approved_by="analyst-1")
        service.withdraw(
            entry.evidence_id,
            withdrawn_by="analyst-2",
            reason="No longer valid",
        )

        # History should show both the original and the withdrawal
        history = service.get_entry_history(entry.evidence_id)
        assert len(history) == 2
        assert history[0].withdrawn is False
        assert history[1].withdrawn is True

    def test_withdraw_nonexistent_raises_error(self, service: EvidenceLedgerService):
        """Withdrawing a non-existent evidence_id raises ValueError."""
        with pytest.raises(ValueError, match="No evidence entry found"):
            service.withdraw(
                "nonexistent-id",
                withdrawn_by="analyst-1",
                reason="test",
            )


# --- Supersede Tests ---


class TestSupersede:
    def test_supersede_creates_new_entry_with_reference(self, service: EvidenceLedgerService):
        """Superseding creates a new entry with supersedes=old_evidence_id."""
        candidate = _make_candidate()
        original = service.promote(candidate, approved_by="analyst-1")

        new_entry = EvidenceLedgerEntry(
            evidence_id=str(uuid.uuid4()),
            promoted_from=["cand-001"],
            approval_timestamp="2024-01-16T10:00:00+00:00",
            approved_by="analyst-1",
            source_refs=[_make_source_ref()],
            observed_event={"type": "process_execution", "name": "powershell.exe"},
            observed_fact="Corrected: powershell.exe was executed",
            interpretation="Corrected interpretation",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.PROBABLE,
        )

        result = service.supersede(original.evidence_id, new_entry)

        assert result.supersedes == original.evidence_id
        assert result.evidence_id == new_entry.evidence_id

    def test_supersede_excludes_old_from_active(self, service: EvidenceLedgerService):
        """Superseded entry is excluded from active view."""
        candidate = _make_candidate()
        original = service.promote(candidate, approved_by="analyst-1")

        new_entry = EvidenceLedgerEntry(
            evidence_id=str(uuid.uuid4()),
            promoted_from=["cand-001"],
            approval_timestamp="2024-01-16T10:00:00+00:00",
            approved_by="analyst-1",
            source_refs=[_make_source_ref()],
            observed_event={"type": "process_execution", "name": "powershell.exe"},
            observed_fact="Corrected fact",
            interpretation="Corrected interpretation",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.PROBABLE,
        )

        service.supersede(original.evidence_id, new_entry)

        active = service.get_active_entries()
        active_ids = {e.evidence_id for e in active}
        assert original.evidence_id not in active_ids
        assert new_entry.evidence_id in active_ids

    def test_supersede_nonexistent_raises_error(self, service: EvidenceLedgerService):
        """Superseding a non-existent evidence_id raises ValueError."""
        new_entry = EvidenceLedgerEntry(
            evidence_id=str(uuid.uuid4()),
            promoted_from=["cand-001"],
            approval_timestamp="2024-01-16T10:00:00+00:00",
            approved_by="analyst-1",
            source_refs=[_make_source_ref()],
            observed_event={},
            observed_fact="fact",
            interpretation="interp",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.PROBABLE,
        )

        with pytest.raises(ValueError, match="No evidence entry found"):
            service.supersede("nonexistent-id", new_entry)


# --- Active Entries Tests ---


class TestGetActiveEntries:
    def test_active_entries_excludes_withdrawn(self, service: EvidenceLedgerService):
        """Withdrawn entries are excluded from active view."""
        c1 = _make_candidate("cand-001")
        c2 = _make_candidate("cand-002")

        e1 = service.promote(c1, approved_by="analyst-1")
        e2 = service.promote(c2, approved_by="analyst-1")

        service.withdraw(e1.evidence_id, withdrawn_by="analyst-1", reason="invalid")

        active = service.get_active_entries()
        active_ids = {e.evidence_id for e in active}
        assert e1.evidence_id not in active_ids
        assert e2.evidence_id in active_ids

    def test_active_entries_excludes_superseded(self, service: EvidenceLedgerService):
        """Superseded entries are excluded from active view."""
        candidate = _make_candidate()
        original = service.promote(candidate, approved_by="analyst-1")

        new_entry = EvidenceLedgerEntry(
            evidence_id=str(uuid.uuid4()),
            promoted_from=["cand-001"],
            approval_timestamp="2024-01-16T10:00:00+00:00",
            approved_by="analyst-1",
            source_refs=[_make_source_ref()],
            observed_event={},
            observed_fact="updated fact",
            interpretation="updated interpretation",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.PROBABLE,
        )

        service.supersede(original.evidence_id, new_entry)

        active = service.get_active_entries()
        active_ids = {e.evidence_id for e in active}
        assert original.evidence_id not in active_ids

    def test_active_entries_empty_ledger(self, service: EvidenceLedgerService):
        """Empty ledger returns empty active list."""
        assert service.get_active_entries() == []


# --- Append Tests ---


class TestAppend:
    def test_append_writes_entry_to_file(self, service: EvidenceLedgerService):
        """Direct append writes a pre-built entry to the JSONL file."""
        entry = EvidenceLedgerEntry(
            evidence_id="manual-001",
            promoted_from=["cand-001"],
            approval_timestamp="2024-01-15T10:00:00+00:00",
            approved_by="analyst-1",
            source_refs=[_make_source_ref()],
            observed_event={"type": "test"},
            observed_fact="test fact",
            interpretation="test interpretation",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.POSSIBLE,
        )

        service.append(entry)

        entries = service.get_active_entries()
        assert len(entries) == 1
        assert entries[0].evidence_id == "manual-001"


# --- Entry History Tests ---


class TestGetEntryHistory:
    def test_history_returns_all_records_for_id(self, service: EvidenceLedgerService):
        """History returns all records matching the evidence_id."""
        candidate = _make_candidate()
        entry = service.promote(candidate, approved_by="analyst-1")
        service.withdraw(
            entry.evidence_id,
            withdrawn_by="analyst-2",
            reason="Obsolete",
        )

        history = service.get_entry_history(entry.evidence_id)
        assert len(history) == 2
        assert history[0].withdrawn is False
        assert history[1].withdrawn is True

    def test_history_chronological_order(self, service: EvidenceLedgerService):
        """History is in chronological (append) order."""
        candidate = _make_candidate()
        entry = service.promote(candidate, approved_by="analyst-1")

        # Withdraw
        service.withdraw(
            entry.evidence_id,
            withdrawn_by="analyst-2",
            reason="First correction",
        )

        history = service.get_entry_history(entry.evidence_id)
        assert len(history) == 2
        # First is original, second is withdrawal
        assert history[0].approved_by == "analyst-1"
        assert history[1].withdrawn is True

    def test_history_nonexistent_id_returns_empty(self, service: EvidenceLedgerService):
        """History of a nonexistent evidence_id returns empty list."""
        assert service.get_entry_history("nonexistent") == []

    def test_history_does_not_include_unrelated_entries(
        self, service: EvidenceLedgerService
    ):
        """History only includes records for the specific evidence_id."""
        c1 = _make_candidate("cand-001")
        c2 = _make_candidate("cand-002")

        e1 = service.promote(c1, approved_by="analyst-1")
        e2 = service.promote(c2, approved_by="analyst-1")

        history = service.get_entry_history(e1.evidence_id)
        assert len(history) == 1
        assert history[0].evidence_id == e1.evidence_id


# --- Ledger Path Configuration Tests ---


class TestLedgerPath:
    def test_default_ledger_path(self, case_dir: Path):
        """Default ledger is at data/evidence_ledger.jsonl relative to case_dir."""
        service = EvidenceLedgerService(case_dir)
        assert service.ledger_path == case_dir / "data" / "evidence_ledger.jsonl"

    def test_custom_ledger_filename(self, case_dir: Path):
        """Custom ledger filename is respected."""
        service = EvidenceLedgerService(case_dir, ledger_filename="custom_ledger.jsonl")
        assert service.ledger_path == case_dir / "data" / "custom_ledger.jsonl"
