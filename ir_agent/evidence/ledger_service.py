"""Evidence Ledger Service for the IR Reporting Support Agent.

Manages the evidence ledger lifecycle including promotion from candidates,
withdrawal, supersession, and active view computation. Uses an append-only
JSONL store to ensure full audit trail.

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ir_agent.models.evidence import EvidenceCandidate, EvidenceLedgerEntry
from ir_agent.storage.store import AppendOnlyStore

logger = logging.getLogger(__name__)

DEFAULT_LEDGER_FILENAME = "evidence_ledger.jsonl"


class EvidenceLedgerService:
    """Service for managing the Evidence Ledger.

    Provides operations for promoting candidates to the ledger, withdrawing
    entries, superseding entries, and querying the active set. All mutations
    are append-only — existing records are never modified or deleted.

    Design invariants:
    - promote: Creates a new EvidenceLedgerEntry from an EvidenceCandidate.
    - withdraw: Appends a new record with withdrawn=True for the same evidence_id.
    - supersede: Creates a new entry with supersedes referencing the old entry.
    - Active view: Excludes withdrawn and superseded entries.
    - observed_fact_confidence and interpretation_confidence stored separately.
    """

    def __init__(self, case_dir: Path, ledger_filename: str = DEFAULT_LEDGER_FILENAME) -> None:
        """Initialize the EvidenceLedgerService.

        Args:
            case_dir: Root directory of the case. The ledger file is stored
                under ``data/`` within this directory.
            ledger_filename: Name of the JSONL ledger file.
                Defaults to ``evidence_ledger.jsonl``.
        """
        self._ledger_path = case_dir / "data" / ledger_filename
        self._store = AppendOnlyStore(self._ledger_path, EvidenceLedgerEntry)

    @property
    def ledger_path(self) -> Path:
        """Return the path to the backing JSONL ledger file."""
        return self._ledger_path

    def promote(
        self,
        candidate: EvidenceCandidate,
        approved_by: str,
    ) -> EvidenceLedgerEntry:
        """Promote an EvidenceCandidate to the Evidence Ledger.

        Creates a new EvidenceLedgerEntry with a unique evidence_id (uuid4),
        copies relevant fields from the candidate, sets the approval_timestamp
        to the current UTC time in ISO 8601 format, and appends to the JSONL file.

        Args:
            candidate: The evidence candidate to promote.
            approved_by: Identifier of the analyst who approved the promotion.

        Returns:
            The newly created EvidenceLedgerEntry.

        Requirements: 8.1, 8.2, 8.3, 8.9
        """
        evidence_id = str(uuid.uuid4())
        approval_timestamp = datetime.now(timezone.utc).isoformat()

        entry = EvidenceLedgerEntry(
            evidence_id=evidence_id,
            promoted_from=[candidate.candidate_id],
            approval_timestamp=approval_timestamp,
            approved_by=approved_by,
            source_refs=candidate.source_refs,
            observed_event=candidate.observed_event,
            observed_fact=candidate.observed_fact,
            interpretation=candidate.interpretation,
            observed_fact_confidence=candidate.observed_fact_confidence,
            interpretation_confidence=candidate.interpretation_confidence,
            attack_mapping_candidates=list(candidate.attack_mapping_candidates),
        )

        self._store.append(entry)
        logger.info(
            "Promoted candidate %s to evidence %s (approved by %s)",
            candidate.candidate_id,
            evidence_id,
            approved_by,
        )
        return entry

    def withdraw(
        self,
        evidence_id: str,
        withdrawn_by: str,
        reason: str,
        replacement_id: str | None = None,
    ) -> EvidenceLedgerEntry:
        """Withdraw an evidence entry from the ledger.

        Marks an existing entry as withdrawn by appending a new record with
        the same evidence_id but withdrawn=True. The original record remains
        untouched (append-only semantics).

        Args:
            evidence_id: The evidence_id of the entry to withdraw.
            withdrawn_by: Identifier of the analyst who initiated withdrawal.
            reason: Human-readable reason for the withdrawal.
            replacement_id: Optional evidence_id of a replacement entry.

        Returns:
            The withdrawal record appended to the ledger.

        Raises:
            ValueError: If no entry with the given evidence_id exists.

        Requirements: 8.5, 8.6, 8.8
        """
        # Find the original entry to copy its fields
        original = self._find_latest_entry(evidence_id)
        if original is None:
            raise ValueError(f"No evidence entry found with id: {evidence_id}")

        withdrawn_at = datetime.now(timezone.utc).isoformat()

        withdrawal_record = EvidenceLedgerEntry(
            evidence_id=evidence_id,
            promoted_from=original.promoted_from,
            approval_timestamp=original.approval_timestamp,
            approved_by=original.approved_by,
            source_refs=original.source_refs,
            observed_event=original.observed_event,
            observed_fact=original.observed_fact,
            interpretation=original.interpretation,
            observed_fact_confidence=original.observed_fact_confidence,
            interpretation_confidence=original.interpretation_confidence,
            withdrawn=True,
            withdrawn_at=withdrawn_at,
            withdrawn_by=withdrawn_by,
            withdrawal_reason=reason,
            replacement_evidence_id=replacement_id,
            supersedes=original.supersedes,
        )

        self._store.append(withdrawal_record)
        logger.info(
            "Withdrew evidence %s by %s: %s",
            evidence_id,
            withdrawn_by,
            reason,
        )
        return withdrawal_record

    def supersede(
        self,
        old_evidence_id: str,
        new_entry: EvidenceLedgerEntry,
    ) -> EvidenceLedgerEntry:
        """Create a new entry that supersedes an old one.

        The new entry is appended with its ``supersedes`` field set to the
        old_evidence_id. The old entry remains in the ledger but will be
        excluded from the active view.

        Args:
            old_evidence_id: The evidence_id being superseded.
            new_entry: The new EvidenceLedgerEntry to append. Its ``supersedes``
                field will be set to ``old_evidence_id``.

        Returns:
            The new entry as appended (with supersedes set).

        Raises:
            ValueError: If no entry with old_evidence_id exists.

        Requirements: 8.6, 8.7
        """
        original = self._find_latest_entry(old_evidence_id)
        if original is None:
            raise ValueError(f"No evidence entry found with id: {old_evidence_id}")

        # Create the superseding entry with the supersedes reference
        superseding_entry = new_entry.model_copy(
            update={"supersedes": old_evidence_id}
        )

        self._store.append(superseding_entry)
        logger.info(
            "Evidence %s superseded by %s",
            old_evidence_id,
            superseding_entry.evidence_id,
        )
        return superseding_entry

    def get_active_entries(self) -> list[EvidenceLedgerEntry]:
        """Return all active (non-withdrawn, non-superseded) ledger entries.

        An entry is considered inactive if:
        - Any record with the same evidence_id has withdrawn=True, OR
        - Another entry exists with supersedes pointing to this entry's evidence_id.

        Because the store is append-only, withdrawal is recorded as a new row
        with the same evidence_id and withdrawn=True. This method considers the
        *latest* state for each evidence_id.

        Returns:
            List of active EvidenceLedgerEntry instances (one per unique
            evidence_id that is still active), returning the latest record
            for each.

        Requirements: 8.4, 8.5, 8.6
        """
        all_records = self._store.read_all()

        # Determine which evidence_ids have been withdrawn
        withdrawn_ids: set[str] = set()
        for record in all_records:
            if record.withdrawn:
                withdrawn_ids.add(record.evidence_id)

        # Determine which evidence_ids have been superseded
        superseded_ids: set[str] = set()
        for record in all_records:
            if record.supersedes:
                superseded_ids.add(record.supersedes)

        # Build a map of evidence_id -> latest record (last in append order)
        latest_by_id: dict[str, EvidenceLedgerEntry] = {}
        for record in all_records:
            latest_by_id[record.evidence_id] = record

        # Return active entries: not withdrawn, not superseded
        active: list[EvidenceLedgerEntry] = []
        seen_ids: set[str] = set()
        for record in all_records:
            eid = record.evidence_id
            if eid in seen_ids:
                continue
            if eid in withdrawn_ids:
                seen_ids.add(eid)
                continue
            if eid in superseded_ids:
                seen_ids.add(eid)
                continue
            # Use the latest version of this record
            active.append(latest_by_id[eid])
            seen_ids.add(eid)

        return active

    def append(self, entry: EvidenceLedgerEntry) -> None:
        """Append a single EvidenceLedgerEntry to the ledger JSONL file.

        This is a low-level operation for writing a pre-built entry directly
        to the store.

        Args:
            entry: The EvidenceLedgerEntry to write.

        Requirements: 8.1, 8.4, 8.6
        """
        self._store.append(entry)

    def get_entry_history(self, evidence_id: str) -> list[EvidenceLedgerEntry]:
        """Return all records matching a specific evidence_id in chronological order.

        This provides the full audit trail for an evidence entry, including
        the original promotion, any withdrawals, and supersession records.

        Args:
            evidence_id: The evidence_id to look up.

        Returns:
            List of all records with this evidence_id, in append (chronological)
            order.

        Requirements: 8.4, 8.6
        """
        all_records = self._store.read_all()
        history: list[EvidenceLedgerEntry] = [
            record for record in all_records if record.evidence_id == evidence_id
        ]
        return history

    def _find_latest_entry(self, evidence_id: str) -> EvidenceLedgerEntry | None:
        """Find the most recent record for a given evidence_id.

        Scans all records and returns the last one with the matching
        evidence_id (latest state).

        Args:
            evidence_id: The ID to search for.

        Returns:
            The latest EvidenceLedgerEntry with this ID, or None if not found.
        """
        all_records = self._store.read_all()
        latest: EvidenceLedgerEntry | None = None
        for record in all_records:
            if record.evidence_id == evidence_id:
                latest = record
        return latest
