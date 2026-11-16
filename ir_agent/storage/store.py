"""Append-only JSONL store with active view computation.

Provides a generic, thread-safe, append-only store backed by JSONL files.
Records are validated via Pydantic on both serialization (append) and
deserialization (read). The active view filters out withdrawn, superseded,
and rejected records.

Requirements: 8.4, 8.6, 20.4
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Generic, TypeVar

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class AppendOnlyStore(Generic[T]):
    """Generic append-only JSONL store parameterized by a Pydantic model type.

    Design invariants:
    - Existing entries are NEVER overwritten or deleted (append-only).
    - Each append writes exactly one JSON record as a new line.
    - Thread-safe append via a threading lock.
    - Corrupt JSONL lines are skipped with a logged warning during read.
    - Active view excludes withdrawn, superseded, and rejected records.
    """

    def __init__(self, file_path: Path, model_class: type[T]) -> None:
        """Initialize the store.

        Args:
            file_path: Path to the JSONL file. Created on first append if it
                does not exist.
            model_class: The Pydantic model class used for validation.
        """
        self._file_path = file_path
        self._model_class = model_class
        self._lock = threading.Lock()

    @property
    def file_path(self) -> Path:
        """Return the backing JSONL file path."""
        return self._file_path

    def append(self, record: T) -> None:
        """Append a single validated record to the JSONL file.

        The record is serialized to JSON via Pydantic and written as a single
        line. The operation is thread-safe.

        Args:
            record: A Pydantic model instance to persist.

        Raises:
            TypeError: If record is not an instance of the configured model class.
            OSError: If the file cannot be written.
        """
        if not isinstance(record, self._model_class):
            raise TypeError(
                f"Expected instance of {self._model_class.__name__}, "
                f"got {type(record).__name__}"
            )

        # Serialize via Pydantic (validates the model is well-formed)
        json_line = record.model_dump_json()

        with self._lock:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._file_path, "a", encoding="utf-8") as f:
                f.write(json_line + "\n")

    def read_all(self) -> list[T]:
        """Read all records from the JSONL file.

        Each line is deserialized and validated via Pydantic. Corrupt or
        unparseable lines are skipped with a warning log (graceful recovery).

        Returns:
            List of validated Pydantic model instances in append order.
        """
        if not self._file_path.exists():
            return []

        records: list[T] = []
        with open(self._file_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    data = json.loads(stripped)
                    record = self._model_class.model_validate(data)
                    records.append(record)
                except (json.JSONDecodeError, ValidationError) as exc:
                    logger.warning(
                        "Skipping corrupt JSONL line %d in %s: %s",
                        line_no,
                        self._file_path,
                        exc,
                    )
        return records

    def get_active_view(self) -> list[T]:
        """Return records that are currently active.

        Active view rules (from design):
        1. Withdrawn records are excluded (field ``withdrawn`` is True).
        2. Superseded records are excluded (field ``supersedes`` is set on a
           *newer* record, meaning the *older* record is superseded).
        3. Rejected records are excluded (field ``review_status`` == "rejected").

        Records that do not have the relevant fields are considered active.

        Returns:
            Filtered list of active records in append order.
        """
        all_records = self.read_all()

        # Collect IDs of records that have been superseded by newer records.
        superseded_ids: set[str] = set()
        for record in all_records:
            supersedes_value = getattr(record, "supersedes", None)
            if supersedes_value:
                superseded_ids.add(supersedes_value)

        active: list[T] = []
        for record in all_records:
            # Rule 1: Skip withdrawn records
            if getattr(record, "withdrawn", False):
                continue

            # Rule 2: Skip records that have been superseded
            record_id = self._get_record_id(record)
            if record_id and record_id in superseded_ids:
                continue

            # Rule 3: Skip rejected records
            review_status = getattr(record, "review_status", None)
            if review_status == "rejected":
                continue

            active.append(record)

        return active

    def get_record_history(self, record_id: str) -> list[T]:
        """Return all versions/states of a record in chronological order.

        A record's history includes:
        - The original record with the given ID.
        - Any records that supersede it (following the supersedes chain).
        - Any records whose ID matches (e.g., same evidence_id across
          multiple append entries representing state changes).

        Args:
            record_id: The identifier to search for (checked against common
                ID fields: evidence_id, candidate_id, claim_id, gap_id,
                entry_id, record_id, id).

        Returns:
            List of records in chronological (append) order.
        """
        all_records = self.read_all()

        # Build a set of IDs in the supersession chain
        chain_ids: set[str] = {record_id}

        # Forward pass: find records that supersede something in our chain
        changed = True
        while changed:
            changed = False
            for record in all_records:
                rid = self._get_record_id(record)
                supersedes_value = getattr(record, "supersedes", None)
                if supersedes_value and supersedes_value in chain_ids:
                    if rid and rid not in chain_ids:
                        chain_ids.add(rid)
                        changed = True

        # Collect all records whose ID is in the chain
        history: list[T] = []
        for record in all_records:
            rid = self._get_record_id(record)
            if rid and rid in chain_ids:
                history.append(record)

        return history

    def _get_record_id(self, record: T) -> str | None:
        """Extract the primary identifier from a record.

        Checks common ID field names used across the data models.
        """
        for field_name in (
            "evidence_id",
            "candidate_id",
            "claim_id",
            "gap_id",
            "entry_id",
            "record_id",
            "event_id",
            "task_id",
            "ioc_id",
            "data_source_id",
            "id",
        ):
            value = getattr(record, field_name, None)
            if value is not None:
                return str(value)
        return None
