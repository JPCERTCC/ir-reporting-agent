"""Unit tests for AppendOnlyStore.

Validates Requirements 8.4, 8.6, 20.4:
- Append-only semantics (records never overwritten or deleted)
- Active view excludes withdrawn, superseded, and rejected records
- Record history returns chronological order
- Thread-safe append operations
- Corrupt JSONL recovery
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Optional

import pytest
from pydantic import BaseModel

from ir_agent.storage.store import AppendOnlyStore


# --- Test Pydantic models ---


class SimpleRecord(BaseModel):
    """Minimal record for basic tests."""

    id: str
    value: str


class EvidenceRecord(BaseModel):
    """Model mimicking evidence ledger entries with active view fields."""

    evidence_id: str
    observed_fact: str
    withdrawn: bool = False
    supersedes: Optional[str] = None
    review_status: str = "approved"


class ClaimRecord(BaseModel):
    """Model mimicking claim records."""

    claim_id: str
    claim_text: str
    review_status: str = "pending"


# --- Fixtures ---


@pytest.fixture
def tmp_jsonl(tmp_path: Path) -> Path:
    """Return path to a temporary JSONL file."""
    return tmp_path / "test_store.jsonl"


@pytest.fixture
def simple_store(tmp_jsonl: Path) -> AppendOnlyStore[SimpleRecord]:
    return AppendOnlyStore(tmp_jsonl, SimpleRecord)


@pytest.fixture
def evidence_store(tmp_jsonl: Path) -> AppendOnlyStore[EvidenceRecord]:
    return AppendOnlyStore(tmp_jsonl, EvidenceRecord)


@pytest.fixture
def claim_store(tmp_path: Path) -> AppendOnlyStore[ClaimRecord]:
    return AppendOnlyStore(tmp_path / "claims.jsonl", ClaimRecord)


# --- Basic Append and Read Tests ---


class TestAppend:
    def test_append_creates_file(self, simple_store: AppendOnlyStore[SimpleRecord], tmp_jsonl: Path):
        """Appending to a non-existent file creates it."""
        assert not tmp_jsonl.exists()
        simple_store.append(SimpleRecord(id="r1", value="hello"))
        assert tmp_jsonl.exists()

    def test_append_single_record(self, simple_store: AppendOnlyStore[SimpleRecord]):
        """A single append writes one JSON line."""
        simple_store.append(SimpleRecord(id="r1", value="hello"))
        records = simple_store.read_all()
        assert len(records) == 1
        assert records[0].id == "r1"
        assert records[0].value == "hello"

    def test_append_multiple_records(self, simple_store: AppendOnlyStore[SimpleRecord]):
        """Multiple appends produce multiple lines in order."""
        simple_store.append(SimpleRecord(id="r1", value="first"))
        simple_store.append(SimpleRecord(id="r2", value="second"))
        simple_store.append(SimpleRecord(id="r3", value="third"))

        records = simple_store.read_all()
        assert len(records) == 3
        assert [r.id for r in records] == ["r1", "r2", "r3"]

    def test_append_preserves_existing_records(
        self, simple_store: AppendOnlyStore[SimpleRecord], tmp_jsonl: Path
    ):
        """Appending never overwrites existing content (append-only invariant)."""
        simple_store.append(SimpleRecord(id="r1", value="original"))

        # Read raw file content
        content_before = tmp_jsonl.read_text(encoding="utf-8")

        simple_store.append(SimpleRecord(id="r2", value="new"))

        content_after = tmp_jsonl.read_text(encoding="utf-8")
        assert content_after.startswith(content_before)

    def test_append_type_error_wrong_model(self, simple_store: AppendOnlyStore[SimpleRecord]):
        """Appending a wrong model type raises TypeError."""
        wrong_record = EvidenceRecord(evidence_id="e1", observed_fact="test")
        with pytest.raises(TypeError, match="Expected instance of SimpleRecord"):
            simple_store.append(wrong_record)  # type: ignore[arg-type]

    def test_append_creates_parent_directories(self, tmp_path: Path):
        """Append creates parent directories if they don't exist."""
        deep_path = tmp_path / "nested" / "dir" / "store.jsonl"
        store = AppendOnlyStore(deep_path, SimpleRecord)
        store.append(SimpleRecord(id="r1", value="deep"))
        assert deep_path.exists()


# --- Read All Tests ---


class TestReadAll:
    def test_read_all_empty_file(self, simple_store: AppendOnlyStore[SimpleRecord], tmp_jsonl: Path):
        """Reading from a non-existent file returns empty list."""
        assert simple_store.read_all() == []

    def test_read_all_skips_empty_lines(
        self, simple_store: AppendOnlyStore[SimpleRecord], tmp_jsonl: Path
    ):
        """Empty lines in the JSONL are skipped."""
        tmp_jsonl.parent.mkdir(parents=True, exist_ok=True)
        content = (
            json.dumps({"id": "r1", "value": "first"}) + "\n"
            "\n"
            + json.dumps({"id": "r2", "value": "second"}) + "\n"
        )
        tmp_jsonl.write_text(content, encoding="utf-8")

        records = simple_store.read_all()
        assert len(records) == 2

    def test_read_all_validates_via_pydantic(
        self, simple_store: AppendOnlyStore[SimpleRecord], tmp_jsonl: Path
    ):
        """Records are validated through Pydantic on deserialization."""
        tmp_jsonl.parent.mkdir(parents=True, exist_ok=True)
        # Valid record
        valid = json.dumps({"id": "r1", "value": "valid"})
        tmp_jsonl.write_text(valid + "\n", encoding="utf-8")

        records = simple_store.read_all()
        assert len(records) == 1
        assert isinstance(records[0], SimpleRecord)


# --- Corrupt JSONL Recovery ---


class TestCorruptRecovery:
    def test_skips_invalid_json(
        self, simple_store: AppendOnlyStore[SimpleRecord], tmp_jsonl: Path
    ):
        """Corrupt JSON lines are skipped with a warning."""
        tmp_jsonl.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            json.dumps({"id": "r1", "value": "good"}),
            "this is not json{{{",
            json.dumps({"id": "r2", "value": "also good"}),
        ]
        tmp_jsonl.write_text("\n".join(lines) + "\n", encoding="utf-8")

        records = simple_store.read_all()
        assert len(records) == 2
        assert records[0].id == "r1"
        assert records[1].id == "r2"

    def test_skips_invalid_schema(
        self, simple_store: AppendOnlyStore[SimpleRecord], tmp_jsonl: Path
    ):
        """Lines with valid JSON but invalid schema are skipped."""
        tmp_jsonl.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            json.dumps({"id": "r1", "value": "good"}),
            json.dumps({"wrong_field": 123}),  # Missing required fields
            json.dumps({"id": "r3", "value": "fine"}),
        ]
        tmp_jsonl.write_text("\n".join(lines) + "\n", encoding="utf-8")

        records = simple_store.read_all()
        assert len(records) == 2


# --- Active View Tests ---


class TestActiveView:
    def test_active_view_excludes_withdrawn(self, evidence_store: AppendOnlyStore[EvidenceRecord]):
        """Withdrawn records are excluded from active view."""
        evidence_store.append(
            EvidenceRecord(evidence_id="e1", observed_fact="fact1", withdrawn=False)
        )
        evidence_store.append(
            EvidenceRecord(evidence_id="e2", observed_fact="fact2", withdrawn=True)
        )
        evidence_store.append(
            EvidenceRecord(evidence_id="e3", observed_fact="fact3", withdrawn=False)
        )

        active = evidence_store.get_active_view()
        assert len(active) == 2
        assert {r.evidence_id for r in active} == {"e1", "e3"}

    def test_active_view_excludes_superseded(self, evidence_store: AppendOnlyStore[EvidenceRecord]):
        """Superseded records are excluded from active view."""
        evidence_store.append(
            EvidenceRecord(evidence_id="e1", observed_fact="original")
        )
        evidence_store.append(
            EvidenceRecord(evidence_id="e2", observed_fact="corrected", supersedes="e1")
        )

        active = evidence_store.get_active_view()
        assert len(active) == 1
        assert active[0].evidence_id == "e2"

    def test_active_view_excludes_rejected(self, claim_store: AppendOnlyStore[ClaimRecord]):
        """Rejected records are excluded from active view."""
        claim_store.append(ClaimRecord(claim_id="c1", claim_text="ok", review_status="approved"))
        claim_store.append(ClaimRecord(claim_id="c2", claim_text="no", review_status="rejected"))
        claim_store.append(ClaimRecord(claim_id="c3", claim_text="maybe", review_status="pending"))

        active = claim_store.get_active_view()
        assert len(active) == 2
        assert {r.claim_id for r in active} == {"c1", "c3"}

    def test_active_view_all_filters_combined(
        self, evidence_store: AppendOnlyStore[EvidenceRecord]
    ):
        """All three filter rules work together."""
        evidence_store.append(
            EvidenceRecord(evidence_id="e1", observed_fact="original")
        )
        evidence_store.append(
            EvidenceRecord(
                evidence_id="e2", observed_fact="replacement", supersedes="e1"
            )
        )
        evidence_store.append(
            EvidenceRecord(evidence_id="e3", observed_fact="withdrawn", withdrawn=True)
        )
        evidence_store.append(
            EvidenceRecord(
                evidence_id="e4", observed_fact="rejected", review_status="rejected"
            )
        )
        evidence_store.append(
            EvidenceRecord(evidence_id="e5", observed_fact="active")
        )

        active = evidence_store.get_active_view()
        assert len(active) == 2
        assert {r.evidence_id for r in active} == {"e2", "e5"}

    def test_active_view_empty_store(self, evidence_store: AppendOnlyStore[EvidenceRecord]):
        """Empty store returns empty active view."""
        assert evidence_store.get_active_view() == []

    def test_active_view_records_without_filter_fields(
        self, simple_store: AppendOnlyStore[SimpleRecord]
    ):
        """Records without withdrawn/supersedes/review_status are considered active."""
        simple_store.append(SimpleRecord(id="r1", value="a"))
        simple_store.append(SimpleRecord(id="r2", value="b"))

        active = simple_store.get_active_view()
        assert len(active) == 2


# --- Record History Tests ---


class TestRecordHistory:
    def test_history_single_record(self, evidence_store: AppendOnlyStore[EvidenceRecord]):
        """History of a single record with no supersession."""
        evidence_store.append(
            EvidenceRecord(evidence_id="e1", observed_fact="fact")
        )
        history = evidence_store.get_record_history("e1")
        assert len(history) == 1
        assert history[0].evidence_id == "e1"

    def test_history_with_supersession_chain(
        self, evidence_store: AppendOnlyStore[EvidenceRecord]
    ):
        """History includes original and superseding records chronologically."""
        evidence_store.append(
            EvidenceRecord(evidence_id="e1", observed_fact="v1")
        )
        evidence_store.append(
            EvidenceRecord(evidence_id="e2", observed_fact="v2", supersedes="e1")
        )
        evidence_store.append(
            EvidenceRecord(evidence_id="e3", observed_fact="v3", supersedes="e2")
        )

        history = evidence_store.get_record_history("e1")
        assert len(history) == 3
        assert [r.evidence_id for r in history] == ["e1", "e2", "e3"]

    def test_history_nonexistent_id(self, evidence_store: AppendOnlyStore[EvidenceRecord]):
        """History of nonexistent record returns empty list."""
        evidence_store.append(
            EvidenceRecord(evidence_id="e1", observed_fact="fact")
        )
        history = evidence_store.get_record_history("nonexistent")
        assert history == []

    def test_history_chronological_order(self, evidence_store: AppendOnlyStore[EvidenceRecord]):
        """History preserves append order (chronological)."""
        evidence_store.append(
            EvidenceRecord(evidence_id="e1", observed_fact="first")
        )
        evidence_store.append(
            EvidenceRecord(evidence_id="e1-fix", observed_fact="second", supersedes="e1")
        )

        history = evidence_store.get_record_history("e1")
        assert len(history) == 2
        assert history[0].evidence_id == "e1"
        assert history[1].evidence_id == "e1-fix"


# --- Thread Safety Tests ---


class TestThreadSafety:
    def test_concurrent_appends(self, tmp_path: Path):
        """Multiple threads appending concurrently produces no data loss."""
        store_path = tmp_path / "concurrent.jsonl"
        store: AppendOnlyStore[SimpleRecord] = AppendOnlyStore(store_path, SimpleRecord)
        num_threads = 10
        records_per_thread = 50

        def append_records(thread_id: int):
            for i in range(records_per_thread):
                store.append(SimpleRecord(id=f"t{thread_id}-r{i}", value=f"val-{i}"))

        threads = [
            threading.Thread(target=append_records, args=(tid,))
            for tid in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        records = store.read_all()
        assert len(records) == num_threads * records_per_thread

    def test_concurrent_appends_no_corruption(self, tmp_path: Path):
        """Concurrent appends produce valid JSON on every line."""
        store_path = tmp_path / "no_corrupt.jsonl"
        store: AppendOnlyStore[SimpleRecord] = AppendOnlyStore(store_path, SimpleRecord)
        num_threads = 5
        records_per_thread = 20

        def append_records(thread_id: int):
            for i in range(records_per_thread):
                store.append(SimpleRecord(id=f"t{thread_id}-r{i}", value="x" * 100))

        threads = [
            threading.Thread(target=append_records, args=(tid,))
            for tid in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify every line is valid JSON
        with open(store_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                stripped = line.strip()
                if stripped:
                    json.loads(stripped)  # Should not raise
