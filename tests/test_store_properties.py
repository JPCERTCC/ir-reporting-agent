"""Property-based tests for AppendOnlyStore.

**Validates: Requirements 8.4, 8.6, 20.4**

Property 9: Append-Only Store Integrity
- Appended records are never overwritten or deleted
- Active view correctly excludes withdrawn and superseded records
- Record history returns chronological order
- File size only grows (never shrinks) after appends
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from hypothesis import given, settings, assume
from hypothesis import strategies as st
from pydantic import BaseModel

from ir_agent.storage.store import AppendOnlyStore


# --- Test Models for property-based tests ---


class PropRecord(BaseModel):
    """Record model for property-based testing with all filter-relevant fields."""

    record_id: str
    data: str
    withdrawn: bool = False
    supersedes: Optional[str] = None
    review_status: str = "approved"


# --- Strategies ---

# Generate valid record IDs (non-empty, alphanumeric with hyphens for readability)
record_id_st = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_"),
    min_size=1,
    max_size=20,
)

# Generate arbitrary string data (avoiding only null bytes which break JSONL)
data_st = st.text(min_size=0, max_size=100).filter(lambda s: "\x00" not in s and "\n" not in s)

# Generate a valid review_status
review_status_st = st.sampled_from(["approved", "pending", "rejected"])


# Strategy for a single PropRecord (always active — no withdrawn/superseded/rejected)
active_record_st = st.builds(
    PropRecord,
    record_id=record_id_st,
    data=data_st,
    withdrawn=st.just(False),
    supersedes=st.just(None),
    review_status=st.sampled_from(["approved", "pending"]),
)

# Strategy for a record that may or may not be active
any_record_st = st.builds(
    PropRecord,
    record_id=record_id_st,
    data=data_st,
    withdrawn=st.booleans(),
    supersedes=st.one_of(st.none(), record_id_st),
    review_status=review_status_st,
)


# --- Property Tests ---


class TestAppendOnlyIntegrity:
    """Property 9: Append-Only Store Integrity — append-only semantics."""

    @given(records=st.lists(active_record_st, min_size=1, max_size=30))
    @settings(max_examples=100, deadline=None)
    def test_read_all_returns_all_in_order(self, records: list[PropRecord], tmp_path_factory):
        """For any sequence of appends, read_all() returns all records in order.

        Nothing is lost and nothing is reordered.

        **Validates: Requirements 8.4, 8.6**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_store")
        store_path = tmp_dir / "store.jsonl"
        store: AppendOnlyStore[PropRecord] = AppendOnlyStore(store_path, PropRecord)

        for record in records:
            store.append(record)

        read_back = store.read_all()

        # Same count
        assert len(read_back) == len(records)

        # Same order and same data
        for original, loaded in zip(records, read_back):
            assert loaded.record_id == original.record_id
            assert loaded.data == original.data
            assert loaded.withdrawn == original.withdrawn
            assert loaded.supersedes == original.supersedes
            assert loaded.review_status == original.review_status

    @given(records=st.lists(active_record_st, min_size=1, max_size=30))
    @settings(max_examples=100, deadline=None)
    def test_file_size_never_shrinks(self, records: list[PropRecord], tmp_path_factory):
        """File size only grows (never shrinks) after appends.

        **Validates: Requirements 8.4, 8.6**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_grow")
        store_path = tmp_dir / "store.jsonl"
        store: AppendOnlyStore[PropRecord] = AppendOnlyStore(store_path, PropRecord)

        previous_size = 0
        for record in records:
            store.append(record)
            current_size = store_path.stat().st_size
            assert current_size > previous_size, (
                f"File size did not grow: was {previous_size}, now {current_size}"
            )
            previous_size = current_size

    @given(records=st.lists(active_record_st, min_size=2, max_size=20))
    @settings(max_examples=80, deadline=None)
    def test_existing_content_preserved_after_append(
        self, records: list[PropRecord], tmp_path_factory
    ):
        """Appending a new record never alters previously written bytes.

        **Validates: Requirements 8.4, 8.6**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_preserve")
        store_path = tmp_dir / "store.jsonl"
        store: AppendOnlyStore[PropRecord] = AppendOnlyStore(store_path, PropRecord)

        # Append first record
        store.append(records[0])
        content_before = store_path.read_bytes()

        # Append remaining records
        for record in records[1:]:
            store.append(record)

        content_after = store_path.read_bytes()

        # The content after must START with the exact bytes that were there before
        assert content_after[: len(content_before)] == content_before


class TestActiveViewProperty:
    """Property 9: Active view is a strict subset of read_all."""

    @given(records=st.lists(any_record_st, min_size=0, max_size=30))
    @settings(max_examples=100, deadline=None)
    def test_active_view_is_subset_of_read_all(
        self, records: list[PropRecord], tmp_path_factory
    ):
        """For any mix of records, active view is a subset of read_all.

        **Validates: Requirements 8.4, 8.6, 20.4**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_active")
        store_path = tmp_dir / "store.jsonl"
        store: AppendOnlyStore[PropRecord] = AppendOnlyStore(store_path, PropRecord)

        for record in records:
            store.append(record)

        all_records = store.read_all()
        active_records = store.get_active_view()

        # Active view length is <= total records
        assert len(active_records) <= len(all_records)

        # Every active record must exist in all_records (by identity check via serialization)
        all_serialized = [r.model_dump_json() for r in all_records]
        for active_rec in active_records:
            assert active_rec.model_dump_json() in all_serialized

    @given(records=st.lists(any_record_st, min_size=0, max_size=30))
    @settings(max_examples=100, deadline=None)
    def test_active_view_excludes_withdrawn_superseded_rejected(
        self, records: list[PropRecord], tmp_path_factory
    ):
        """Active view never contains withdrawn, superseded, or rejected records.

        **Validates: Requirements 8.4, 8.6, 20.4**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_exclude")
        store_path = tmp_dir / "store.jsonl"
        store: AppendOnlyStore[PropRecord] = AppendOnlyStore(store_path, PropRecord)

        for record in records:
            store.append(record)

        all_records = store.read_all()
        active_records = store.get_active_view()

        # Collect IDs that are superseded (some record has `supersedes` pointing to them)
        superseded_ids: set[str] = set()
        for rec in all_records:
            if rec.supersedes:
                superseded_ids.add(rec.supersedes)

        for active_rec in active_records:
            # Rule 1: not withdrawn
            assert active_rec.withdrawn is False, (
                f"Active view contains withdrawn record: {active_rec.record_id}"
            )
            # Rule 2: not superseded
            assert active_rec.record_id not in superseded_ids, (
                f"Active view contains superseded record: {active_rec.record_id}"
            )
            # Rule 3: not rejected
            assert active_rec.review_status != "rejected", (
                f"Active view contains rejected record: {active_rec.record_id}"
            )


class TestRecordHistoryProperty:
    """Property 9: Record history returns chronological order."""

    @given(
        base_id=record_id_st,
        chain_length=st.integers(min_value=1, max_value=6),
        data_values=st.lists(data_st, min_size=6, max_size=6),
    )
    @settings(max_examples=80, deadline=None)
    def test_record_history_chronological_order(
        self,
        base_id: str,
        chain_length: int,
        data_values: list[str],
        tmp_path_factory,
    ):
        """For any record with a supersession chain, get_record_history returns
        records in chronological (append) order.

        **Validates: Requirements 8.4, 8.6, 20.4**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_history")
        store_path = tmp_dir / "store.jsonl"
        store: AppendOnlyStore[PropRecord] = AppendOnlyStore(store_path, PropRecord)

        # Build a supersession chain: base_id → base_id-v2 → base_id-v3 → ...
        chain_ids = [base_id] + [f"{base_id}-v{i+2}" for i in range(chain_length - 1)]

        for i, rid in enumerate(chain_ids):
            supersedes_val = chain_ids[i - 1] if i > 0 else None
            record = PropRecord(
                record_id=rid,
                data=data_values[i],
                supersedes=supersedes_val,
            )
            store.append(record)

        history = store.get_record_history(base_id)

        # History must include all records in the chain
        assert len(history) == chain_length

        # History must be in chronological (append) order
        history_ids = [r.record_id for r in history]
        assert history_ids == chain_ids, (
            f"Expected chronological order {chain_ids}, got {history_ids}"
        )

    @given(
        records=st.lists(active_record_st, min_size=1, max_size=15),
        query_index=st.integers(min_value=0, max_value=14),
    )
    @settings(max_examples=80, deadline=None)
    def test_record_history_contains_queried_record(
        self,
        records: list[PropRecord],
        query_index: int,
        tmp_path_factory,
    ):
        """get_record_history always contains the queried record itself (if it exists).

        **Validates: Requirements 8.4, 8.6, 20.4**
        """
        assume(query_index < len(records))

        tmp_dir = tmp_path_factory.mktemp("prop_hist_contains")
        store_path = tmp_dir / "store.jsonl"
        store: AppendOnlyStore[PropRecord] = AppendOnlyStore(store_path, PropRecord)

        for record in records:
            store.append(record)

        target_id = records[query_index].record_id
        history = store.get_record_history(target_id)

        # The queried record must appear in its own history
        history_ids = [r.record_id for r in history]
        assert target_id in history_ids, (
            f"Record {target_id} not found in its own history: {history_ids}"
        )
