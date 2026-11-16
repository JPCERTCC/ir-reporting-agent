"""Unit tests for the Text Chunker module.

Tests cover:
- Single chunk for small files
- Splitting into multiple chunks when file exceeds max_size
- Preserving line number references (start_line, end_line)
- Avoiding splitting within multi-line log entries
- Chunk metadata: source_file_id, chunk_index, start_line, end_line, content
- Overlap between consecutive chunks
- Handling binary files gracefully
- Handling empty files

Requirements: 3.1, 3.2, 3.3, 3.4
"""

from pathlib import Path

import pytest

from ir_agent.ingestion.chunker import Chunk, chunk_file, _is_log_entry_start
from ir_agent.ingestion.scanner import FileRecord


@pytest.fixture
def artifacts_dir(tmp_path: Path) -> Path:
    """Create a temporary artifacts directory."""
    d = tmp_path / "artifacts"
    d.mkdir()
    return d


def _make_file_record(
    artifacts_dir: Path, filename: str, content: str, encoding: str = "utf-8"
) -> FileRecord:
    """Create a file on disk and return a matching FileRecord."""
    file_path = artifacts_dir / filename
    file_path.write_text(content, encoding=encoding)
    lines = content.count("\n") + (0 if content.endswith("\n") else 1) if content else 0
    return FileRecord(
        file_id="test-file-001",
        path=filename,
        sha256="abc123",
        host="host01",
        file_type="text/x-log",
        encoding=encoding,
        line_count=lines,
        time_range=None,
    )


class TestChunkFileSmallFile:
    """Test that files smaller than max_size produce a single chunk."""

    def test_single_chunk_for_small_file(self, artifacts_dir: Path):
        content = "line1\nline2\nline3\n"
        record = _make_file_record(artifacts_dir, "small.log", content)

        chunks = chunk_file(record, max_size=100, overlap=10, artifacts_dir=artifacts_dir)

        assert len(chunks) == 1
        assert chunks[0].chunk_index == 0
        assert chunks[0].start_line == 1
        assert chunks[0].end_line == 3
        assert chunks[0].content == content
        assert chunks[0].source_file_id == "test-file-001"

    def test_chunk_id_is_unique(self, artifacts_dir: Path):
        content = "line1\nline2\n"
        record = _make_file_record(artifacts_dir, "small.log", content)

        chunks = chunk_file(record, max_size=100, overlap=0, artifacts_dir=artifacts_dir)

        assert chunks[0].chunk_id  # non-empty
        # UUID format check
        assert len(chunks[0].chunk_id) == 36


class TestChunkFileLargeFile:
    """Test splitting large files into multiple chunks."""

    def test_splits_large_file(self, artifacts_dir: Path):
        # Create a file with 10 lines, max_size=4 should produce multiple chunks
        lines = [f"2024-01-15T10:00:{i:02d} event {i}\n" for i in range(10)]
        content = "".join(lines)
        record = _make_file_record(artifacts_dir, "large.log", content)

        chunks = chunk_file(record, max_size=4, overlap=0, artifacts_dir=artifacts_dir)

        assert len(chunks) >= 3  # 10 lines / 4 per chunk = 3 chunks (last may be smaller)
        # Verify chunk indices are sequential
        for i, chunk in enumerate(chunks):
            assert chunk.chunk_index == i

    def test_preserves_line_references(self, artifacts_dir: Path):
        lines = [f"2024-01-15T10:00:{i:02d} event {i}\n" for i in range(8)]
        content = "".join(lines)
        record = _make_file_record(artifacts_dir, "lines.log", content)

        chunks = chunk_file(record, max_size=4, overlap=0, artifacts_dir=artifacts_dir)

        # First chunk should start at line 1
        assert chunks[0].start_line == 1
        assert chunks[0].end_line == 4
        # Second chunk should start where the first ended + 1
        assert chunks[1].start_line == 5

    def test_all_content_covered(self, artifacts_dir: Path):
        """All lines in the file should appear in at least one chunk."""
        lines = [f"2024-01-15T10:00:{i:02d} event {i}\n" for i in range(10)]
        content = "".join(lines)
        record = _make_file_record(artifacts_dir, "coverage.log", content)

        chunks = chunk_file(record, max_size=4, overlap=0, artifacts_dir=artifacts_dir)

        # Combine all chunk content
        all_chunk_content = "".join(c.content for c in chunks)
        # Every original line should appear
        for line in lines:
            assert line in all_chunk_content


class TestChunkFileOverlap:
    """Test overlap between consecutive chunks."""

    def test_overlap_provides_shared_lines(self, artifacts_dir: Path):
        lines = [f"2024-01-15T10:00:{i:02d} event {i}\n" for i in range(10)]
        content = "".join(lines)
        record = _make_file_record(artifacts_dir, "overlap.log", content)

        chunks = chunk_file(record, max_size=4, overlap=2, artifacts_dir=artifacts_dir)

        # With overlap, consecutive chunks should share some content
        if len(chunks) >= 2:
            # The end of the first chunk and start of the second should overlap
            first_lines = chunks[0].content.splitlines(keepends=True)
            second_lines = chunks[1].content.splitlines(keepends=True)
            # Some lines from end of first chunk should appear in second chunk
            overlap_found = any(
                line in second_lines for line in first_lines[-2:]
            )
            assert overlap_found


class TestMultiLineLogEntries:
    """Test that multi-line log entries are not split across chunks."""

    def test_multiline_entry_stays_together(self, artifacts_dir: Path):
        """A multi-line log entry (traceback) should not be split."""
        # Create log entries with multi-line content
        entries = []
        for i in range(6):
            if i == 2:
                # Multi-line entry with traceback
                entries.append(f"2024-01-15T10:00:0{i} ERROR exception occurred\n")
                entries.append("  Traceback (most recent call last):\n")
                entries.append('    File "main.py", line 42, in foo\n')
                entries.append("  ValueError: something went wrong\n")
            else:
                entries.append(f"2024-01-15T10:00:0{i} INFO normal event {i}\n")

        content = "".join(entries)
        record = _make_file_record(artifacts_dir, "multiline.log", content)

        # Use max_size=3, which would split the multi-line entry if not careful
        chunks = chunk_file(record, max_size=3, overlap=0, artifacts_dir=artifacts_dir)

        # The multi-line entry (4 lines) should appear together in one chunk
        traceback_part = "  Traceback (most recent call last):\n"
        error_line = "2024-01-15T10:00:02 ERROR exception occurred\n"

        for chunk in chunks:
            if error_line in chunk.content:
                # The traceback continuation must also be in this chunk
                assert traceback_part in chunk.content
                break
        else:
            pytest.fail("Error entry not found in any chunk")

    def test_continuation_lines_not_start_new_entry(self):
        """Lines without timestamps should be treated as continuations."""
        assert not _is_log_entry_start("  Traceback (most recent call last):")
        assert not _is_log_entry_start("    at com.example.Main.run(Main.java:42)")
        assert not _is_log_entry_start("  caused by: NullPointerException")

    def test_timestamp_lines_start_new_entry(self):
        """Lines with recognized timestamp patterns start new entries."""
        assert _is_log_entry_start("2024-01-15T10:30:00 INFO started")
        assert _is_log_entry_start("Jan 15 10:30:00 host01 sshd[1234]: Accepted")
        assert _is_log_entry_start("01/15/2024 10:30:00 Event logged")


class TestChunkFileEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_file_returns_no_chunks(self, artifacts_dir: Path):
        record = _make_file_record(artifacts_dir, "empty.log", "")

        chunks = chunk_file(record, max_size=100, overlap=0, artifacts_dir=artifacts_dir)

        assert chunks == []

    def test_binary_file_returns_no_chunks(self, artifacts_dir: Path):
        # Write some binary content
        file_path = artifacts_dir / "binary.dat"
        file_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        record = FileRecord(
            file_id="binary-001",
            path="binary.dat",
            sha256="def456",
            host="host01",
            file_type="image/png",
            encoding="binary",
            line_count=0,
            time_range=None,
        )

        chunks = chunk_file(record, max_size=100, overlap=0, artifacts_dir=artifacts_dir)

        assert chunks == []

    def test_file_not_found_raises(self, artifacts_dir: Path):
        record = FileRecord(
            file_id="missing-001",
            path="nonexistent.log",
            sha256="000",
            host="host01",
            file_type="text/x-log",
            encoding="utf-8",
            line_count=0,
            time_range=None,
        )

        with pytest.raises(FileNotFoundError):
            chunk_file(record, max_size=100, overlap=0, artifacts_dir=artifacts_dir)

    def test_chunk_metadata_fields(self, artifacts_dir: Path):
        content = "2024-01-01T00:00:00 line1\n2024-01-01T00:00:01 line2\n"
        record = _make_file_record(artifacts_dir, "meta.log", content)

        chunks = chunk_file(record, max_size=100, overlap=0, artifacts_dir=artifacts_dir)

        chunk = chunks[0]
        assert chunk.source_file_id == "test-file-001"
        assert chunk.chunk_index == 0
        assert chunk.start_line >= 1
        assert chunk.end_line >= chunk.start_line
        assert chunk.content == content
        assert isinstance(chunk.chunk_id, str)
        assert len(chunk.chunk_id) > 0

    def test_single_very_large_entry_exceeding_max_size(self, artifacts_dir: Path):
        """A single multi-line entry larger than max_size still forms one chunk."""
        lines = ["2024-01-15T10:00:00 ERROR big entry\n"]
        lines += [f"  detail line {i}\n" for i in range(10)]
        content = "".join(lines)
        record = _make_file_record(artifacts_dir, "bigentry.log", content)

        # max_size=5, but the single entry is 11 lines - it must not be split
        chunks = chunk_file(record, max_size=5, overlap=0, artifacts_dir=artifacts_dir)

        # The entry should be in one chunk (even though it exceeds max_size)
        assert len(chunks) >= 1
        assert "ERROR big entry" in chunks[0].content
        assert "  detail line 9\n" in chunks[0].content
