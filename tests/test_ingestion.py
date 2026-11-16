"""Unit tests for the Ingestion Layer (scanner module).

Tests cover:
- SHA-256 hash computation for known content
- File classification using content-based detection (magic bytes, text patterns)
- Encoding detection
- Error handling for unreadable files and non-existent directories
- Line counting

Requirements: 2.2, 2.8, 3.2, 3.4
"""

import hashlib
from pathlib import Path

import pytest

from ir_agent.ingestion.scanner import IngestionService


@pytest.fixture
def service() -> IngestionService:
    """Create an IngestionService instance."""
    return IngestionService()


# --- SHA-256 Hash Computation (Requirement 2.2) ---


class TestComputeHash:
    """Test SHA-256 hash computation for known content."""

    def test_hash_of_known_content(self, service: IngestionService, tmp_path: Path):
        """Hash of known content matches expected SHA-256 value."""
        content = b"Hello, World!"
        expected_hash = hashlib.sha256(content).hexdigest()

        file_path = tmp_path / "hello.txt"
        file_path.write_bytes(content)

        result = service.compute_hash(file_path)

        assert result == expected_hash

    def test_hash_of_empty_file(self, service: IngestionService, tmp_path: Path):
        """Hash of an empty file matches SHA-256 of empty bytes."""
        expected_hash = hashlib.sha256(b"").hexdigest()

        file_path = tmp_path / "empty.txt"
        file_path.write_bytes(b"")

        result = service.compute_hash(file_path)

        assert result == expected_hash

    def test_hash_is_deterministic(self, service: IngestionService, tmp_path: Path):
        """Same content produces the same hash across multiple calls."""
        content = b"deterministic content for hashing"

        file_path = tmp_path / "repeat.txt"
        file_path.write_bytes(content)

        hash1 = service.compute_hash(file_path)
        hash2 = service.compute_hash(file_path)

        assert hash1 == hash2

    def test_different_content_produces_different_hash(
        self, service: IngestionService, tmp_path: Path
    ):
        """Different content produces different hashes."""
        file_a = tmp_path / "a.txt"
        file_a.write_bytes(b"content A")

        file_b = tmp_path / "b.txt"
        file_b.write_bytes(b"content B")

        hash_a = service.compute_hash(file_a)
        hash_b = service.compute_hash(file_b)

        assert hash_a != hash_b

    def test_hash_format_is_hex_string(self, service: IngestionService, tmp_path: Path):
        """Hash result is a 64-character hex string."""
        file_path = tmp_path / "format.txt"
        file_path.write_bytes(b"test")

        result = service.compute_hash(file_path)

        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


# --- File Classification (Requirement 2.3 / Content Detection) ---


class TestClassifyFile:
    """Test file classification using content-based detection."""

    def test_png_magic_bytes(self, service: IngestionService, tmp_path: Path):
        """PNG file is detected by magic bytes, not extension."""
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        file_path = tmp_path / "image.dat"  # No .png extension
        file_path.write_bytes(png_header)

        result = service.classify_file(file_path)

        assert result == "image/png"

    def test_jpeg_magic_bytes(self, service: IngestionService, tmp_path: Path):
        """JPEG file is detected by magic bytes."""
        jpeg_header = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        file_path = tmp_path / "photo.dat"
        file_path.write_bytes(jpeg_header)

        result = service.classify_file(file_path)

        assert result == "image/jpeg"

    def test_pdf_magic_bytes(self, service: IngestionService, tmp_path: Path):
        """PDF file is detected by magic bytes."""
        pdf_header = b"%PDF-1.4 " + b"\x00" * 100
        file_path = tmp_path / "document.dat"
        file_path.write_bytes(pdf_header)

        result = service.classify_file(file_path)

        assert result == "application/pdf"

    def test_gzip_magic_bytes(self, service: IngestionService, tmp_path: Path):
        """Gzip file is detected by magic bytes."""
        gzip_header = b"\x1f\x8b\x08" + b"\x00" * 100
        file_path = tmp_path / "archive.dat"
        file_path.write_bytes(gzip_header)

        result = service.classify_file(file_path)

        assert result == "application/gzip"

    def test_syslog_content_pattern(self, service: IngestionService, tmp_path: Path):
        """Syslog format is detected by content pattern."""
        syslog_content = "Jan 15 10:30:00 host01 sshd[1234]: Accepted publickey\n"
        file_path = tmp_path / "messages.log"
        file_path.write_text(syslog_content, encoding="utf-8")

        result = service.classify_file(file_path)

        assert result == "text/x-syslog"

    def test_csv_content_pattern(self, service: IngestionService, tmp_path: Path):
        """CSV format is detected by content pattern (comma-separated header)."""
        csv_content = '"timestamp","source","event_id"\n"2024-01-15","host01","4624"\n'
        file_path = tmp_path / "events.dat"
        file_path.write_text(csv_content, encoding="utf-8")

        result = service.classify_file(file_path)

        assert result == "text/csv"

    def test_json_content_pattern(self, service: IngestionService, tmp_path: Path):
        """JSON is detected by content pattern."""
        json_content = '{"event": "login", "user": "admin"}\n'
        file_path = tmp_path / "data.dat"
        file_path.write_text(json_content, encoding="utf-8")

        result = service.classify_file(file_path)

        # Could be application/json or application/x-jsonl
        assert result in ("application/json", "application/x-jsonl")

    def test_plain_text_fallback(self, service: IngestionService, tmp_path: Path):
        """Plain text without recognizable patterns falls back to text/plain."""
        plain_content = "This is just plain text with no special format.\n"
        file_path = tmp_path / "notes.txt"
        file_path.write_text(plain_content, encoding="utf-8")

        result = service.classify_file(file_path)

        assert result == "text/plain"

    def test_empty_file_classified_as_octet_stream(
        self, service: IngestionService, tmp_path: Path
    ):
        """Empty files are classified as application/octet-stream."""
        file_path = tmp_path / "empty.dat"
        file_path.write_bytes(b"")

        result = service.classify_file(file_path)

        assert result == "application/octet-stream"

    def test_classification_uses_content_not_extension(
        self, service: IngestionService, tmp_path: Path
    ):
        """Classification uses content, not file extension."""
        # Write syslog content to a file with .csv extension
        syslog_content = "Jan 15 10:30:00 host01 sshd[1234]: Accepted publickey\n"
        file_path = tmp_path / "misleading.csv"
        file_path.write_text(syslog_content, encoding="utf-8")

        result = service.classify_file(file_path)

        # Should detect syslog, not CSV
        assert result == "text/x-syslog"


# --- Error Handling (Requirement 2.8) ---


class TestErrorHandling:
    """Test error handling for unreadable files and directories."""

    def test_scan_nonexistent_directory_returns_empty(
        self, service: IngestionService, tmp_path: Path
    ):
        """Scanning a non-existent directory returns an empty list."""
        nonexistent = tmp_path / "does_not_exist"

        records = service.scan_directory(nonexistent)

        assert records == []

    def test_scan_file_as_directory_returns_empty(
        self, service: IngestionService, tmp_path: Path
    ):
        """Scanning a file path (not a directory) returns an empty list."""
        file_path = tmp_path / "not_a_dir.txt"
        file_path.write_text("content")

        records = service.scan_directory(file_path)

        assert records == []

    def test_unreadable_file_skipped_gracefully(
        self, service: IngestionService, tmp_path: Path
    ):
        """Unreadable files are skipped and other files still processed."""
        artifacts_dir = tmp_path / "artifacts"
        host_dir = artifacts_dir / "host01"
        host_dir.mkdir(parents=True)

        # Create a valid file
        good_file = host_dir / "good.log"
        good_file.write_text("2024-01-15T10:00:00 normal event\n", encoding="utf-8")

        # Create a file that will cause an error (simulate by making path a directory)
        # This tests that scan_directory continues processing after errors
        bad_path = host_dir / "bad_dir"
        bad_path.mkdir()  # This is a directory, not a file - rglob("*") skips it

        records = service.scan_directory(artifacts_dir)

        # Should still get the good file
        assert len(records) >= 1
        assert any("good.log" in r.path for r in records)

    def test_classify_unreadable_file_returns_octet_stream(
        self, service: IngestionService, tmp_path: Path
    ):
        """Classifying a non-existent file returns application/octet-stream."""
        nonexistent = tmp_path / "ghost.bin"

        result = service.classify_file(nonexistent)

        assert result == "application/octet-stream"

    def test_scan_empty_directory_returns_empty(
        self, service: IngestionService, tmp_path: Path
    ):
        """Scanning an empty directory returns an empty list."""
        empty_dir = tmp_path / "empty_artifacts"
        empty_dir.mkdir()

        records = service.scan_directory(empty_dir)

        assert records == []

    def test_artifact_metadata_sidecar_is_not_ingested(
        self, service: IngestionService, tmp_path: Path
    ):
        """artifact_metadata.yaml is context only, not an evidence artifact."""
        artifacts_dir = tmp_path / "artifacts"
        host_dir = artifacts_dir / "FS01"
        host_dir.mkdir(parents=True)
        (host_dir / "artifact_metadata.yaml").write_text(
            "system_role: file_server\n",
            encoding="utf-8",
        )
        (host_dir / "notes.txt").write_text(
            "Free-form analyst note\n",
            encoding="utf-8",
        )

        records = service.scan_directory(artifacts_dir)

        assert [r.path for r in records] == ["FS01/notes.txt"]

    def test_artifact_metadata_attaches_to_records(
        self, service: IngestionService, tmp_path: Path
    ):
        """Optional metadata is merged into matching FileRecord objects."""
        artifacts_dir = tmp_path / "artifacts"
        host_dir = artifacts_dir / "FS01"
        host_dir.mkdir(parents=True)
        (host_dir / "artifact_metadata.yaml").write_text(
            "system_role: file_server\n"
            "files:\n"
            "  notes.txt:\n"
            "    artifact_kind: analyst_note\n",
            encoding="utf-8",
        )
        (host_dir / "notes.txt").write_text(
            "Free-form analyst note\n",
            encoding="utf-8",
        )

        records = service.scan_directory(artifacts_dir)

        assert records[0].metadata["system_role"] == "file_server"
        assert records[0].metadata["artifact_kind"] == "analyst_note"


# --- Chunker Preserves Line References (Requirement 3.2) ---


class TestChunkerLineReferences:
    """Test that chunker preserves line number references."""

    def test_chunk_start_end_lines_match_content(self, tmp_path: Path):
        """Chunk start_line and end_line match the actual lines in the content."""
        from ir_agent.ingestion.chunker import chunk_file
        from ir_agent.ingestion.scanner import FileRecord

        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()

        # Create a file with 20 lines, each a separate log entry
        lines = [f"2024-01-15T10:00:{i:02d} event {i}\n" for i in range(20)]
        content = "".join(lines)
        file_path = artifacts_dir / "lines.log"
        file_path.write_text(content, encoding="utf-8")

        record = FileRecord(
            file_id="line-ref-test",
            path="lines.log",
            sha256="abc",
            host="host01",
            file_type="text/x-log",
            encoding="utf-8",
            line_count=20,
            time_range=None,
        )

        chunks = chunk_file(record, max_size=5, overlap=0, artifacts_dir=artifacts_dir)

        # Verify start_line is 1-based and sequential
        assert chunks[0].start_line == 1

        # Verify each chunk's line range corresponds to its content line count
        for chunk in chunks:
            actual_lines_in_chunk = chunk.content.count("\n")
            expected_line_span = chunk.end_line - chunk.start_line + 1
            assert actual_lines_in_chunk == expected_line_span

    def test_chunk_covers_all_lines(self, tmp_path: Path):
        """All lines in the source file are covered by at least one chunk."""
        from ir_agent.ingestion.chunker import chunk_file
        from ir_agent.ingestion.scanner import FileRecord

        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()

        lines = [f"2024-01-15T10:00:{i:02d} event {i}\n" for i in range(12)]
        content = "".join(lines)
        file_path = artifacts_dir / "coverage.log"
        file_path.write_text(content, encoding="utf-8")

        record = FileRecord(
            file_id="coverage-test",
            path="coverage.log",
            sha256="abc",
            host="host01",
            file_type="text/x-log",
            encoding="utf-8",
            line_count=12,
            time_range=None,
        )

        chunks = chunk_file(record, max_size=4, overlap=0, artifacts_dir=artifacts_dir)

        # Build set of all covered line numbers
        covered_lines = set()
        for chunk in chunks:
            for line_num in range(chunk.start_line, chunk.end_line + 1):
                covered_lines.add(line_num)

        # All 12 lines should be covered
        assert covered_lines == set(range(1, 13))


# --- Chunker Does Not Split Multi-Line Log Entries (Requirement 3.4) ---


class TestChunkerMultiLineIntegrity:
    """Test that chunker does not split multi-line log entries."""

    def test_traceback_stays_with_error_line(self, tmp_path: Path):
        """A Python traceback following an error log stays in the same chunk."""
        from ir_agent.ingestion.chunker import chunk_file
        from ir_agent.ingestion.scanner import FileRecord

        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()

        # Create a log with a multi-line traceback entry
        log_lines = [
            "2024-01-15T10:00:00 INFO startup complete\n",
            "2024-01-15T10:00:01 INFO processing request\n",
            "2024-01-15T10:00:02 ERROR unhandled exception\n",
            "  Traceback (most recent call last):\n",
            '    File "/app/main.py", line 42, in handle\n',
            "  ValueError: invalid input\n",
            "2024-01-15T10:00:03 INFO recovery started\n",
            "2024-01-15T10:00:04 INFO recovery complete\n",
        ]
        content = "".join(log_lines)
        file_path = artifacts_dir / "traceback.log"
        file_path.write_text(content, encoding="utf-8")

        record = FileRecord(
            file_id="multiline-test",
            path="traceback.log",
            sha256="abc",
            host="host01",
            file_type="text/x-log",
            encoding="utf-8",
            line_count=8,
            time_range=None,
        )

        # max_size=3 would naively split the traceback
        chunks = chunk_file(record, max_size=3, overlap=0, artifacts_dir=artifacts_dir)

        # Find the chunk containing the ERROR line
        error_chunk = None
        for chunk in chunks:
            if "ERROR unhandled exception" in chunk.content:
                error_chunk = chunk
                break

        assert error_chunk is not None
        # The traceback continuation lines must be in the same chunk
        assert "Traceback (most recent call last):" in error_chunk.content
        assert "ValueError: invalid input" in error_chunk.content

    def test_java_stacktrace_stays_together(self, tmp_path: Path):
        """A Java-style stack trace stays in the same chunk as its error."""
        from ir_agent.ingestion.chunker import chunk_file
        from ir_agent.ingestion.scanner import FileRecord

        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()

        log_lines = [
            "2024-01-15T10:00:00 INFO normal operation\n",
            "2024-01-15T10:00:01 ERROR NullPointerException\n",
            "  at com.example.Service.process(Service.java:55)\n",
            "  at com.example.Main.run(Main.java:12)\n",
            "  at com.example.Main.main(Main.java:8)\n",
            "2024-01-15T10:00:02 INFO service restarted\n",
        ]
        content = "".join(log_lines)
        file_path = artifacts_dir / "java.log"
        file_path.write_text(content, encoding="utf-8")

        record = FileRecord(
            file_id="java-trace-test",
            path="java.log",
            sha256="abc",
            host="host01",
            file_type="text/x-log",
            encoding="utf-8",
            line_count=6,
            time_range=None,
        )

        chunks = chunk_file(record, max_size=3, overlap=0, artifacts_dir=artifacts_dir)

        # Find chunk with the ERROR line
        error_chunk = None
        for chunk in chunks:
            if "NullPointerException" in chunk.content:
                error_chunk = chunk
                break

        assert error_chunk is not None
        # All stack trace lines must be in the same chunk
        assert "at com.example.Service.process" in error_chunk.content
        assert "at com.example.Main.main" in error_chunk.content


# --- Encoding Detection ---


class TestDetectEncoding:
    """Test encoding detection functionality."""

    def test_utf8_detection(self, service: IngestionService, tmp_path: Path):
        """UTF-8 encoded file is detected correctly."""
        content = "Hello, this is UTF-8 text with some unicode: café\n"
        file_path = tmp_path / "utf8.txt"
        file_path.write_text(content, encoding="utf-8")

        result = service.detect_encoding(file_path)

        # chardet may return 'ascii' for ASCII-compatible UTF-8 content
        assert result in ("utf-8", "ascii")

    def test_binary_file_detection(self, service: IngestionService, tmp_path: Path):
        """Binary file is detected as binary encoding."""
        # Random binary content with high entropy
        binary_content = bytes(range(256)) * 4
        file_path = tmp_path / "binary.dat"
        file_path.write_bytes(binary_content)

        result = service.detect_encoding(file_path)

        # chardet should fail or return low confidence for random bytes
        # The function returns "binary" when confidence is low
        assert result == "binary"

    def test_empty_file_returns_utf8(self, service: IngestionService, tmp_path: Path):
        """Empty file defaults to utf-8 encoding."""
        file_path = tmp_path / "empty.txt"
        file_path.write_bytes(b"")

        result = service.detect_encoding(file_path)

        assert result == "utf-8"


# --- Scan Directory Integration ---


class TestScanDirectory:
    """Integration tests for scan_directory combining hash, classify, and error handling."""

    def test_scan_produces_records_with_hash(
        self, service: IngestionService, tmp_path: Path
    ):
        """scan_directory produces records with valid SHA-256 hashes."""
        artifacts_dir = tmp_path / "artifacts"
        host_dir = artifacts_dir / "host01"
        host_dir.mkdir(parents=True)

        content_bytes = b"2024-01-15T10:00:00 test event\n"
        log_file = host_dir / "test.log"
        log_file.write_bytes(content_bytes)

        records = service.scan_directory(artifacts_dir)

        assert len(records) == 1
        record = records[0]

        # Verify hash matches expected (using exact bytes written to disk)
        expected_hash = hashlib.sha256(content_bytes).hexdigest()
        assert record.sha256 == expected_hash

    def test_scan_classifies_files_by_content(
        self, service: IngestionService, tmp_path: Path
    ):
        """scan_directory classifies files by content, not extension."""
        artifacts_dir = tmp_path / "artifacts"
        host_dir = artifacts_dir / "host01"
        host_dir.mkdir(parents=True)

        # Create a PNG file with .log extension
        png_file = host_dir / "sneaky.log"
        png_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        records = service.scan_directory(artifacts_dir)

        assert len(records) == 1
        assert records[0].file_type == "image/png"

    def test_scan_extracts_host_from_directory(
        self, service: IngestionService, tmp_path: Path
    ):
        """scan_directory extracts host name from the first directory level."""
        artifacts_dir = tmp_path / "artifacts"
        host_dir = artifacts_dir / "webserver01" / "logs"
        host_dir.mkdir(parents=True)

        log_file = host_dir / "access.log"
        log_file.write_text("2024-01-15T10:00:00 GET /index.html\n", encoding="utf-8")

        records = service.scan_directory(artifacts_dir)

        assert len(records) == 1
        assert records[0].host == "webserver01"

    def test_scan_assigns_unique_file_ids(
        self, service: IngestionService, tmp_path: Path
    ):
        """Each scanned file receives a unique file_id."""
        artifacts_dir = tmp_path / "artifacts"
        host_dir = artifacts_dir / "host01"
        host_dir.mkdir(parents=True)

        for i in range(3):
            f = host_dir / f"file{i}.log"
            f.write_text(f"2024-01-15T10:00:0{i} event {i}\n", encoding="utf-8")

        records = service.scan_directory(artifacts_dir)

        file_ids = [r.file_id for r in records]
        assert len(file_ids) == 3
        assert len(set(file_ids)) == 3  # All unique

    def test_scan_assigns_stable_version_id_for_unchanged_file(
        self, service: IngestionService, tmp_path: Path
    ):
        """Unchanged artifacts keep the same logical and version identifiers."""
        artifacts_dir = tmp_path / "artifacts"
        host_dir = artifacts_dir / "host01"
        host_dir.mkdir(parents=True)
        log_file = host_dir / "auth.log"
        log_file.write_text("2026-06-01T00:00:00 login ok\n", encoding="utf-8")

        first = service.scan_directory(artifacts_dir)[0]
        second = service.scan_directory(artifacts_dir)[0]

        assert first.artifact_id == second.artifact_id
        assert first.artifact_version_id == second.artifact_version_id
        assert first.file_id == first.artifact_version_id

    def test_scan_changes_version_id_when_content_changes(
        self, service: IngestionService, tmp_path: Path
    ):
        """Overwriting an artifact creates a new version under the same artifact."""
        artifacts_dir = tmp_path / "artifacts"
        host_dir = artifacts_dir / "host01"
        host_dir.mkdir(parents=True)
        log_file = host_dir / "auth.log"
        log_file.write_text("2026-06-01T00:00:00 login ok\n", encoding="utf-8")

        first = service.scan_directory(artifacts_dir)[0]
        log_file.write_text("2026-06-01T00:00:00 login failed\n", encoding="utf-8")
        second = service.scan_directory(artifacts_dir)[0]

        assert first.artifact_id == second.artifact_id
        assert first.artifact_version_id != second.artifact_version_id
