"""Unit tests for write_inventory function.

Validates Requirement 2.7:
- THE Ingestion_Layer SHALL produce a File_Inventory in JSON format containing
  file_id, path, sha256, host, file_type, encoding, line_count, and time_range
  for each ingested file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ir_agent.ingestion.scanner import (
    FileRecord,
    FileRecordModel,
    IngestionService,
    TimeRangeModel,
)
from ir_agent.models.base import TimeRange


# --- Fixtures ---


@pytest.fixture
def service() -> IngestionService:
    return IngestionService()


@pytest.fixture
def sample_records() -> list[FileRecord]:
    """Create sample FileRecord instances for testing."""
    return [
        FileRecord(
            file_id="file-001",
            path="host01/logs/syslog.log",
            sha256="abc123def456" * 5 + "ab",
            host="host01",
            file_type="text/x-syslog",
            encoding="utf-8",
            line_count=1500,
            time_range=TimeRange(
                start="2024-01-15T00:00:00Z",
                end="2024-01-15T23:59:59Z",
            ),
        ),
        FileRecord(
            file_id="file-002",
            path="host02/images/screenshot.png",
            sha256="def789ghi012" * 5 + "de",
            host="host02",
            file_type="image/png",
            encoding="binary",
            line_count=0,
            time_range=None,
        ),
        FileRecord(
            file_id="file-003",
            path="host01/logs/auth.log",
            sha256="111222333444" * 5 + "11",
            host="host01",
            file_type="text/x-log",
            encoding="utf-8",
            line_count=340,
            time_range=TimeRange(
                start="2024-01-10T08:00:00+09:00",
                end="2024-01-12T17:30:00+09:00",
            ),
        ),
    ]


# --- FileRecordModel Tests ---


class TestFileRecordModel:
    def test_from_file_record_with_time_range(self):
        """FileRecordModel correctly converts a FileRecord with time_range."""
        record = FileRecord(
            file_id="f1",
            path="host/file.log",
            sha256="a" * 64,
            host="host",
            file_type="text/x-log",
            encoding="utf-8",
            line_count=100,
            time_range=TimeRange(start="2024-01-01T00:00:00Z", end="2024-01-02T00:00:00Z"),
        )

        model = FileRecordModel.from_file_record(record)

        assert model.file_id == "f1"
        assert model.path == "host/file.log"
        assert model.sha256 == "a" * 64
        assert model.host == "host"
        assert model.file_type == "text/x-log"
        assert model.encoding == "utf-8"
        assert model.line_count == 100
        assert model.time_range is not None
        assert model.time_range.start == "2024-01-01T00:00:00Z"
        assert model.time_range.end == "2024-01-02T00:00:00Z"

    def test_from_file_record_without_time_range(self):
        """FileRecordModel correctly converts a FileRecord with None time_range."""
        record = FileRecord(
            file_id="f2",
            path="host/binary.exe",
            sha256="b" * 64,
            host="host",
            file_type="application/x-dosexec",
            encoding="binary",
            line_count=0,
            time_range=None,
        )

        model = FileRecordModel.from_file_record(record)

        assert model.time_range is None

    def test_model_dump_produces_valid_json_structure(self):
        """model_dump produces a dict suitable for JSON serialization."""
        record = FileRecord(
            file_id="f1",
            path="host/file.log",
            sha256="c" * 64,
            host="host",
            file_type="text/plain",
            encoding="utf-8",
            line_count=50,
            time_range=TimeRange(start="2024-03-01T10:00:00Z", end="2024-03-01T12:00:00Z"),
        )

        model = FileRecordModel.from_file_record(record)
        data = model.model_dump(mode="json")

        assert isinstance(data, dict)
        assert {
            "file_id", "path", "sha256", "host",
            "file_type", "encoding", "line_count", "time_range",
        }.issubset(data.keys())
        assert {
            "artifact_id",
            "artifact_version_id",
            "metadata_sha256",
            "change_status",
        }.issubset(data.keys())
        assert data["time_range"] == {
            "start": "2024-03-01T10:00:00Z",
            "end": "2024-03-01T12:00:00Z",
        }


# --- write_inventory Tests ---


class TestWriteInventory:
    def test_writes_json_file(
        self, service: IngestionService, sample_records: list[FileRecord], tmp_path: Path
    ):
        """write_inventory creates a JSON file at the output path."""
        output = tmp_path / "file_inventory.json"
        service.write_inventory(sample_records, output)
        assert output.exists()

    def test_output_is_valid_json(
        self, service: IngestionService, sample_records: list[FileRecord], tmp_path: Path
    ):
        """The output file contains valid JSON."""
        output = tmp_path / "file_inventory.json"
        service.write_inventory(sample_records, output)

        content = output.read_text(encoding="utf-8")
        data = json.loads(content)
        assert isinstance(data, list)

    def test_contains_all_records(
        self, service: IngestionService, sample_records: list[FileRecord], tmp_path: Path
    ):
        """The output contains one entry per input FileRecord."""
        output = tmp_path / "file_inventory.json"
        service.write_inventory(sample_records, output)

        data = json.loads(output.read_text(encoding="utf-8"))
        assert len(data) == len(sample_records)

    def test_includes_all_required_fields(
        self, service: IngestionService, sample_records: list[FileRecord], tmp_path: Path
    ):
        """Each entry contains all FileRecord fields."""
        output = tmp_path / "file_inventory.json"
        service.write_inventory(sample_records, output)

        data = json.loads(output.read_text(encoding="utf-8"))
        required_fields = {
            "file_id", "path", "sha256", "host",
            "file_type", "encoding", "line_count", "time_range",
        }

        for entry in data:
            assert required_fields.issubset(entry.keys())
            assert "artifact_id" in entry
            assert "artifact_version_id" in entry
            assert "change_status" in entry

    def test_time_range_serialization(
        self, service: IngestionService, sample_records: list[FileRecord], tmp_path: Path
    ):
        """TimeRange is correctly serialized as a dict with start/end."""
        output = tmp_path / "file_inventory.json"
        service.write_inventory(sample_records, output)

        data = json.loads(output.read_text(encoding="utf-8"))

        # First record has a time_range
        assert data[0]["time_range"] == {
            "start": "2024-01-15T00:00:00Z",
            "end": "2024-01-15T23:59:59Z",
        }

        # Second record has None time_range
        assert data[1]["time_range"] is None

    def test_field_values_match_input(
        self, service: IngestionService, sample_records: list[FileRecord], tmp_path: Path
    ):
        """Output field values match the input FileRecord values."""
        output = tmp_path / "file_inventory.json"
        service.write_inventory(sample_records, output)

        data = json.loads(output.read_text(encoding="utf-8"))

        first = data[0]
        assert first["file_id"] == "file-001"
        assert first["path"] == "host01/logs/syslog.log"
        assert first["host"] == "host01"
        assert first["file_type"] == "text/x-syslog"
        assert first["encoding"] == "utf-8"
        assert first["line_count"] == 1500

    def test_empty_records_list(
        self, service: IngestionService, tmp_path: Path
    ):
        """write_inventory handles an empty list of records."""
        output = tmp_path / "file_inventory.json"
        service.write_inventory([], output)

        data = json.loads(output.read_text(encoding="utf-8"))
        assert data == []

    def test_creates_parent_directories(
        self, service: IngestionService, sample_records: list[FileRecord], tmp_path: Path
    ):
        """write_inventory creates parent directories if they don't exist."""
        output = tmp_path / "nested" / "dir" / "file_inventory.json"
        service.write_inventory(sample_records, output)
        assert output.exists()

    def test_utf8_encoding(
        self, service: IngestionService, tmp_path: Path
    ):
        """Output file is written in UTF-8 encoding (supports non-ASCII paths)."""
        records = [
            FileRecord(
                file_id="f-jp",
                path="host01/ログ/認証.log",
                sha256="d" * 64,
                host="host01",
                file_type="text/x-log",
                encoding="shift_jis",
                line_count=200,
                time_range=None,
            ),
        ]

        output = tmp_path / "file_inventory.json"
        service.write_inventory(records, output)

        content = output.read_text(encoding="utf-8")
        data = json.loads(content)
        assert data[0]["path"] == "host01/ログ/認証.log"

    def test_roundtrip_pydantic_validation(
        self, service: IngestionService, sample_records: list[FileRecord], tmp_path: Path
    ):
        """Records written can be read back and validated through Pydantic."""
        output = tmp_path / "file_inventory.json"
        service.write_inventory(sample_records, output)

        data = json.loads(output.read_text(encoding="utf-8"))
        for entry in data:
            # Should not raise ValidationError
            model = FileRecordModel(**entry)
            assert model.file_id is not None
