"""File Scanner and Hasher for the Ingestion Layer.

Provides the IngestionService class responsible for:
- Recursively scanning artifact directories
- Computing SHA-256 hashes for integrity verification
- Classifying file types using content-based detection (magic bytes / content patterns)
- Detecting file encoding using chardet
- Counting lines in files
- Extracting time ranges from file content
- Assigning unique file_id per artifact
- Writing file inventory JSON with Pydantic validation

Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9
"""

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import chardet
import yaml
from pydantic import BaseModel, Field

from ir_agent.models.base import TimeRange

logger = logging.getLogger(__name__)


@dataclass
class FileRecord:
    """Metadata record for a single ingested artifact file.

    Attributes:
        file_id: Unique identifier for this artifact.
        path: Relative path of the file within the artifacts directory.
        sha256: SHA-256 hash of the file content.
        host: Host name extracted from the directory structure (top-level folder).
        file_type: Content-based file type classification.
        encoding: Detected character encoding.
        line_count: Total number of lines in the file.
        time_range: Optional time range of timestamps found in the file.
    """

    file_id: str
    path: str
    sha256: str
    host: str
    file_type: str
    encoding: str
    line_count: int
    time_range: Optional[TimeRange]
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    metadata_sha256: str = ""
    artifact_id: str = ""
    artifact_version_id: str = ""
    ingest_run_id: str = ""
    change_status: str = "new"
    previous_artifact_version_id: Optional[str] = None


class TimeRangeModel(BaseModel):
    """Pydantic model for TimeRange serialization at the JSON boundary."""

    start: str = Field(description="ISO 8601 start timestamp")
    end: str = Field(description="ISO 8601 end timestamp")


class FileRecordModel(BaseModel):
    """Pydantic model for FileRecord serialization/validation at the JSON boundary.

    Used to validate and serialize FileRecord dataclass instances to JSON
    when writing the file_inventory.json output.
    """

    file_id: str
    path: str
    sha256: str
    host: str
    file_type: str
    encoding: str
    line_count: int
    time_range: Optional[TimeRangeModel] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    metadata_sha256: str = ""
    artifact_id: str = ""
    artifact_version_id: str = ""
    ingest_run_id: str = ""
    change_status: str = "new"
    previous_artifact_version_id: Optional[str] = None

    @classmethod
    def from_file_record(cls, record: FileRecord) -> "FileRecordModel":
        """Create a FileRecordModel from a FileRecord dataclass instance.

        Args:
            record: A FileRecord dataclass instance.

        Returns:
            A validated FileRecordModel instance.
        """
        time_range_model = None
        if record.time_range is not None:
            time_range_model = TimeRangeModel(
                start=record.time_range.start,
                end=record.time_range.end,
            )

        return cls(
            file_id=record.file_id,
            path=record.path,
            sha256=record.sha256,
            host=record.host,
            file_type=record.file_type,
            encoding=record.encoding,
            line_count=record.line_count,
            time_range=time_range_model,
            metadata=record.metadata,
            metadata_sha256=record.metadata_sha256,
            artifact_id=record.artifact_id,
            artifact_version_id=record.artifact_version_id,
            ingest_run_id=record.ingest_run_id,
            change_status=record.change_status,
            previous_artifact_version_id=record.previous_artifact_version_id,
        )


@dataclass
class InventoryDiff:
    """Summary of artifact changes detected during an ingest run."""

    ingest_run_id: str
    new: list[str] = dataclass_field(default_factory=list)
    unchanged: list[str] = dataclass_field(default_factory=list)
    appended: list[str] = dataclass_field(default_factory=list)
    modified: list[str] = dataclass_field(default_factory=list)
    removed: list[str] = dataclass_field(default_factory=list)
    metadata_changed: list[str] = dataclass_field(default_factory=list)

    @property
    def changed_paths(self) -> list[str]:
        """Return paths whose evidence-bearing or contextual state changed."""
        return (
            self.new
            + self.appended
            + self.modified
            + self.removed
            + self.metadata_changed
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the diff for JSON reports and audit logs."""
        return {
            "ingest_run_id": self.ingest_run_id,
            "new": self.new,
            "unchanged": self.unchanged,
            "appended": self.appended,
            "modified": self.modified,
            "removed": self.removed,
            "metadata_changed": self.metadata_changed,
            "changed_count": len(self.changed_paths),
        }


# Magic bytes signatures for content-based file type detection
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"BZh", "application/x-bzip2"),
    (b"\x7fELF", "application/x-elf"),
    (b"MZ", "application/x-dosexec"),
    (b"%PDF", "application/pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    (b"SQLite format 3\x00", "application/x-sqlite3"),
]

# Optional sidecar metadata files. These files describe nearby artifacts and are
# not ingested as evidence-bearing raw artifacts themselves.
_ARTIFACT_METADATA_FILENAMES = {
    "artifact_metadata.json",
    "artifact_metadata.yaml",
    "artifact_metadata.yml",
}

# Content patterns for text-based file type detection
_TEXT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Windows Event Log XML format
    (re.compile(r"<Event\s+xmlns="), "text/x-windows-event-log"),
    # Syslog format: priority + timestamp
    (re.compile(r"^<\d+>"), "text/x-syslog"),
    # Standard syslog: Mon DD HH:MM:SS hostname
    (
        re.compile(
            r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+"
        ),
        "text/x-syslog",
    ),
    # CSV with header (comma-separated with at least 3 fields)
    (re.compile(r'^"?[\w\s]+"?,"?[\w\s]+"?,"?[\w\s]+"?'), "text/csv"),
    # JSON array or object
    (re.compile(r"^\s*[\[{]"), "application/json"),
    # JSONL (JSON lines)
    (re.compile(r'^{"[^"]+":'), "application/x-jsonl"),
    # YAML front matter or document
    (re.compile(r"^---\s*$", re.MULTILINE), "text/x-yaml"),
    # XML declaration
    (re.compile(r"^<\?xml"), "text/xml"),
    # HTML
    (re.compile(r"<!DOCTYPE html|<html", re.IGNORECASE), "text/html"),
    # Markdown heading
    (re.compile(r"^#{1,6}\s+\S"), "text/markdown"),
    # Python shebang or imports
    (re.compile(r"^#!/.*python|^import\s+\w+|^from\s+\w+"), "text/x-python"),
    # Shell script shebang
    (re.compile(r"^#!/.*(?:ba)?sh"), "text/x-shellscript"),
    # Generic log format: ISO timestamp at line start
    (
        re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"),
        "text/x-log",
    ),
]

# Timestamp patterns for time range extraction
_TIMESTAMP_PATTERNS: list[re.Pattern[str]] = [
    # ISO 8601: 2024-01-15T10:30:00Z or 2024-01-15T10:30:00+09:00
    re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
        r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    ),
    # Syslog: Jan 15 10:30:00
    re.compile(
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    ),
    # Common log format: 15/Jan/2024:10:30:00 +0900
    re.compile(
        r"\d{1,2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}"
    ),
    # Windows event log: MM/DD/YYYY HH:MM:SS
    re.compile(r"\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}"),
    # Unix epoch (10+ digits)
    re.compile(r"\b1[6-9]\d{8}\b"),
]


class IngestionService:
    """Service for scanning, classifying, and cataloguing artifact files.

    Recursively scans an artifacts directory and produces FileRecord objects
    with metadata including hash, file type, encoding, line count, and time range.
    Handles unreadable files gracefully by logging errors and continuing.
    """

    def scan_directory(self, artifacts_dir: Path) -> list[FileRecord]:
        """Recursively scan a directory and produce FileRecord for each file.

        Args:
            artifacts_dir: Path to the root artifacts directory.

        Returns:
            List of FileRecord objects for all successfully processed files.
        """
        records: list[FileRecord] = []

        if not artifacts_dir.exists():
            logger.error("Artifacts directory does not exist: %s", artifacts_dir)
            return records

        if not artifacts_dir.is_dir():
            logger.error("Artifacts path is not a directory: %s", artifacts_dir)
            return records

        metadata_index = self._load_artifact_metadata_index(artifacts_dir)

        for file_path in sorted(artifacts_dir.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path.name in _ARTIFACT_METADATA_FILENAMES:
                continue

            try:
                record = self._process_file(file_path, artifacts_dir, metadata_index)
                records.append(record)
            except Exception as exc:
                logger.error(
                    "Failed to process file %s: %s", file_path, exc
                )
                continue

        return records

    def create_ingest_run_id(self) -> str:
        """Create a stable-looking identifier for a single ingest execution."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"ingest-{timestamp}-{uuid.uuid4().hex[:8]}"

    def _process_file(
        self,
        file_path: Path,
        artifacts_dir: Path,
        metadata_index: dict[str, dict[str, Any]] | None = None,
    ) -> FileRecord:
        """Process a single file into a FileRecord.

        Args:
            file_path: Absolute path to the file.
            artifacts_dir: Root artifacts directory for relative path computation.

        Returns:
            A FileRecord with all metadata populated.
        """
        relative_path = str(file_path.relative_to(artifacts_dir))
        sha256 = self.compute_hash(file_path)
        host = self._extract_host(file_path, artifacts_dir)
        file_type = self.classify_file(file_path)
        encoding = self.detect_encoding(file_path)
        line_count = self.count_lines(file_path)
        time_range = self.extract_time_range(file_path, file_type)
        metadata = self._metadata_for_file(relative_path, metadata_index or {})
        metadata_sha256 = self._stable_json_hash(metadata)
        artifact_id = self.make_artifact_id(relative_path)
        artifact_version_id = self.make_artifact_version_id(
            artifact_id=artifact_id,
            content_sha256=sha256,
            metadata_sha256=metadata_sha256,
        )

        return FileRecord(
            file_id=artifact_version_id,
            path=relative_path,
            sha256=sha256,
            host=host,
            file_type=file_type,
            encoding=encoding,
            line_count=line_count,
            time_range=time_range,
            metadata=metadata,
            metadata_sha256=metadata_sha256,
            artifact_id=artifact_id,
            artifact_version_id=artifact_version_id,
        )

    def make_artifact_id(self, relative_path: str) -> str:
        """Return a stable logical artifact ID for a path under artifacts/."""
        normalized_path = Path(relative_path).as_posix()
        digest = hashlib.sha256(normalized_path.encode("utf-8")).hexdigest()[:24]
        return f"artifact-{digest}"

    def make_artifact_version_id(
        self, artifact_id: str, content_sha256: str, metadata_sha256: str
    ) -> str:
        """Return a stable version ID for a content + metadata snapshot."""
        seed = f"{artifact_id}:{content_sha256}:{metadata_sha256}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]
        return f"artifact-version-{digest}"

    def compute_hash(self, file_path: Path) -> str:
        """Compute the SHA-256 hash of a file's content.

        Args:
            file_path: Path to the file.

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()

    def classify_file(self, file_path: Path) -> str:
        """Classify file type using content-based detection (magic bytes / content patterns).

        Checks binary magic bytes first, then falls back to text content patterns.
        Does NOT rely on file extension alone.

        Args:
            file_path: Path to the file.

        Returns:
            MIME-like file type string (e.g., 'text/x-log', 'application/pdf').
        """
        # Read initial bytes for magic byte detection
        try:
            with open(file_path, "rb") as f:
                header = f.read(512)
        except OSError:
            return "application/octet-stream"

        if not header:
            return "application/octet-stream"

        # Check magic bytes
        for signature, file_type in _MAGIC_SIGNATURES:
            if header.startswith(signature):
                return file_type

        # Check if the content appears to be text
        # Heuristic: if a high proportion of bytes are non-text control chars, it's binary
        text_chars = set(range(7, 14)) | set(range(32, 127)) | {0x1B}  # ESC
        non_text = sum(1 for byte in header if byte not in text_chars and byte < 128)
        if non_text > len(header) * 0.3:
            return "application/octet-stream"

        # Try to decode as text for pattern matching
        try:
            text_sample = header.decode("utf-8", errors="replace")
        except Exception:
            return "application/octet-stream"

        # Check text content patterns
        for pattern, file_type in _TEXT_PATTERNS:
            if pattern.search(text_sample):
                return file_type

        return "text/plain"

    def detect_encoding(self, file_path: Path) -> str:
        """Detect the character encoding of a file using chardet.

        Reads a sample of the file (up to 64KB) for detection.

        Args:
            file_path: Path to the file.

        Returns:
            Detected encoding name (e.g., 'utf-8', 'shift_jis'), or 'binary'
            if the file appears to be non-text.
        """
        try:
            with open(file_path, "rb") as f:
                raw_data = f.read(65536)
        except OSError:
            return "binary"

        if not raw_data:
            return "utf-8"

        result = chardet.detect(raw_data)
        encoding = result.get("encoding")
        confidence = result.get("confidence", 0)

        if encoding is None or confidence < 0.5:
            return "binary"

        # Normalize encoding name
        return encoding.lower()

    def count_lines(self, file_path: Path) -> int:
        """Count the number of lines in a file using detected encoding.

        Falls back to binary reading with surrogate escaping if the encoding
        detection results in decode errors.

        Args:
            file_path: Path to the file.

        Returns:
            Total number of lines (0 for empty or binary files).
        """
        encoding = self.detect_encoding(file_path)

        if encoding == "binary":
            return 0

        try:
            with open(file_path, "r", encoding=encoding, errors="replace") as f:
                count = sum(1 for _ in f)
            return count
        except (OSError, UnicodeDecodeError):
            # Fallback: try reading as bytes and counting newlines
            try:
                with open(file_path, "rb") as f:
                    return sum(1 for _ in f)
            except OSError:
                return 0

    def extract_time_range(
        self, file_path: Path, file_type: str
    ) -> Optional[TimeRange]:
        """Extract the time range of timestamps found within a file.

        Scans the file content for recognizable timestamp patterns and returns
        the earliest and latest timestamps found.

        Args:
            file_path: Path to the file.
            file_type: The classified file type (used to skip binary files).

        Returns:
            TimeRange with start/end ISO 8601 strings, or None if no timestamps
            are found or the file is binary.
        """
        # Skip binary file types
        if not file_type.startswith("text/") and file_type not in (
            "application/json",
            "application/x-jsonl",
        ):
            return None

        encoding = self.detect_encoding(file_path)
        if encoding == "binary":
            return None

        timestamps: list[str] = []

        try:
            with open(file_path, "r", encoding=encoding, errors="replace") as f:
                for line in f:
                    for pattern in _TIMESTAMP_PATTERNS:
                        matches = pattern.findall(line)
                        timestamps.extend(matches)
        except OSError:
            return None

        if not timestamps:
            return None

        # Sort timestamps lexicographically (works for ISO 8601 format)
        # Filter to only ISO-like timestamps for reliable sorting
        iso_timestamps = [
            ts
            for ts in timestamps
            if re.match(r"\d{4}-\d{2}-\d{2}", ts)
        ]

        if iso_timestamps:
            sorted_ts = sorted(iso_timestamps)
            return TimeRange(start=sorted_ts[0], end=sorted_ts[-1])

        # For non-ISO timestamps, use first and last occurrence order
        if len(timestamps) >= 2:
            return TimeRange(start=timestamps[0], end=timestamps[-1])
        elif len(timestamps) == 1:
            return TimeRange(start=timestamps[0], end=timestamps[0])

        return None

    def write_inventory(self, records: list[FileRecord], output_path: Path) -> None:
        """Write file inventory as JSON using Pydantic validation/serialization.

        Converts FileRecord dataclass instances to Pydantic models for validation,
        then serializes to JSON and writes to the specified output path.

        Args:
            records: List of FileRecord dataclass instances to serialize.
            output_path: Path where file_inventory.json will be written.

        Raises:
            OSError: If the file cannot be written.
            ValidationError: If any FileRecord fails Pydantic validation.
        """
        # Validate and convert all records through Pydantic models
        validated_models = [
            FileRecordModel.from_file_record(record) for record in records
        ]

        # Serialize to JSON list
        inventory_data = [
            model.model_dump(mode="json") for model in validated_models
        ]

        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write JSON output
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(inventory_data, f, indent=2, ensure_ascii=False)

        logger.info(
            "Wrote file inventory with %d records to %s",
            len(records),
            output_path,
        )

    def load_inventory(self, inventory_path: Path) -> list[dict[str, Any]]:
        """Load a previous file inventory if it exists."""
        if not inventory_path.exists():
            return []
        try:
            data = json.loads(inventory_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("Failed to load previous inventory: %s", inventory_path)
            return []
        if not isinstance(data, list):
            return []
        return [entry for entry in data if isinstance(entry, dict)]

    def classify_inventory_changes(
        self,
        records: list[FileRecord],
        previous_inventory: list[dict[str, Any]],
        artifacts_dir: Path,
        previous_chunks_dir: Path,
        ingest_run_id: str,
    ) -> InventoryDiff:
        """Classify current artifacts against the previous inventory snapshot."""
        previous_by_path: dict[str, dict[str, Any]] = {}
        for entry in previous_inventory:
            path = entry.get("path")
            if isinstance(path, str):
                previous_by_path[path] = entry

        current_paths = {record.path for record in records}
        diff = InventoryDiff(ingest_run_id=ingest_run_id)

        for record in records:
            record.ingest_run_id = ingest_run_id
            previous = previous_by_path.get(record.path)
            if previous is None:
                record.change_status = "new"
                diff.new.append(record.path)
                continue

            previous_version = self._previous_artifact_version_id(previous)
            record.previous_artifact_version_id = previous_version

            if previous.get("sha256") == record.sha256:
                if previous.get("artifact_version_id") is None:
                    record.change_status = "metadata_changed"
                    diff.metadata_changed.append(record.path)
                    continue

                previous_metadata_hash = previous.get("metadata_sha256")
                if previous_metadata_hash is None:
                    previous_metadata_hash = self._stable_json_hash(
                        previous.get("metadata", {})
                    )
                if previous_metadata_hash == record.metadata_sha256:
                    record.change_status = "unchanged"
                    diff.unchanged.append(record.path)
                else:
                    record.change_status = "metadata_changed"
                    diff.metadata_changed.append(record.path)
                continue

            if self._looks_appended(record, previous, artifacts_dir, previous_chunks_dir):
                record.change_status = "appended"
                diff.appended.append(record.path)
            else:
                record.change_status = "modified"
                diff.modified.append(record.path)

        for path in sorted(set(previous_by_path) - current_paths):
            diff.removed.append(path)

        return diff

    def write_ingest_run_summary(
        self,
        diff: InventoryDiff,
        records: list[FileRecord],
        output_path: Path,
    ) -> None:
        """Append one ingest run summary to JSONL history."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        record_by_path = {record.path: record for record in records}
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **diff.to_dict(),
            "records": {
                path: {
                    "artifact_id": record.artifact_id,
                    "artifact_version_id": record.artifact_version_id,
                    "previous_artifact_version_id": record.previous_artifact_version_id,
                    "sha256": record.sha256,
                    "metadata_sha256": record.metadata_sha256,
                    "line_count": record.line_count,
                    "change_status": record.change_status,
                }
                for path, record in sorted(record_by_path.items())
            },
        }
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")

    def write_artifact_registry(
        self,
        records: list[FileRecord],
        previous_inventory: list[dict[str, Any]],
        removed_paths: list[str],
        output_path: Path,
    ) -> None:
        """Write the current artifact registry with previous removed entries retained."""
        artifacts: dict[str, dict[str, Any]] = {}
        previous_by_path = {
            entry.get("path"): entry
            for entry in previous_inventory
            if isinstance(entry.get("path"), str)
        }

        for record in records:
            artifacts[record.path] = {
                "artifact_id": record.artifact_id,
                "path": record.path,
                "host": record.host,
                "status": "active",
                "current_version_id": record.artifact_version_id,
                "previous_version_id": record.previous_artifact_version_id,
                "change_status": record.change_status,
                "sha256": record.sha256,
                "metadata_sha256": record.metadata_sha256,
                "line_count": record.line_count,
                "ingest_run_id": record.ingest_run_id,
            }

        for path in removed_paths:
            previous = previous_by_path.get(path, {})
            artifact_id = previous.get("artifact_id")
            if not artifact_id:
                artifact_id = self.make_artifact_id(path)
            artifacts[path] = {
                "artifact_id": artifact_id,
                "path": path,
                "host": previous.get("host", "unknown"),
                "status": "removed",
                "current_version_id": None,
                "previous_version_id": self._previous_artifact_version_id(previous),
                "change_status": "removed",
                "sha256": previous.get("sha256", ""),
                "metadata_sha256": previous.get("metadata_sha256", ""),
                "line_count": previous.get("line_count", 0),
                "ingest_run_id": None,
            }

        payload = {
            "schema_version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": artifacts,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _extract_host(self, file_path: Path, artifacts_dir: Path) -> str:
        """Extract the host name from the directory structure.

        Assumes the convention that the first directory level under artifacts_dir
        is the host name (e.g., artifacts/host01/logs/...).

        Args:
            file_path: Absolute path to the file.
            artifacts_dir: Root artifacts directory.

        Returns:
            Host name string, or 'unknown' if cannot be determined.
        """
        try:
            relative = file_path.relative_to(artifacts_dir)
            parts = relative.parts
            if len(parts) > 1:
                return parts[0]
            return "unknown"
        except ValueError:
            return "unknown"

    def _load_artifact_metadata_index(
        self, artifacts_dir: Path
    ) -> dict[str, dict[str, Any]]:
        """Load optional artifact metadata sidecars.

        Metadata files may be placed at any directory level under artifacts/.
        Keys other than ``files`` apply to every artifact below that directory.
        The optional ``files`` mapping can add per-file metadata using either a
        filename relative to the metadata file or a path relative to artifacts/.
        """
        index: dict[str, dict[str, Any]] = {}

        for metadata_path in sorted(artifacts_dir.rglob("*")):
            if metadata_path.name not in _ARTIFACT_METADATA_FILENAMES:
                continue
            if not metadata_path.is_file():
                continue

            try:
                metadata = self._read_artifact_metadata(metadata_path)
            except Exception as exc:
                logger.warning(
                    "Failed to read artifact metadata %s: %s",
                    metadata_path,
                    exc,
                )
                continue

            if not isinstance(metadata, dict):
                logger.warning("Artifact metadata must be a mapping: %s", metadata_path)
                continue

            metadata_dir = metadata_path.parent
            try:
                dir_key = metadata_dir.relative_to(artifacts_dir).as_posix()
            except ValueError:
                dir_key = "."
            if dir_key == ".":
                dir_key = ""

            directory_metadata = {
                key: value for key, value in metadata.items() if key != "files"
            }
            if directory_metadata:
                index[f"{dir_key}/"] = directory_metadata

            files_metadata = metadata.get("files", {})
            if isinstance(files_metadata, dict):
                for file_name, file_metadata in files_metadata.items():
                    if not isinstance(file_metadata, dict):
                        continue
                    relative_file = self._resolve_metadata_file_key(
                        str(file_name), dir_key
                    )
                    existing = index.get(relative_file, {})
                    index[relative_file] = {**existing, **file_metadata}

        return index

    def _read_artifact_metadata(self, metadata_path: Path) -> Any:
        """Read a JSON or YAML artifact metadata sidecar."""
        content = metadata_path.read_text(encoding="utf-8")
        if metadata_path.suffix.lower() == ".json":
            return json.loads(content)
        return yaml.safe_load(content)

    def _resolve_metadata_file_key(self, file_name: str, dir_key: str) -> str:
        """Resolve a metadata ``files`` key to an artifacts-relative path."""
        normalized = Path(file_name).as_posix()
        if "/" in normalized or not dir_key:
            return normalized
        return f"{dir_key}/{normalized}"

    def _metadata_for_file(
        self, relative_path: str, metadata_index: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """Return merged directory and per-file metadata for an artifact."""
        path = Path(relative_path)
        merged: dict[str, Any] = {}

        directory_parts = path.parent.parts
        for i in range(len(directory_parts) + 1):
            prefix = "/".join(directory_parts[:i])
            key = f"{prefix}/" if prefix else "/"
            if key in metadata_index:
                merged.update(metadata_index[key])

        if relative_path in metadata_index:
            merged.update(metadata_index[relative_path])

        return merged

    def _stable_json_hash(self, value: Any) -> str:
        """Hash JSON-compatible data with deterministic key ordering."""
        canonical = json.dumps(
            value if value is not None else {},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _previous_artifact_version_id(self, previous: dict[str, Any]) -> Optional[str]:
        """Read the previous version ID while tolerating older inventory files."""
        value = previous.get("artifact_version_id") or previous.get("file_id")
        return str(value) if value else None

    def _looks_appended(
        self,
        record: FileRecord,
        previous: dict[str, Any],
        artifacts_dir: Path,
        previous_chunks_dir: Path,
    ) -> bool:
        """Best-effort detection that a text artifact was appended in place."""
        previous_line_count = previous.get("line_count")
        if not isinstance(previous_line_count, int):
            return False
        if record.line_count < previous_line_count:
            return False
        if record.encoding == "binary":
            return False

        previous_file_id = self._previous_artifact_version_id(previous)
        if not previous_file_id:
            return False

        old_text = self._load_previous_text_from_chunks(
            previous_chunks_dir,
            previous_file_id,
        )
        if old_text is None:
            return False

        current_path = artifacts_dir / record.path
        try:
            current_text = current_path.read_text(
                encoding=record.encoding,
                errors="replace",
            )
        except OSError:
            return False

        return current_text.startswith(old_text) and current_text != old_text

    def _load_previous_text_from_chunks(
        self, chunks_dir: Path, previous_file_id: str
    ) -> Optional[str]:
        """Reconstruct previous text from generated chunk cache if available."""
        if not chunks_dir.exists():
            return None

        lines_by_number: dict[int, str] = {}
        chunk_files = sorted(chunks_dir.glob("*.json"))
        for chunk_path in chunk_files:
            try:
                chunk_data = json.loads(chunk_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if chunk_data.get("source_file_id") != previous_file_id:
                continue

            start_line = chunk_data.get("start_line")
            content = chunk_data.get("content", "")
            if not isinstance(start_line, int) or not isinstance(content, str):
                continue

            for offset, line in enumerate(content.splitlines(keepends=True)):
                lines_by_number.setdefault(start_line + offset, line)

        if not lines_by_number:
            return None

        return "".join(lines_by_number[line_no] for line_no in sorted(lines_by_number))
