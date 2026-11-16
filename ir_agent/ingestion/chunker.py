"""Text Chunker for the Ingestion Layer.

Splits ingested artifact files into sequential chunks while preserving
line number references and avoiding splits within multi-line log entries.

Requirements: 3.1, 3.2, 3.3, 3.4
"""

import logging
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ir_agent.ingestion.scanner import FileRecord

logger = logging.getLogger(__name__)

# Patterns that indicate the start of a new log entry.
# A line matching any of these is considered the beginning of a log entry;
# subsequent lines that do NOT match are continuation lines of the same entry.
_LOG_ENTRY_START_PATTERNS: list[re.Pattern[str]] = [
    # ISO 8601 timestamp at line start: 2024-01-15T10:30:00 or 2024-01-15 10:30:00
    re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"),
    # Syslog timestamp: Jan 15 10:30:00
    re.compile(
        r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    ),
    # Windows event log XML element start
    re.compile(r"^\s*<Event\s"),
    # Common log format timestamp: 15/Jan/2024:10:30:00
    re.compile(
        r"^\d{1,2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}"
    ),
    # Bracket-enclosed timestamp: [2024-01-15 10:30:00]
    re.compile(r"^\[\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"),
    # Unix epoch in brackets or at start: [1705312200] or 1705312200
    re.compile(r"^[\[]?1[6-9]\d{8}[\]]?"),
    # Windows event date format: MM/DD/YYYY HH:MM:SS
    re.compile(r"^\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}"),
]


@dataclass
class Chunk:
    """A text chunk extracted from a source artifact file.

    Attributes:
        chunk_id: Unique identifier for this chunk (uuid4).
        source_file_id: The file_id of the source FileRecord.
        chunk_index: Zero-based index of this chunk within the file.
        start_line: First line number (1-based) included in this chunk.
        end_line: Last line number (1-based) included in this chunk.
        content: The text content of the chunk.
    """

    chunk_id: str
    source_file_id: str
    chunk_index: int
    start_line: int
    end_line: int
    content: str


def _make_chunk_id(
    file_record: FileRecord,
    chunk_index: int,
    start_line: int,
    end_line: int,
    content: str,
) -> str:
    """Create a deterministic chunk ID for an artifact version and line span."""
    version_id = file_record.artifact_version_id or file_record.file_id
    seed = f"{version_id}:{chunk_index}:{start_line}:{end_line}:{content}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def _is_log_entry_start(line: str) -> bool:
    """Check if a line marks the beginning of a new log entry.

    A line that matches any known timestamp/log-start pattern is considered
    the start of a new entry. Lines that don't match are continuation lines
    belonging to the preceding entry.

    Args:
        line: A single line of text from the file.

    Returns:
        True if the line starts a new log entry, False otherwise.
    """
    for pattern in _LOG_ENTRY_START_PATTERNS:
        if pattern.search(line):
            return True
    return False


def _group_into_log_entries(lines: list[str]) -> list[tuple[int, int]]:
    """Group lines into logical log entries, respecting multi-line entries.

    Each entry is represented as a (start_index, end_index) tuple where
    indices are 0-based positions in the lines list. The end_index is
    inclusive.

    Args:
        lines: List of all lines in the file.

    Returns:
        List of (start_index, end_index) tuples representing log entries.
    """
    if not lines:
        return []

    entries: list[tuple[int, int]] = []
    current_start = 0

    for i in range(1, len(lines)):
        if _is_log_entry_start(lines[i]):
            entries.append((current_start, i - 1))
            current_start = i

    # Add the final entry
    entries.append((current_start, len(lines) - 1))

    return entries


def chunk_file(
    file_record: FileRecord,
    max_size: int = 3000,
    overlap: int = 50,
    artifacts_dir: Optional[Path] = None,
) -> list[Chunk]:
    """Split a file into sequential chunks preserving log entry boundaries.

    Reads the file using the encoding from the FileRecord, groups lines into
    logical log entries (multi-line entries stay together), and creates chunks
    that respect the max_size limit while keeping entries intact.

    Args:
        file_record: The FileRecord describing the file to chunk.
        max_size: Maximum number of lines per chunk.
        overlap: Number of lines to overlap between consecutive chunks.
        artifacts_dir: Base directory to resolve relative file paths.
            If None, file_record.path is treated as an absolute path.

    Returns:
        List of Chunk objects representing the file's content split into
        sequential segments with metadata.

    Raises:
        FileNotFoundError: If the resolved file path does not exist.
        UnicodeDecodeError: If the file cannot be decoded with the specified encoding.
    """
    # Resolve the file path
    if artifacts_dir is not None:
        file_path = artifacts_dir / file_record.path
    else:
        file_path = Path(file_record.path)

    # Skip binary files
    if file_record.encoding == "binary":
        logger.warning(
            "Skipping binary file for chunking: %s", file_record.path
        )
        return []

    # Read file content using detected encoding
    try:
        with open(file_path, "r", encoding=file_record.encoding, errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        logger.error("File not found for chunking: %s", file_path)
        raise
    except OSError as exc:
        logger.error("Cannot read file for chunking: %s - %s", file_path, exc)
        return []

    if not lines:
        return []

    # If the file fits within a single chunk, return it as one chunk
    if len(lines) <= max_size:
        content = "".join(lines)
        return [
            Chunk(
                chunk_id=_make_chunk_id(
                    file_record=file_record,
                    chunk_index=0,
                    start_line=1,
                    end_line=len(lines),
                    content=content,
                ),
                source_file_id=file_record.file_id,
                chunk_index=0,
                start_line=1,
                end_line=len(lines),
                content=content,
            )
        ]

    # Group lines into logical log entries to avoid splitting multi-line entries
    entries = _group_into_log_entries(lines)

    # Build chunks from entries respecting max_size
    chunks: list[Chunk] = []
    chunk_index = 0
    entry_idx = 0

    while entry_idx < len(entries):
        chunk_lines: list[str] = []
        chunk_start_line: Optional[int] = None
        chunk_end_line = 0
        first_entry_in_chunk = entry_idx

        while entry_idx < len(entries):
            entry_start, entry_end = entries[entry_idx]
            entry_line_count = entry_end - entry_start + 1

            # If adding this entry would exceed max_size and we already have
            # content, stop here (unless this is the first entry in the chunk,
            # in which case we must include it to make progress)
            if chunk_lines and (len(chunk_lines) + entry_line_count > max_size):
                break

            # Add this entry's lines to the chunk
            for line_idx in range(entry_start, entry_end + 1):
                chunk_lines.append(lines[line_idx])

            if chunk_start_line is None:
                chunk_start_line = entry_start + 1  # 1-based

            chunk_end_line = entry_end + 1  # 1-based
            entry_idx += 1

        # Create the chunk
        content = "".join(chunk_lines)
        chunks.append(
            Chunk(
                chunk_id=_make_chunk_id(
                    file_record=file_record,
                    chunk_index=chunk_index,
                    start_line=chunk_start_line if chunk_start_line is not None else 1,
                    end_line=chunk_end_line,
                    content=content,
                ),
                source_file_id=file_record.file_id,
                chunk_index=chunk_index,
                start_line=chunk_start_line if chunk_start_line is not None else 1,
                end_line=chunk_end_line,
                content=content,
            )
        )
        chunk_index += 1

        # Apply overlap: move back by overlap lines worth of entries
        if entry_idx < len(entries) and overlap > 0:
            # Calculate how many entries to go back to cover ~overlap lines
            overlap_lines_remaining = overlap
            rewind_idx = entry_idx - 1

            while rewind_idx > first_entry_in_chunk and overlap_lines_remaining > 0:
                e_start, e_end = entries[rewind_idx]
                entry_lines = e_end - e_start + 1
                overlap_lines_remaining -= entry_lines
                if overlap_lines_remaining >= 0:
                    rewind_idx -= 1
                else:
                    break

            # Start next chunk from the overlap position
            # But ensure we move forward at least one entry to avoid infinite loops
            if rewind_idx < entry_idx - 1:
                entry_idx = rewind_idx + 1

    return chunks
