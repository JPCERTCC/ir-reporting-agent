"""Base data models for the IR Reporting Support Agent.

Defines foundational models used across multiple layers:
SourceReference, EventTimestamp, and TimeRange.
"""

from typing import Optional

from pydantic import BaseModel, Field

from ir_agent.models.enums import ConfidenceLevel


class SourceReference(BaseModel):
    """A reference to a specific location in a source artifact.

    Every piece of evidence must trace back to source file, line numbers,
    and excerpts to maintain full traceability.
    """

    source_ref_id: str
    source_file_id: str
    source_path: str
    source_lines: tuple[int, int] = Field(
        description="Start and end line numbers (inclusive) in the source file"
    )
    excerpt: str
    excerpt_sha256: str
    parser_name: Optional[str] = None
    parser_version: Optional[str] = None
    source_artifact_id: Optional[str] = None
    source_artifact_version_id: Optional[str] = None
    source_ingest_run_id: Optional[str] = None


class EventTimestamp(BaseModel):
    """A timestamp extracted from evidence with normalization metadata.

    Tracks both the original value and the normalized UTC representation,
    along with confidence in the parsing accuracy.
    """

    original_value: str
    normalized_utc: Optional[str] = None
    timezone: Optional[str] = None
    timestamp_type: str = Field(
        description=(
            "Type of timestamp: event_time, collection_time, "
            "file_modified_time, analysis_time, report_time"
        )
    )
    confidence: ConfidenceLevel
    parsing_notes: Optional[str] = None


class TimeRange(BaseModel):
    """A time range with ISO 8601 start and end timestamps."""

    start: str = Field(description="ISO 8601 start timestamp")
    end: str = Field(description="ISO 8601 end timestamp")
