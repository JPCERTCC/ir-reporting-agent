"""Event data models for the IR Reporting Support Agent.

Defines NormalizedEvent and ATTCKMapping models used by the
extraction and analysis layers.
"""

from typing import Optional

from pydantic import BaseModel, Field

from ir_agent.models.base import EventTimestamp, SourceReference
from ir_agent.models.enums import ConfidenceLevel


class ATTCKMapping(BaseModel):
    """A mapping between observed behavior and MITRE ATT&CK framework.

    Links evidence to specific tactics and techniques with confidence
    and rationale for the mapping.
    """

    tactic: str
    technique_id: str
    technique_name: str
    confidence: ConfidenceLevel
    mapping_reason: str = ""
    supporting_evidence: list[str] = Field(
        default_factory=list,
        description=(
            "evidence_ids this mapping is grounded in when carried on a "
            "claim (empty on evidence-level mappings)"
        ),
    )


class NormalizedEvent(BaseModel):
    """A structured event extracted from raw artifacts using rule-based parsers.

    Normalized events are created before evidence candidates, ensuring
    the Agent does not rely solely on LLM interpretation of raw text.
    Preserves the link: Raw Artifact -> Normalized Event -> Evidence Candidate.
    """

    event_id: str
    source_refs: list[SourceReference]
    timestamps: list[EventTimestamp]
    host: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    file_path: Optional[str] = None
    event_type: str
    raw_excerpt: str = Field(
        description="The raw text excerpt from which this event was extracted"
    )
