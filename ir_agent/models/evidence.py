"""Evidence data models for the IR Reporting Support Agent.

Defines EvidenceCandidate, EvidenceLedgerEntry, IOCRecord, and
EntityResolutionEntry models for the evidence lifecycle.
"""

from typing import Optional

from pydantic import BaseModel, Field

from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.events import ATTCKMapping


class EvidenceCandidate(BaseModel):
    """A potential evidence item extracted from raw artifacts.

    Evidence candidates have not yet received human approval and must
    be reviewed before promotion to the Evidence Ledger. Supports
    multi-source references for corroborating evidence.
    """

    candidate_id: str
    source_refs: list[SourceReference] = Field(
        description="Multiple source references supporting this candidate"
    )
    observed_event: dict
    observed_fact: str = Field(
        description="What the data objectively shows (strictly separated from interpretation)"
    )
    interpretation: str = Field(
        description="What the observed data might mean (analyst interpretation)"
    )
    observed_fact_confidence: ConfidenceLevel
    interpretation_confidence: ConfidenceLevel
    attack_mapping_candidates: list[ATTCKMapping] = Field(default_factory=list)
    from_normalized_event_ids: list[str] = Field(default_factory=list)
    candidate_status: str = "candidate"
    review_status: str = "pending"


class EvidenceLedgerEntry(BaseModel):
    """An approved evidence item in the Evidence Ledger.

    Only entries in the ledger can be used to support report claims.
    Stores observed_fact_confidence and interpretation_confidence separately
    because an observed fact may be confirmed while its interpretation
    remains possible or probable.
    """

    evidence_id: str
    promoted_from: list[str] = Field(
        description="candidate_ids this entry was promoted from (supports merged evidence)"
    )
    approval_timestamp: str
    approved_by: str
    source_refs: list[SourceReference]
    observed_event: dict
    observed_fact: str
    interpretation: str
    observed_fact_confidence: ConfidenceLevel
    interpretation_confidence: ConfidenceLevel
    attack_mapping_candidates: list[ATTCKMapping] = Field(default_factory=list)
    withdrawn: bool = False
    withdrawn_at: Optional[str] = None
    withdrawn_by: Optional[str] = None
    withdrawal_reason: Optional[str] = None
    replacement_evidence_id: Optional[str] = None
    supersedes: Optional[str] = None


class IOCRecord(BaseModel):
    """An Indicator of Compromise extracted from artifacts.

    IOCs include IP addresses, domains, hashes, file paths, URLs,
    and email addresses that indicate potential malicious activity.
    """

    ioc_id: str
    ioc_type: str = Field(
        description=(
            "Type of IOC: ip, domain, hash_md5, hash_sha1, "
            "hash_sha256, file_path, url, email"
        )
    )
    value: str
    source_file_id: str
    source_line: int


class EntityResolutionEntry(BaseModel):
    """A mapping between observed values and canonical entity identifiers.

    Used to resolve different representations of the same entity
    (e.g., hostname variations, IP aliases) to a single canonical ID.
    """

    canonical_entity_id: str
    observed_value: str
    source_file_id: str
    source_lines: tuple[int, int]
    resolution_confidence: float = Field(ge=0.0, le=1.0)
    resolution_reason: str
    review_status: str = Field(
        description="Status: pending, approved, rejected"
    )
