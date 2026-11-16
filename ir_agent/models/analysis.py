"""Analysis data models for the IR Reporting Support Agent.

Defines TimelineEntry, Claim, Gap, InvestigationTask, and DataCoverageEntry
models used by the analysis layer for timeline construction, claim building,
gap detection, and data coverage tracking.
"""

from typing import Optional

from pydantic import BaseModel, Field

from ir_agent.models.base import TimeRange
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.events import ATTCKMapping


class TimelineEntry(BaseModel):
    """A single entry in the investigation timeline.

    Built from approved evidence in the ledger, representing
    a chronologically ordered event.
    """

    entry_id: str
    evidence_id: str
    event_time: str = Field(description="UTC ISO 8601 timestamp")
    original_timestamp: str
    display_timezone: str
    event_description: str
    host: Optional[str] = None
    confidence: ConfidenceLevel
    # Split confidence: the event occurrence (observed fact) is typically
    # confirmed, while its attack-attribution interpretation may be weaker.
    # Kept separate so a timeline reader does not mistake an uncertain
    # interpretation for an uncertain event. (UP-05)
    event_confidence: Optional[ConfidenceLevel] = None
    interpretation_confidence: Optional[ConfidenceLevel] = None
    timestamp_type: str = "event_time"
    # The excerpt line this time was read from, when the evidence spans
    # several timestamped lines: each line gets its own timeline row so the
    # report does not collapse them into one event.
    source_path: Optional[str] = None
    source_line: Optional[int] = None
    source_text: Optional[str] = None


class Claim(BaseModel):
    """A report assertion explicitly linked to approved evidence.

    Every claim must be grounded in human-approved evidence from the
    Evidence Ledger. Claims include confidence calculations, expression
    policy compliance, and explicit tracking of limitations.
    """

    claim_id: str
    report_section: str
    claim_text: str
    claim_category: ClaimCategory
    confidence_level: ConfidenceLevel
    confidence_basis: str = Field(
        description="Explanation of how confidence was calculated"
    )
    supporting_evidence: list[str] = Field(
        description="evidence_ids supporting this claim"
    )
    counter_evidence: list[str] = Field(
        default_factory=list,
        description="evidence_ids contradicting this claim",
    )
    limitations: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    recommended_expressions: list[str] = Field(default_factory=list)
    prohibited_expressions: list[str] = Field(default_factory=list)
    review_status: str = Field(
        default="pending",
        description="Status: pending, approved, rejected, edited, downgraded",
    )
    original_claim_text: Optional[str] = None
    approved_claim_text: Optional[str] = None
    attack_mappings: list[ATTCKMapping] = Field(default_factory=list)
    # Upstream-analysis provenance: set when the claim was built from a
    # validated analysis group so CP2 reviewers can judge the grouping.
    analysis_group_id: Optional[str] = None
    group_basis: Optional[str] = Field(
        default=None,
        description="Why multiple evidence items were grouped into this claim",
    )
    related_entity_link_ids: list[str] = Field(default_factory=list)
    related_hint_ids: list[str] = Field(default_factory=list)


class Gap(BaseModel):
    """An identified deficiency in evidence coverage.

    Gaps represent missing, weak, single-source, or contradictory
    evidence that must be dispositioned before report finalization.
    """

    gap_id: str
    related_claim_id: str
    gap_type: str = Field(
        description=(
            "Type: missing_evidence, weak_evidence, single_source, "
            "unavailable_logs, logs_outside_scope, logs_not_analyzed, "
            "contradictory_evidence"
        )
    )
    severity: str = Field(description="Severity: critical, major, minor")
    description: str
    recommended_action: str
    disposition: Optional[str] = Field(
        default=None,
        description=(
            "Disposition: accepted_as_limitation, mitigated_by_claim_downgrade, "
            "addressed_by_additional_evidence, out_of_scope_with_analyst_approval, "
            "deferred_with_reason"
        ),
    )
    disposition_reason: Optional[str] = None
    dispositioned_by: Optional[str] = None


class InvestigationTask(BaseModel):
    """A follow-up action generated from identified gaps.

    Investigation tasks guide the analyst on what additional evidence
    to collect or document to address identified gaps.
    """

    task_id: str
    related_gap_id: str
    related_claim_id: str
    task_description: str
    suggested_data_sources: list[str] = Field(default_factory=list)
    expected_evidence: str
    priority: str = Field(description="Priority: high, medium, low")
    reason: str
    status: str = Field(
        default="proposed",
        description=(
            "Status: proposed, accepted, rejected, in_progress, "
            "completed, not_possible, deferred"
        ),
    )


class DataCoverageEntry(BaseModel):
    """A record tracking data source availability for the investigation.

    Distinguishes between 'not observed' (data analyzed but event not found)
    and 'not available' (data source missing or inaccessible).
    """

    data_source_id: str
    host_or_system: str
    data_source_type: str
    availability_status: str = Field(
        description=(
            "Status: available, partially_available, unavailable, "
            "outside_scope, not_requested, pending_collection, unknown"
        )
    )
    covered_time_range: Optional[TimeRange] = None
    collection_time: Optional[str] = None
    known_gaps: list[str] = Field(default_factory=list)
    reason_for_unavailability: Optional[str] = None
    impact_on_findings: Optional[str] = None
