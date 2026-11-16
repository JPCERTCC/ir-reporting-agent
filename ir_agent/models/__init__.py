"""Data Models.

Core data models, enums, and dataclasses used across all layers
of the IR Reporting Support Agent.
"""

from ir_agent.models.enums import ClaimCategory, ConfidenceLevel, WorkflowPhase
from ir_agent.models.base import EventTimestamp, SourceReference, TimeRange
from ir_agent.models.events import ATTCKMapping, NormalizedEvent
from ir_agent.models.evidence import (
    EntityResolutionEntry,
    EvidenceCandidate,
    EvidenceLedgerEntry,
    IOCRecord,
)
from ir_agent.models.analysis import (
    Claim,
    DataCoverageEntry,
    Gap,
    InvestigationTask,
    TimelineEntry,
)
from ir_agent.models.governance import ApprovalEntry, AuditEntry, LLMCallEntry
from ir_agent.models.reporting import ReportPlan

__all__ = [
    # Enums
    "ClaimCategory",
    "ConfidenceLevel",
    "WorkflowPhase",
    # Base models
    "EventTimestamp",
    "SourceReference",
    "TimeRange",
    # Event models
    "ATTCKMapping",
    "NormalizedEvent",
    # Evidence models
    "EntityResolutionEntry",
    "EvidenceCandidate",
    "EvidenceLedgerEntry",
    "IOCRecord",
    # Analysis models
    "Claim",
    "DataCoverageEntry",
    "Gap",
    "InvestigationTask",
    "TimelineEntry",
    # Governance models
    "ApprovalEntry",
    "AuditEntry",
    "LLMCallEntry",
    # Reporting models
    "ReportPlan",
]
