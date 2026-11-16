"""Core enumerations for the IR Reporting Support Agent.

Defines ConfidenceLevel, ClaimCategory, and WorkflowPhase enums
used across all layers of the system.
"""

from enum import Enum


class ConfidenceLevel(str, Enum):
    """Confidence level for observations and interpretations.

    Controls report language via the expression policy.
    """

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"
    NOT_OBSERVED = "not_observed"


class ClaimCategory(str, Enum):
    """Categories of claims that can appear in reports.

    Each category may have different expression policies and
    confidence calculation approaches.
    """

    OBSERVED_FACT = "observed_fact"
    INTERPRETATION = "interpretation"
    CAUSAL_RELATIONSHIP = "causal_relationship"
    IMPACT_ASSESSMENT = "impact_assessment"
    DATA_EXFILTRATION_ASSESSMENT = "data_exfiltration_assessment"
    INTRUSION_VECTOR_ASSESSMENT = "intrusion_vector_assessment"
    ATTRIBUTION_ASSESSMENT = "attribution_assessment"


class WorkflowPhase(str, Enum):
    """Phases in the IR reporting workflow state machine.

    Each phase has prerequisites that must be completed before
    the workflow can advance to that phase.
    """

    CASE_INITIALIZED = "case_initialized"
    ARTIFACTS_INGESTED = "artifacts_ingested"
    EVENTS_NORMALIZED = "events_normalized"
    EVIDENCE_CANDIDATES_GENERATED = "evidence_candidates_generated"
    EVIDENCE_REVIEWED = "evidence_reviewed"
    EVIDENCE_LEDGER_APPROVED = "evidence_ledger_approved"
    DATA_COVERAGE_BUILT = "data_coverage_built"
    TIMELINE_BUILT = "timeline_built"
    ATTACK_MAPPED = "attack_mapped"
    # Upstream-analysis improvement phases (recommended, between map-attack
    # and build-claims; build-claims falls back when they are absent).
    FIELDS_GROUNDED = "fields_grounded"
    CORRELATION_HINTS_BUILT = "correlation_hints_built"
    ANALYSIS_GROUPS_VALIDATED = "analysis_groups_validated"
    CLAIMS_GENERATED = "claims_generated"
    CLAIMS_REVIEWED = "claims_reviewed"
    GAPS_CHECKED = "gaps_checked"
    GAPS_DISPOSITIONED = "gaps_dispositioned"
    REPORT_PLAN_GENERATED = "report_plan_generated"
    REPORT_PLAN_APPROVED = "report_plan_approved"
    DRAFT_REPORT_GENERATED = "draft_report_generated"
    DRAFT_REPORT_APPROVED = "draft_report_approved"
    FINAL_REPORT_GENERATED = "final_report_generated"
