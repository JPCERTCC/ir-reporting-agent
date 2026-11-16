"""Upstream-analysis correlation models for the IR Reporting Support Agent.

Defines the intermediate artifacts of the upstream-analysis improvement
(specification_upstream_analysis_improvement.md):

- FieldGroundingRecord: whether an observed_event field value is grounded
  in the evidence excerpt or artifact inventory (data/field_grounding.jsonl).
- CorrelationHint: mechanical correlation candidates the CLI derives from
  grounded values (data/correlation_hints.jsonl).
- EntityLinkCandidate / EntityLink: LLM-proposed same-entity links and their
  CLI-validated form (data/entity_link_candidates.jsonl / entity_links.jsonl).
- AnalysisGroupCandidate / AnalysisGroup: LLM-proposed multi-evidence
  analysis groups and their CLI-validated form
  (data/analysis_group_candidates.jsonl / analysis_groups.jsonl).

Design principle: No Grounding, No Correlation. LLM output is untrusted
until it passes CLI validation.
"""

from typing import Optional

from pydantic import BaseModel, Field

from ir_agent.models.enums import ConfidenceLevel


# report_section values allowed for analysis groups / claims routed to the
# fixed chapter structure of the final report (spec section 4.4).
ALLOWED_REPORT_SECTIONS: dict[str, str] = {
    "3.1": "初期侵入",
    "3.2": "認証情報取得・アカウント悪用",
    "3.3": "内部探索・横展開",
    "3.4": "永続化",
    "3.5": "C2通信・プロキシ・外部通信",
    "3.6": "情報窃取・情報持ち出し",
    "3.7": "防衛回避・痕跡消去",
    "context": "3章の直接所見ではない背景情報",
    "limitation": "調査上の制約・不足事項",
}

# observed_event fields verified by ground-evidence-fields (spec section 4.1).
GROUNDING_TARGET_FIELDS: list[str] = [
    "timestamp",
    "host",
    "user",
    "src_ip",
    "dst_ip",
    "process_name",
    "command_line",
    "file_path",
    "registry_key",
    "url",
    "domain",
    "hash",
]


class FieldGroundingRecord(BaseModel):
    """Grounding status of a single observed_event (or derived) field value.

    ``kind`` distinguishes fixed observed_event fields from ``derived``
    values extracted from raw_summary / excerpts (e.g. ``tunnel_ip=...``),
    which are required so cross-evidence pivots on non-fixed fields are not
    lost during correlation.
    """

    grounding_id: str
    evidence_id: str
    candidate_id: Optional[str] = None
    field: str
    value: str
    normalized_value: Optional[str] = None
    kind: str = Field(
        default="fixed", description="Origin of the value: fixed or derived"
    )
    status: str = Field(
        description=(
            "grounded, partially_grounded, not_grounded, or not_applicable"
        )
    )
    matched_in: Optional[str] = Field(
        default=None,
        description="Where the value was confirmed: excerpt, file_inventory, raw_summary",
    )
    source_ref_id: Optional[str] = None
    source_lines: Optional[list[int]] = None
    reason: str = ""
    created_at: str = ""


class CorrelationHint(BaseModel):
    """A mechanical correlation candidate between two or more evidence items.

    Hints are material for the LLM correlation step and human reviewers,
    never conclusions. Only grounded values may produce hints.
    """

    hint_id: str
    hint_type: str = Field(
        description=(
            "shared_entity, time_proximity, same_attack_mapping, "
            "or same_artifact_context"
        )
    )
    evidence_ids: list[str]
    fields: list[str] = Field(default_factory=list)
    values: list[str] = Field(default_factory=list)
    score: float = Field(ge=0.0, le=1.0)
    reason: str = ""
    status: str = "candidate"


class EntityLinkMember(BaseModel):
    """A single (evidence, field, value) participation in an entity link."""

    evidence_id: str
    field: str
    value: str


class EntityLinkCandidate(BaseModel):
    """An LLM-proposed link asserting values across evidence are one entity."""

    entity_link_id: str
    entity_type: str
    canonical_label: str
    members: list[EntityLinkMember]
    link_reason: str = ""
    related_hint_ids: list[str] = Field(default_factory=list)
    review_status: str = "pending"


class EntityLink(BaseModel):
    """A CLI-validated entity link. Failed members are excluded, and links

    whose members were all excluded are marked rejected.
    """

    entity_link_id: str
    entity_type: str
    canonical_label: str
    members: list[EntityLinkMember]
    excluded_members: list[EntityLinkMember] = Field(default_factory=list)
    link_reason: str = ""
    related_hint_ids: list[str] = Field(default_factory=list)
    validation_status: str = Field(
        default="valid", description="valid, warning, or rejected"
    )
    validation_reasons: list[str] = Field(default_factory=list)
    review_status: str = "pending"


class GroupAttackMapping(BaseModel):
    """An ATT&CK mapping carried by an analysis group.

    Unlike the evidence-level ATTCKMapping, this keeps the supporting
    evidence ids so mapping reasons stay tied to concrete evidence when
    propagated into claims (spec section 8.1).
    """

    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    supporting_evidence: list[str] = Field(default_factory=list)
    mapping_reason: str = ""
    confidence: Optional[ConfidenceLevel] = None


class AnalysisGroupCandidate(BaseModel):
    """An LLM-proposed analysis result backed by one or more evidence items."""

    analysis_group_id: str
    title: str = ""
    report_section: str
    claim_text: str
    claim_category: str = "interpretation"
    supporting_evidence: list[str]
    related_entity_link_ids: list[str] = Field(default_factory=list)
    related_hint_ids: list[str] = Field(default_factory=list)
    attack_mappings: list[GroupAttackMapping] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    group_basis: str = ""
    review_status: str = "pending"


class AnalysisGroup(BaseModel):
    """A CLI-validated analysis group, ready for build-claims consumption."""

    analysis_group_id: str
    title: str = ""
    report_section: str
    claim_text: str
    claim_category: str = "interpretation"
    supporting_evidence: list[str]
    related_entity_link_ids: list[str] = Field(default_factory=list)
    related_hint_ids: list[str] = Field(default_factory=list)
    attack_mappings: list[GroupAttackMapping] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    group_basis: str = ""
    validation_status: str = Field(
        default="valid", description="valid, warning, or rejected"
    )
    validation_reasons: list[str] = Field(default_factory=list)
    review_status: str = "pending"
