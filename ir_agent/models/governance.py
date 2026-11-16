"""Governance data models for the IR Reporting Support Agent.

Defines AuditEntry, ApprovalEntry, and LLMCallEntry models
for the governance layer's audit logging and approval tracking.
"""

from typing import Optional

from pydantic import BaseModel, Field


class AuditEntry(BaseModel):
    """An entry in the append-only audit log.

    Records every significant operation performed by the Agent
    for full traceability and compliance.
    """

    timestamp: str
    operation_type: str
    input_summary: str
    output_summary: str
    status: str = Field(description="Status: success, failure")


class ApprovalEntry(BaseModel):
    """A record of an analyst's approval decision.

    Tracks human approval gates at every critical step in the workflow.
    """

    timestamp: str
    analyst_id: str
    item_type: str
    item_id: str
    decision: str = Field(
        description="Decision: approved, rejected, edited, downgraded"
    )
    reason: Optional[str] = None


class LLMCallEntry(BaseModel):
    """A record of an LLM API call for audit purposes.

    Tracks all LLM interactions including prompts (hashed),
    models used, and token consumption.
    """

    timestamp: str
    prompt_hash: str
    model_used: str
    token_count: int
    response_hash: str
    provider: str
    temperature: float
