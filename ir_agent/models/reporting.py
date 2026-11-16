"""Reporting data models for the IR Reporting Support Agent.

Defines the ReportPlan model used by the reporting layer
for structuring the final report output.
"""

from pydantic import BaseModel, Field


class ReportPlan(BaseModel):
    """A plan defining the structure and content of the final report.

    Each section maps to approved claims and their supporting evidence,
    defining the narrative flow of the report.
    """

    sections: list[dict] = Field(
        description=(
            "List of report sections, each containing heading, claims, "
            "evidence_refs, and narrative_flow"
        )
    )
    structure_type: str = Field(
        default="standard",
        description='Report structure type: "standard" or "japanese_ir"',
    )
