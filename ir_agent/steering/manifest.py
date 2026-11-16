"""Case Steering Layer manifest models.

Defines CaseManifest, ExpressionPolicy, ExpressionRule, ConfidenceExpressionPolicy,
and TimeRange models used for case configuration and expression policy
management. These Pydantic models are validated at the YAML serialization boundary.
"""

from pydantic import BaseModel, Field

from ir_agent.models.base import TimeRange
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel


class ExpressionRule(BaseModel):
    """A rule defining recommended and prohibited expressions for report language.

    Controls what language may or must not be used when expressing claims
    at a given confidence level and category.
    """

    recommended_expressions: list[str] = Field(default_factory=list)
    prohibited_expressions: list[str] = Field(default_factory=list)


class ConfidenceExpressionPolicy(BaseModel):
    """Expression policy for a single confidence level.

    Contains a default rule and optional category-specific overrides.
    When a claim's category has a specific rule, it takes precedence
    over the default.
    """

    default: ExpressionRule = Field(default_factory=ExpressionRule)
    by_category: dict[ClaimCategory, ExpressionRule] = Field(default_factory=dict)


class ExpressionPolicy(BaseModel):
    """Expression policy defining permitted and prohibited language per confidence level.

    Each confidence level has a ConfidenceExpressionPolicy with a default rule
    and optional category-specific overrides. The get_rule method resolves the
    appropriate rule for a given confidence level and claim category.
    """

    confirmed: ConfidenceExpressionPolicy = Field(
        default_factory=ConfidenceExpressionPolicy
    )
    probable: ConfidenceExpressionPolicy = Field(
        default_factory=ConfidenceExpressionPolicy
    )
    possible: ConfidenceExpressionPolicy = Field(
        default_factory=ConfidenceExpressionPolicy
    )
    unknown: ConfidenceExpressionPolicy = Field(
        default_factory=ConfidenceExpressionPolicy
    )
    not_observed: ConfidenceExpressionPolicy = Field(
        default_factory=ConfidenceExpressionPolicy
    )

    def get_rule(
        self, confidence: ConfidenceLevel, category: ClaimCategory
    ) -> ExpressionRule:
        """Return the expression rule for a given confidence level and claim category.

        Looks up the ConfidenceExpressionPolicy for the confidence level, then
        returns the category-specific rule if one exists, otherwise the default rule.

        Args:
            confidence: The confidence level to look up.
            category: The claim category to check for overrides.

        Returns:
            The matching ExpressionRule for the confidence/category combination.
        """
        policy: ConfidenceExpressionPolicy = getattr(self, confidence.value)
        return policy.by_category.get(category, policy.default)


class CaseManifest(BaseModel):
    """Case manifest defining scope, hosts, rules, and configuration.

    Validated at the YAML serialization boundary when loading manifest.yaml.
    Controls all aspects of case behavior including report language,
    expression policy, and chunking parameters.
    """

    case_id: str
    case_name: str
    scope: str
    hosts: list[str]
    time_range: TimeRange
    report_language: str = Field(
        default="ja",
        description="Language for report output (ISO 639-1 code)",
    )
    review_language: str = Field(
        default="ja",
        description="Language for human-facing review documents (ISO 639-1 code)",
    )
    report_timezone: str = Field(
        default="UTC",
        description="Timezone for timestamp display in reports",
    )
    rubric: dict = Field(default_factory=dict)
    expression_policy: ExpressionPolicy = Field(default_factory=ExpressionPolicy)
    max_chunk_size: int = Field(
        default=3000, description="Maximum chunk size in lines"
    )
    chunk_overlap: int = Field(
        default=50, description="Chunk overlap in lines"
    )
