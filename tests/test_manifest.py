"""Unit tests for ir_agent.steering.manifest models."""

import pytest

from ir_agent.models.base import TimeRange
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.steering.manifest import (
    CaseManifest,
    ConfidenceExpressionPolicy,
    ExpressionPolicy,
    ExpressionRule,
)


class TestExpressionRule:
    def test_default_empty_lists(self):
        rule = ExpressionRule()
        assert rule.recommended_expressions == []
        assert rule.prohibited_expressions == []

    def test_with_values(self):
        rule = ExpressionRule(
            recommended_expressions=["確認された", "判明した"],
            prohibited_expressions=["かもしれない"],
        )
        assert rule.recommended_expressions == ["確認された", "判明した"]
        assert rule.prohibited_expressions == ["かもしれない"]


class TestConfidenceExpressionPolicy:
    def test_default_empty_by_category(self):
        policy = ConfidenceExpressionPolicy(default=ExpressionRule())
        assert policy.by_category == {}

    def test_with_category_override(self):
        default = ExpressionRule(recommended_expressions=["default"])
        override = ExpressionRule(recommended_expressions=["override"])
        policy = ConfidenceExpressionPolicy(
            default=default,
            by_category={ClaimCategory.OBSERVED_FACT: override},
        )
        assert policy.by_category[ClaimCategory.OBSERVED_FACT] == override


class TestExpressionPolicy:
    @pytest.fixture
    def policy(self) -> ExpressionPolicy:
        """Build an ExpressionPolicy with distinct rules for testing."""
        return ExpressionPolicy(
            confirmed=ConfidenceExpressionPolicy(
                default=ExpressionRule(recommended_expressions=["confirmed-default"]),
                by_category={
                    ClaimCategory.OBSERVED_FACT: ExpressionRule(
                        recommended_expressions=["confirmed-observed"]
                    ),
                },
            ),
            probable=ConfidenceExpressionPolicy(
                default=ExpressionRule(recommended_expressions=["probable-default"]),
            ),
            possible=ConfidenceExpressionPolicy(
                default=ExpressionRule(recommended_expressions=["possible-default"]),
            ),
            unknown=ConfidenceExpressionPolicy(
                default=ExpressionRule(recommended_expressions=["unknown-default"]),
            ),
            not_observed=ConfidenceExpressionPolicy(
                default=ExpressionRule(recommended_expressions=["not-observed-default"]),
            ),
        )

    def test_get_rule_returns_category_override(self, policy: ExpressionPolicy):
        rule = policy.get_rule(ConfidenceLevel.CONFIRMED, ClaimCategory.OBSERVED_FACT)
        assert rule.recommended_expressions == ["confirmed-observed"]

    def test_get_rule_returns_default_when_no_category_override(
        self, policy: ExpressionPolicy
    ):
        rule = policy.get_rule(ConfidenceLevel.CONFIRMED, ClaimCategory.INTERPRETATION)
        assert rule.recommended_expressions == ["confirmed-default"]

    def test_get_rule_probable_level(self, policy: ExpressionPolicy):
        rule = policy.get_rule(ConfidenceLevel.PROBABLE, ClaimCategory.IMPACT_ASSESSMENT)
        assert rule.recommended_expressions == ["probable-default"]

    def test_get_rule_possible_level(self, policy: ExpressionPolicy):
        rule = policy.get_rule(ConfidenceLevel.POSSIBLE, ClaimCategory.CAUSAL_RELATIONSHIP)
        assert rule.recommended_expressions == ["possible-default"]

    def test_get_rule_unknown_level(self, policy: ExpressionPolicy):
        rule = policy.get_rule(
            ConfidenceLevel.UNKNOWN, ClaimCategory.DATA_EXFILTRATION_ASSESSMENT
        )
        assert rule.recommended_expressions == ["unknown-default"]

    def test_get_rule_not_observed_level(self, policy: ExpressionPolicy):
        rule = policy.get_rule(
            ConfidenceLevel.NOT_OBSERVED, ClaimCategory.ATTRIBUTION_ASSESSMENT
        )
        assert rule.recommended_expressions == ["not-observed-default"]

    def test_default_factory_creates_empty_policy(self):
        policy = ExpressionPolicy()
        rule = policy.get_rule(ConfidenceLevel.CONFIRMED, ClaimCategory.OBSERVED_FACT)
        assert rule.recommended_expressions == []
        assert rule.prohibited_expressions == []


class TestCaseManifest:
    @pytest.fixture
    def minimal_manifest(self) -> CaseManifest:
        return CaseManifest(
            case_id="CASE-2024-001",
            case_name="Test Incident",
            scope="Full investigation of lateral movement",
            hosts=["host01", "host02"],
            time_range=TimeRange(
                start="2024-01-15T00:00:00Z",
                end="2024-01-20T23:59:59Z",
            ),
        )

    def test_defaults(self, minimal_manifest: CaseManifest):
        assert minimal_manifest.report_language == "ja"
        assert minimal_manifest.review_language == "ja"
        assert minimal_manifest.report_timezone == "UTC"
        assert minimal_manifest.max_chunk_size == 3000
        assert minimal_manifest.chunk_overlap == 50
        assert minimal_manifest.rubric == {}
        assert isinstance(minimal_manifest.expression_policy, ExpressionPolicy)

    def test_required_fields(self):
        with pytest.raises(Exception):
            CaseManifest()  # type: ignore

    def test_custom_language_settings(self):
        manifest = CaseManifest(
            case_id="CASE-002",
            case_name="English Report",
            scope="Investigation",
            hosts=["server01"],
            time_range=TimeRange(start="2024-01-01T00:00:00Z", end="2024-01-31T23:59:59Z"),
            report_language="en",
            review_language="en",
            report_timezone="America/New_York",
        )
        assert manifest.report_language == "en"
        assert manifest.review_language == "en"
        assert manifest.report_timezone == "America/New_York"

    def test_validation_rejects_invalid_case_id_type(self):
        with pytest.raises(Exception):
            CaseManifest(
                case_id=123,  # type: ignore
                case_name="Test",
                scope="Test",
                hosts=["h1"],
                time_range=TimeRange(start="2024-01-01T00:00:00Z", end="2024-01-31T23:59:59Z"),
            )

    def test_hosts_list(self, minimal_manifest: CaseManifest):
        assert minimal_manifest.hosts == ["host01", "host02"]

    def test_time_range(self, minimal_manifest: CaseManifest):
        assert minimal_manifest.time_range.start == "2024-01-15T00:00:00Z"
        assert minimal_manifest.time_range.end == "2024-01-20T23:59:59Z"


class TestClaimCategory:
    """Verify ClaimCategory enum values expected by the steering layer."""

    def test_all_categories_present(self):
        expected = {
            "observed_fact",
            "interpretation",
            "causal_relationship",
            "impact_assessment",
            "data_exfiltration_assessment",
            "intrusion_vector_assessment",
            "attribution_assessment",
        }
        actual = {c.value for c in ClaimCategory}
        assert actual == expected

    def test_category_is_string_enum(self):
        assert isinstance(ClaimCategory.OBSERVED_FACT, str)
        assert ClaimCategory.OBSERVED_FACT == "observed_fact"
