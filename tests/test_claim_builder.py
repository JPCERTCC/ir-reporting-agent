"""Unit tests for ClaimBuilder.

Validates Requirements 11.1, 11.2, 11.3, 11.4, 11.5, 11.6:
- Claims generated from approved evidence (11.1)
- Claim fields recorded correctly (11.2)
- Confidence level assigned based on evidence strength (11.3)
- No claim without supporting evidence (11.4)
- Multi-factor confidence calculation, no weakest-item downgrade (11.5)
- Expression policy applied to each claim (11.6)
"""

import pytest

from ir_agent.analysis.claim_builder import ClaimBuilder
from ir_agent.models.analysis import Claim, DataCoverageEntry, TimelineEntry
from ir_agent.models.base import SourceReference, TimeRange
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry
from ir_agent.steering.manifest import (
    ConfidenceExpressionPolicy,
    ExpressionPolicy,
    ExpressionRule,
)


# --- Fixtures ---


def _make_source_ref(file_id: str = "file-001", lines: tuple[int, int] = (1, 5)) -> SourceReference:
    """Create a test SourceReference."""
    return SourceReference(
        source_ref_id=f"ref-{file_id}",
        source_file_id=file_id,
        source_path=f"/artifacts/{file_id}.log",
        source_lines=lines,
        excerpt="test log entry",
        excerpt_sha256="abc123",
    )


def _make_ledger_entry(
    evidence_id: str = "EV-001",
    interpretation: str = "Malicious lateral movement detected",
    observed_fact: str = "Process executed on host",
    observed_fact_confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
    interpretation_confidence: ConfidenceLevel = ConfidenceLevel.PROBABLE,
    source_file_ids: list[str] | None = None,
    host: str | None = "host01",
) -> EvidenceLedgerEntry:
    """Create a test EvidenceLedgerEntry."""
    if source_file_ids is None:
        source_file_ids = ["file-001"]

    source_refs = [_make_source_ref(fid) for fid in source_file_ids]
    observed_event = {"host": host} if host else {}

    return EvidenceLedgerEntry(
        evidence_id=evidence_id,
        promoted_from=["cand-001"],
        approval_timestamp="2025-01-01T00:00:00Z",
        approved_by="analyst",
        source_refs=source_refs,
        observed_event=observed_event,
        observed_fact=observed_fact,
        interpretation=interpretation,
        observed_fact_confidence=observed_fact_confidence,
        interpretation_confidence=interpretation_confidence,
    )


def _make_coverage_entry(
    host: str = "host01",
    data_source_type: str = "syslog",
    availability_status: str = "available",
) -> DataCoverageEntry:
    """Create a test DataCoverageEntry."""
    return DataCoverageEntry(
        data_source_id=f"ds-{host}-{data_source_type}",
        host_or_system=host,
        data_source_type=data_source_type,
        availability_status=availability_status,
        covered_time_range=TimeRange(
            start="2025-01-01T00:00:00Z",
            end="2025-01-31T23:59:59Z",
        ),
    )


def _make_expression_policy() -> ExpressionPolicy:
    """Create a test ExpressionPolicy with rules for all confidence levels."""
    return ExpressionPolicy(
        confirmed=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["確認された", "confirmed"],
                prohibited_expressions=["可能性がある", "possibly"],
            )
        ),
        probable=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["可能性が高い", "likely"],
                prohibited_expressions=["確認された", "confirmed"],
            )
        ),
        possible=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["可能性がある", "possibly"],
                prohibited_expressions=["確認された", "confirmed", "likely"],
            )
        ),
        unknown=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["不明", "unknown"],
                prohibited_expressions=["確認された", "confirmed", "likely"],
            )
        ),
        not_observed=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["観測されていない", "not observed"],
                prohibited_expressions=["確認された", "confirmed"],
            )
        ),
    )


@pytest.fixture
def builder() -> ClaimBuilder:
    """Create a ClaimBuilder instance."""
    return ClaimBuilder()


@pytest.fixture
def policy() -> ExpressionPolicy:
    """Create a test ExpressionPolicy."""
    return _make_expression_policy()


# --- Test: Requirement 11.1 - Claims generated from evidence and timeline ---


class TestBuildClaims:
    """Tests for build_claims method (Requirements 11.1, 11.2, 11.4)."""

    def test_generates_claims_from_ledger_and_timeline(
        self, builder: ClaimBuilder, policy: ExpressionPolicy
    ):
        """Requirement 11.1: Generate claims when ledger and timeline available."""
        ledger = [_make_ledger_entry()]
        timeline = [
            TimelineEntry(
                entry_id="tl-001",
                evidence_id="EV-001",
                event_time="2025-01-15T10:00:00Z",
                original_timestamp="2025-01-15T19:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="Process execution",
                host="host01",
                confidence=ConfidenceLevel.PROBABLE,
            )
        ]
        coverage = [_make_coverage_entry()]

        claims = builder.build_claims(ledger, timeline, policy, coverage)

        assert len(claims) >= 1
        assert all(isinstance(c, Claim) for c in claims)

    def test_returns_empty_for_empty_ledger(
        self, builder: ClaimBuilder, policy: ExpressionPolicy
    ):
        """No claims generated from empty ledger."""
        claims = builder.build_claims([], [], policy, [])
        assert claims == []

    def test_skips_withdrawn_entries(
        self, builder: ClaimBuilder, policy: ExpressionPolicy
    ):
        """Withdrawn entries are excluded from claim generation."""
        entry = _make_ledger_entry()
        entry.withdrawn = True

        claims = builder.build_claims([entry], [], policy, [])
        assert claims == []

    def test_claim_has_required_fields(
        self, builder: ClaimBuilder, policy: ExpressionPolicy
    ):
        """Requirement 11.2: Each claim has all required fields."""
        ledger = [_make_ledger_entry()]
        claims = builder.build_claims(ledger, [], policy, [])

        assert len(claims) == 1
        claim = claims[0]

        # Verify all required fields are present
        assert claim.claim_id
        assert claim.report_section
        assert claim.claim_text
        assert isinstance(claim.claim_category, ClaimCategory)
        assert isinstance(claim.confidence_level, ConfidenceLevel)
        assert claim.confidence_basis  # non-empty explanation
        assert isinstance(claim.supporting_evidence, list)
        assert isinstance(claim.counter_evidence, list)
        assert isinstance(claim.limitations, list)
        assert isinstance(claim.missing_evidence, list)


# --- Test: Requirement 11.4 - No claim without supporting evidence ---


class TestNoClaimWithoutEvidence:
    """Tests for Requirement 11.4: No claim without supporting evidence_id."""

    def test_every_claim_has_supporting_evidence(
        self, builder: ClaimBuilder, policy: ExpressionPolicy
    ):
        """Every generated claim must have at least one supporting evidence_id."""
        ledger = [
            _make_ledger_entry("EV-001", "Lateral movement detected"),
            _make_ledger_entry("EV-002", "Data exfiltration observed"),
        ]

        claims = builder.build_claims(ledger, [], policy, [])

        for claim in claims:
            assert len(claim.supporting_evidence) >= 1, (
                f"Claim {claim.claim_id} has no supporting evidence"
            )


# --- Test: Requirement 11.3 & 11.5 - Confidence calculation ---


class TestCalculateConfidence:
    """Tests for calculate_confidence (Requirements 11.3, 11.5)."""

    def test_single_confirmed_evidence_gives_high_confidence(
        self, builder: ClaimBuilder
    ):
        """Single confirmed evidence should give high confidence for observed facts."""
        supporting = [
            _make_ledger_entry(
                interpretation_confidence=ConfidenceLevel.CONFIRMED
            )
        ]

        confidence, basis = builder.calculate_confidence(
            ClaimCategory.OBSERVED_FACT, supporting, [], []
        )

        assert confidence == ConfidenceLevel.CONFIRMED
        assert basis  # non-empty explanation

    def test_multiple_probable_evidence_can_elevate_confidence(
        self, builder: ClaimBuilder
    ):
        """Requirement 11.5: Multiple corroborating sources can elevate confidence
        above the weakest individual item."""
        # Three probable items from different sources should give elevated confidence
        supporting = [
            _make_ledger_entry(
                "EV-001",
                interpretation_confidence=ConfidenceLevel.PROBABLE,
                source_file_ids=["file-001"],
            ),
            _make_ledger_entry(
                "EV-002",
                interpretation_confidence=ConfidenceLevel.PROBABLE,
                source_file_ids=["file-002"],
            ),
            _make_ledger_entry(
                "EV-003",
                interpretation_confidence=ConfidenceLevel.PROBABLE,
                source_file_ids=["file-003"],
            ),
        ]

        confidence, basis = builder.calculate_confidence(
            ClaimCategory.OBSERVED_FACT, supporting, [], []
        )

        from ir_agent.analysis.claim_builder import _CONFIDENCE_ORDER

        # With corroboration from 3 independent sources, should be at least PROBABLE
        assert _CONFIDENCE_ORDER[confidence] >= _CONFIDENCE_ORDER[ConfidenceLevel.PROBABLE]

    def test_does_not_mechanically_downgrade_to_weakest(
        self, builder: ClaimBuilder
    ):
        """Requirement 11.5: Does NOT mechanically downgrade to weakest evidence."""
        # Mix of confirmed and possible - should not downgrade to possible
        supporting = [
            _make_ledger_entry(
                "EV-001",
                interpretation_confidence=ConfidenceLevel.CONFIRMED,
                source_file_ids=["file-001"],
            ),
            _make_ledger_entry(
                "EV-002",
                interpretation_confidence=ConfidenceLevel.CONFIRMED,
                source_file_ids=["file-002"],
            ),
            _make_ledger_entry(
                "EV-003",
                interpretation_confidence=ConfidenceLevel.POSSIBLE,
                source_file_ids=["file-003"],
            ),
        ]

        confidence, basis = builder.calculate_confidence(
            ClaimCategory.OBSERVED_FACT, supporting, [], []
        )

        # Should NOT be downgraded to POSSIBLE just because one item is POSSIBLE
        assert confidence != ConfidenceLevel.POSSIBLE
        assert confidence in (ConfidenceLevel.CONFIRMED, ConfidenceLevel.PROBABLE)

    def test_counter_evidence_reduces_confidence(
        self, builder: ClaimBuilder
    ):
        """Counter-evidence should reduce confidence."""
        supporting = [
            _make_ledger_entry(
                interpretation_confidence=ConfidenceLevel.CONFIRMED
            )
        ]
        counter = [
            _make_ledger_entry(
                "EV-COUNTER",
                interpretation_confidence=ConfidenceLevel.PROBABLE,
            )
        ]

        confidence_with_counter, _ = builder.calculate_confidence(
            ClaimCategory.INTERPRETATION, supporting, counter, []
        )
        confidence_without_counter, _ = builder.calculate_confidence(
            ClaimCategory.INTERPRETATION, supporting, [], []
        )

        # Confidence with counter should be less than or equal to without
        from ir_agent.analysis.claim_builder import _CONFIDENCE_ORDER
        assert (
            _CONFIDENCE_ORDER[confidence_with_counter]
            <= _CONFIDENCE_ORDER[confidence_without_counter]
        )

    def test_attribution_category_requires_stronger_evidence(
        self, builder: ClaimBuilder
    ):
        """Attribution claims get a category-specific downward adjustment."""
        supporting = [
            _make_ledger_entry(
                interpretation_confidence=ConfidenceLevel.PROBABLE,
                source_file_ids=["file-001"],
            )
        ]

        conf_attribution, _ = builder.calculate_confidence(
            ClaimCategory.ATTRIBUTION_ASSESSMENT, supporting, [], []
        )
        conf_observation, _ = builder.calculate_confidence(
            ClaimCategory.OBSERVED_FACT, supporting, [], []
        )

        from ir_agent.analysis.claim_builder import _CONFIDENCE_ORDER
        assert _CONFIDENCE_ORDER[conf_attribution] <= _CONFIDENCE_ORDER[conf_observation]

    def test_no_supporting_evidence_returns_unknown(
        self, builder: ClaimBuilder
    ):
        """No supporting evidence should return UNKNOWN confidence."""
        confidence, basis = builder.calculate_confidence(
            ClaimCategory.INTERPRETATION, [], [], []
        )

        assert confidence == ConfidenceLevel.UNKNOWN
        assert "No supporting evidence" in basis

    def test_elevation_documented_in_basis(
        self, builder: ClaimBuilder
    ):
        """Requirement 11.5: If confidence elevated above any single evidence,
        the basis must explain the elevation rationale."""
        # One possible and two probable from different sources
        supporting = [
            _make_ledger_entry(
                "EV-001",
                interpretation_confidence=ConfidenceLevel.POSSIBLE,
                source_file_ids=["file-001"],
            ),
            _make_ledger_entry(
                "EV-002",
                interpretation_confidence=ConfidenceLevel.PROBABLE,
                source_file_ids=["file-002"],
            ),
            _make_ledger_entry(
                "EV-003",
                interpretation_confidence=ConfidenceLevel.PROBABLE,
                source_file_ids=["file-003"],
            ),
        ]

        confidence, basis = builder.calculate_confidence(
            ClaimCategory.OBSERVED_FACT, supporting, [], []
        )

        from ir_agent.analysis.claim_builder import _CONFIDENCE_ORDER

        # If confidence is above POSSIBLE (weakest), elevation note must be present
        if _CONFIDENCE_ORDER[confidence] > _CONFIDENCE_ORDER[ConfidenceLevel.POSSIBLE]:
            assert "ELEVATION" in basis

    def test_poor_coverage_reduces_confidence(
        self, builder: ClaimBuilder
    ):
        """Limited data coverage should reduce confidence."""
        supporting = [
            _make_ledger_entry(
                interpretation_confidence=ConfidenceLevel.PROBABLE,
                source_file_ids=["file-001"],
            )
        ]

        # Poor coverage: mostly unavailable
        poor_coverage = [
            _make_coverage_entry("host01", "syslog", "unavailable"),
            _make_coverage_entry("host01", "auth_log", "unavailable"),
            _make_coverage_entry("host01", "firewall", "unavailable"),
        ]

        conf_poor, _ = builder.calculate_confidence(
            ClaimCategory.INTERPRETATION, supporting, [], poor_coverage
        )
        conf_good, _ = builder.calculate_confidence(
            ClaimCategory.INTERPRETATION, supporting, [], []
        )

        from ir_agent.analysis.claim_builder import _CONFIDENCE_ORDER
        assert _CONFIDENCE_ORDER[conf_poor] <= _CONFIDENCE_ORDER[conf_good]


# --- Test: Requirement 11.6 - Expression policy application ---


class TestApplyExpressionPolicy:
    """Tests for apply_expression_policy (Requirement 11.6)."""

    def test_sets_recommended_expressions(
        self, builder: ClaimBuilder, policy: ExpressionPolicy
    ):
        """Expression policy recommended_expressions applied to claim."""
        claim = Claim(
            claim_id="CLM-001",
            report_section="analysis",
            claim_text="Test claim",
            claim_category=ClaimCategory.INTERPRETATION,
            confidence_level=ConfidenceLevel.PROBABLE,
            confidence_basis="Test basis",
            supporting_evidence=["EV-001"],
        )

        result = builder.apply_expression_policy(claim, policy)

        assert result.recommended_expressions == ["可能性が高い", "likely"]

    def test_sets_prohibited_expressions(
        self, builder: ClaimBuilder, policy: ExpressionPolicy
    ):
        """Expression policy prohibited_expressions applied to claim."""
        claim = Claim(
            claim_id="CLM-001",
            report_section="findings",
            claim_text="Test claim",
            claim_category=ClaimCategory.OBSERVED_FACT,
            confidence_level=ConfidenceLevel.CONFIRMED,
            confidence_basis="Test basis",
            supporting_evidence=["EV-001"],
        )

        result = builder.apply_expression_policy(claim, policy)

        assert result.prohibited_expressions == ["可能性がある", "possibly"]

    def test_category_specific_override(
        self, builder: ClaimBuilder
    ):
        """Category-specific rules override default when present."""
        custom_rule = ExpressionRule(
            recommended_expressions=["帰属の可能性", "possibly attributed"],
            prohibited_expressions=["確定的に帰属", "definitely attributed"],
        )

        policy = ExpressionPolicy(
            probable=ConfidenceExpressionPolicy(
                default=ExpressionRule(
                    recommended_expressions=["default_recommended"],
                    prohibited_expressions=["default_prohibited"],
                ),
                by_category={ClaimCategory.ATTRIBUTION_ASSESSMENT: custom_rule},
            ),
        )

        claim = Claim(
            claim_id="CLM-001",
            report_section="attribution",
            claim_text="Attribution claim",
            claim_category=ClaimCategory.ATTRIBUTION_ASSESSMENT,
            confidence_level=ConfidenceLevel.PROBABLE,
            confidence_basis="Test basis",
            supporting_evidence=["EV-001"],
        )

        result = builder.apply_expression_policy(claim, policy)

        assert result.recommended_expressions == ["帰属の可能性", "possibly attributed"]
        assert result.prohibited_expressions == ["確定的に帰属", "definitely attributed"]

    def test_expression_policy_applied_in_build_claims(
        self, builder: ClaimBuilder, policy: ExpressionPolicy
    ):
        """Requirement 11.6: Expression policy is applied during build_claims."""
        ledger = [_make_ledger_entry()]
        claims = builder.build_claims(ledger, [], policy, [])

        assert len(claims) >= 1
        # Every claim should have expression policy applied
        for claim in claims:
            # At least one of recommended or prohibited should be set
            # (unless the policy has empty defaults)
            assert claim.recommended_expressions is not None
            assert claim.prohibited_expressions is not None
