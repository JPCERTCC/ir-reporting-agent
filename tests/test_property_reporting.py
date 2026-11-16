"""Property-based tests for the Reporting Layer.

**Validates: Requirements 16, 22, 23, 25**

Property 8: Expression Policy Compliance
- For every Claim in a generated report, the language used MUST match the
  recommended_expressions for that Claim's confidence_level and claim_category.
- No prohibited_expression for that confidence+category may appear in the
  rendered text corresponding to that claim.

Property 10: Unsupported Claim Rate Zero
- The final report MUST have an Unsupported Claim Rate of 0%.
- Any claim without an evidence_id reference blocks final generation.
"""

from __future__ import annotations

import uuid
from typing import Optional

from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from ir_agent.analysis.metrics import QualityMetricsCalculator
from ir_agent.models.analysis import Claim, Gap, TimelineEntry
from ir_agent.models.base import SourceReference, TimeRange
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry
from ir_agent.models.reporting import ReportPlan
from ir_agent.reporting.draft_generator import DraftGenerator
from ir_agent.reporting.planner import ReportPlanner
from ir_agent.steering.manifest import (
    CaseManifest,
    ConfidenceExpressionPolicy,
    ExpressionPolicy,
    ExpressionRule,
)


# --- Strategies ---

confidence_st = st.sampled_from(list(ConfidenceLevel))

claim_category_st = st.sampled_from(list(ClaimCategory))

# Strategy for expression words that are safe for detection in report text.
# Uses unique multi-word phrases to avoid false positives.
expression_word_st = st.text(
    alphabet=st.characters(whitelist_categories=("Ll",)),
    min_size=6,
    max_size=15,
).filter(lambda s: s.strip() != "" and len(s) >= 6)


@st.composite
def expression_rule_st(draw):
    """Strategy to generate an ExpressionRule with distinct recommended and prohibited expressions."""
    # Generate 1-3 recommended expressions
    n_recommended = draw(st.integers(min_value=1, max_value=3))
    recommended = []
    for i in range(n_recommended):
        word = draw(expression_word_st)
        recommended.append(f"rec_{word}_{i}")

    # Generate 1-3 prohibited expressions
    n_prohibited = draw(st.integers(min_value=1, max_value=3))
    prohibited = []
    for i in range(n_prohibited):
        word = draw(expression_word_st)
        prohibited.append(f"proh_{word}_{i}")

    # Ensure no overlap
    assume(not set(recommended) & set(prohibited))

    return ExpressionRule(
        recommended_expressions=recommended,
        prohibited_expressions=prohibited,
    )


@st.composite
def expression_policy_st(draw):
    """Strategy to generate a complete ExpressionPolicy with distinct rules per confidence level."""
    rules = {}
    for conf in ConfidenceLevel:
        rule = draw(expression_rule_st())
        rules[conf.value] = ConfidenceExpressionPolicy(default=rule)

    return ExpressionPolicy(
        confirmed=rules["confirmed"],
        probable=rules["probable"],
        possible=rules["possible"],
        unknown=rules["unknown"],
        not_observed=rules["not_observed"],
    )


def _make_source_ref(file_id: str = "file-001") -> SourceReference:
    """Create a minimal SourceReference for testing."""
    return SourceReference(
        source_ref_id=f"ref-{uuid.uuid4().hex[:8]}",
        source_file_id=file_id,
        source_path="/artifacts/test.log",
        source_lines=(1, 10),
        excerpt="test excerpt data",
        excerpt_sha256="deadbeef" * 8,
    )


def _make_ledger_entry(evidence_id: str) -> EvidenceLedgerEntry:
    """Create a minimal EvidenceLedgerEntry for testing."""
    return EvidenceLedgerEntry(
        evidence_id=evidence_id,
        promoted_from=[f"cand-{uuid.uuid4().hex[:8]}"],
        approval_timestamp="2024-01-15T10:00:00+00:00",
        approved_by="analyst-01",
        source_refs=[_make_source_ref()],
        observed_event={"type": "test_event", "host": "host01"},
        observed_fact="Test observed fact",
        interpretation="Test interpretation",
        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
        interpretation_confidence=ConfidenceLevel.PROBABLE,
    )


def _make_manifest() -> CaseManifest:
    """Create a minimal CaseManifest for testing."""
    return CaseManifest(
        case_id="CASE-TEST-001",
        case_name="Test Case",
        scope="Test scope",
        hosts=["host01"],
        time_range=TimeRange(
            start="2024-01-01T00:00:00+00:00",
            end="2024-01-31T23:59:59+00:00",
        ),
        report_language="en",
        review_language="en",
        report_timezone="UTC",
    )


@st.composite
def approved_claim_st(draw, evidence_ids: Optional[list[str]] = None):
    """Strategy to generate an approved Claim with at least one supporting evidence.

    Uses a simple claim_text that does NOT already contain prohibited expressions,
    so we can verify the DraftGenerator handles expression policy correctly.
    """
    claim_id = f"C-{draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz0123456789', min_size=4, max_size=8))}"
    category = draw(claim_category_st)
    confidence = draw(confidence_st)

    # Claim text is a simple sentence that won't accidentally contain expressions
    claim_text = f"Claim assertion for {claim_id} about {category.value}"

    # Ensure at least one supporting evidence
    if evidence_ids and len(evidence_ids) > 0:
        n_evidence = draw(st.integers(min_value=1, max_value=min(3, len(evidence_ids))))
        supporting = draw(
            st.lists(
                st.sampled_from(evidence_ids),
                min_size=n_evidence,
                max_size=n_evidence,
                unique=True,
            )
        )
    else:
        supporting = [f"EV-{uuid.uuid4().hex[:8]}"]

    section = draw(st.sampled_from([
        "ttp_based_findings",
        "per_system_findings",
        "executive_summary",
    ]))

    return Claim(
        claim_id=claim_id,
        report_section=section,
        claim_text=claim_text,
        claim_category=category,
        confidence_level=confidence,
        confidence_basis="Based on multiple corroborating sources",
        supporting_evidence=supporting,
        counter_evidence=[],
        limitations=[],
        missing_evidence=[],
        recommended_expressions=[],
        prohibited_expressions=[],
        review_status="approved",
    )


@st.composite
def approved_claims_with_ledger_st(draw, min_claims=1, max_claims=5):
    """Strategy to generate a list of approved claims with matching ledger entries."""
    n_evidence = draw(st.integers(min_value=max(1, min_claims), max_value=max_claims + 3))
    evidence_ids = [f"EV-{uuid.uuid4().hex[:8]}" for _ in range(n_evidence)]
    ledger = [_make_ledger_entry(eid) for eid in evidence_ids]

    n_claims = draw(st.integers(min_value=min_claims, max_value=max_claims))
    claims = []
    used_ids = set()
    for _ in range(n_claims):
        claim = draw(approved_claim_st(evidence_ids=evidence_ids))
        # Ensure unique claim_ids
        while claim.claim_id in used_ids:
            claim = draw(approved_claim_st(evidence_ids=evidence_ids))
        used_ids.add(claim.claim_id)
        claims.append(claim)

    return claims, ledger


# --- Property 8: Expression Policy Compliance ---


class TestExpressionPolicyCompliance:
    """Property 8: Expression Policy Compliance.

    **Validates: Requirements 22, 25**

    For every Claim in a generated report, the language used MUST match the
    recommended_expressions for that Claim's confidence_level and claim_category.
    No prohibited_expression for that confidence+category may appear in the
    rendered text corresponding to that claim.
    """

    @given(
        data=approved_claims_with_ledger_st(min_claims=1, max_claims=4),
        policy=expression_policy_st(),
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example, HealthCheck.too_slow],
    )
    def test_no_prohibited_expression_in_report_text(
        self,
        data: tuple[list[Claim], list[EvidenceLedgerEntry]],
        policy: ExpressionPolicy,
    ):
        """No prohibited_expression for a claim's confidence+category appears
        in the generated report text.

        The DraftGenerator MUST replace or avoid prohibited expressions when
        rendering each claim. This test verifies that for every claim in the
        report, none of its prohibited expressions (per the ExpressionPolicy)
        appear in the final draft output.

        **Validates: Requirements 22, 25**
        """
        claims, ledger = data
        manifest = _make_manifest()
        manifest = manifest.model_copy(update={"expression_policy": policy})

        # Generate a plan and draft
        planner = ReportPlanner()
        plan = planner.generate_plan(claims, [], manifest)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan=plan,
            approved_claims=claims,
            ledger=ledger,
            gaps=[],
            policy=policy,
            manifest=manifest,
        )

        # For each claim, verify no prohibited expressions appear in the draft
        for claim in claims:
            rule = policy.get_rule(claim.confidence_level, claim.claim_category)
            for prohibited in rule.prohibited_expressions:
                assert prohibited not in draft, (
                    f"Prohibited expression '{prohibited}' found in report draft "
                    f"for claim {claim.claim_id} with confidence={claim.confidence_level.value}, "
                    f"category={claim.claim_category.value}. "
                    f"The DraftGenerator MUST NOT use prohibited expressions."
                )

    @given(
        data=approved_claims_with_ledger_st(min_claims=1, max_claims=4),
        policy=expression_policy_st(),
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example, HealthCheck.too_slow],
    )
    def test_prohibited_expressions_in_claim_text_are_removed(
        self,
        data: tuple[list[Claim], list[EvidenceLedgerEntry]],
        policy: ExpressionPolicy,
    ):
        """When a claim_text contains a prohibited expression, the DraftGenerator
        MUST replace it before including it in the report.

        This tests the DraftGenerator's _apply_confidence_language method
        actively removes prohibited expressions from the rendered output.

        **Validates: Requirements 22, 25**
        """
        claims, ledger = data
        assume(len(claims) > 0)

        # Inject a prohibited expression into the first claim's text
        first_claim = claims[0]
        rule = policy.get_rule(first_claim.confidence_level, first_claim.claim_category)
        assume(len(rule.prohibited_expressions) > 0)

        prohibited_word = rule.prohibited_expressions[0]
        modified_claim = first_claim.model_copy(
            update={"claim_text": f"The system {prohibited_word} this activity"}
        )
        claims_with_prohibited = [modified_claim] + claims[1:]

        manifest = _make_manifest()
        manifest = manifest.model_copy(update={"expression_policy": policy})

        planner = ReportPlanner()
        plan = planner.generate_plan(claims_with_prohibited, [], manifest)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan=plan,
            approved_claims=claims_with_prohibited,
            ledger=ledger,
            gaps=[],
            policy=policy,
            manifest=manifest,
        )

        # The prohibited expression must not appear in the final draft
        assert prohibited_word not in draft, (
            f"Prohibited expression '{prohibited_word}' was NOT removed from the report "
            f"even though it was present in claim_text for claim {first_claim.claim_id}. "
            f"Confidence={first_claim.confidence_level.value}, "
            f"Category={first_claim.claim_category.value}. "
            f"The DraftGenerator MUST actively remove prohibited expressions."
        )

    @given(
        data=approved_claims_with_ledger_st(min_claims=1, max_claims=3),
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example, HealthCheck.too_slow],
    )
    def test_only_approved_claims_appear_in_draft(
        self,
        data: tuple[list[Claim], list[EvidenceLedgerEntry]],
    ):
        """The DraftGenerator uses ONLY approved claims. Claims with
        review_status not in ('approved', 'edited') are excluded.

        **Validates: Requirements 22, 25**
        """
        claims, ledger = data
        assume(len(claims) >= 2)

        # Mark some claims as rejected
        rejected_claim = claims[0].model_copy(update={"review_status": "rejected"})
        all_claims = [rejected_claim] + claims[1:]

        manifest = _make_manifest()
        policy = manifest.expression_policy

        planner = ReportPlanner()
        plan = planner.generate_plan(all_claims, [], manifest)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan=plan,
            approved_claims=all_claims,
            ledger=ledger,
            gaps=[],
            policy=policy,
            manifest=manifest,
        )

        # The rejected claim's text should not appear in the draft
        # (since the DraftGenerator filters by review_status)
        rejected_text = rejected_claim.claim_text
        assert rejected_text not in draft, (
            f"Rejected claim text '{rejected_text}' appeared in the draft report. "
            f"Only approved/edited claims should be included."
        )


# --- Property 10: Unsupported Claim Rate Zero ---


class TestUnsupportedClaimRateZero:
    """Property 10: Unsupported Claim Rate Zero.

    **Validates: Requirements 16, 23**

    The final report MUST have an Unsupported Claim Rate of 0%.
    Any claim without an evidence_id reference blocks final generation.
    """

    @given(
        data=approved_claims_with_ledger_st(min_claims=1, max_claims=5),
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example, HealthCheck.too_slow],
    )
    def test_all_claims_in_report_have_supporting_evidence(
        self,
        data: tuple[list[Claim], list[EvidenceLedgerEntry]],
    ):
        """Every claim used in the generated report has at least one
        supporting evidence_id. The unsupported claim rate is 0%.

        The approved_claims_with_ledger strategy guarantees each claim
        has at least one supporting_evidence entry. This test verifies
        that the QualityMetricsCalculator confirms 0% unsupported rate.

        **Validates: Requirements 16, 23**
        """
        claims, ledger = data

        # All claims have supporting evidence by construction
        calculator = QualityMetricsCalculator()
        rate = calculator.calculate_unsupported_claim_rate(claims)

        assert rate == 0.0, (
            f"Unsupported claim rate is {rate:.2%} but must be 0%. "
            f"Claims without evidence: "
            f"{[c.claim_id for c in claims if not c.supporting_evidence]}"
        )

    @given(
        data=approved_claims_with_ledger_st(min_claims=1, max_claims=5),
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example, HealthCheck.too_slow],
    )
    def test_report_draft_includes_evidence_citations_for_all_claims(
        self,
        data: tuple[list[Claim], list[EvidenceLedgerEntry]],
    ):
        """Every claim rendered in the report includes evidence citations
        (evidence_id references) in the output text.

        This verifies that the DraftGenerator includes inline citations
        for each claim's supporting evidence, ensuring traceability.

        **Validates: Requirements 16, 23**
        """
        claims, ledger = data
        manifest = _make_manifest()
        policy = manifest.expression_policy

        planner = ReportPlanner()
        plan = planner.generate_plan(claims, [], manifest)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan=plan,
            approved_claims=claims,
            ledger=ledger,
            gaps=[],
            policy=policy,
            manifest=manifest,
        )

        # For each approved claim, at least one of its evidence_ids should
        # appear as a citation in the draft
        for claim in claims:
            if claim.review_status not in ("approved", "edited"):
                continue
            has_citation = any(
                eid in draft for eid in claim.supporting_evidence
            )
            assert has_citation, (
                f"Claim {claim.claim_id} has supporting evidence "
                f"{claim.supporting_evidence} but none appear as citations "
                f"in the generated report draft. "
                f"The report MUST include evidence citations for every assertion."
            )

    @given(
        data=approved_claims_with_ledger_st(min_claims=2, max_claims=5),
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example, HealthCheck.too_slow],
    )
    def test_unsupported_claim_rate_detects_missing_evidence(
        self,
        data: tuple[list[Claim], list[EvidenceLedgerEntry]],
    ):
        """When a claim has empty supporting_evidence, the
        QualityMetricsCalculator correctly reports a non-zero
        unsupported claim rate.

        This validates the metric calculation itself, confirming that
        claims without evidence are properly detected and would block
        report finalization.

        **Validates: Requirements 16, 23**
        """
        claims, ledger = data
        assume(len(claims) >= 2)

        # Remove supporting evidence from the first claim
        unsupported_claim = claims[0].model_copy(
            update={"supporting_evidence": []}
        )
        mixed_claims = [unsupported_claim] + claims[1:]

        calculator = QualityMetricsCalculator()
        rate = calculator.calculate_unsupported_claim_rate(mixed_claims)

        # Rate should be > 0 since at least one claim has no evidence
        assert rate > 0.0, (
            f"Unsupported claim rate is 0% despite claim {unsupported_claim.claim_id} "
            f"having no supporting evidence. The metric MUST detect this."
        )

        # Rate should be exactly 1/n where n is total relevant claims
        relevant_count = sum(
            1 for c in mixed_claims if c.review_status != "rejected"
        )
        expected_rate = 1.0 / relevant_count
        assert abs(rate - expected_rate) < 1e-9, (
            f"Expected unsupported rate {expected_rate:.4f} but got {rate:.4f}. "
            f"One out of {relevant_count} claims is unsupported."
        )
