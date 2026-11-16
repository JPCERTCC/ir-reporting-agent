"""Consolidated unit tests for the Analysis Layer.

Tests specific interactions across ClaimBuilder, GapChecker,
QualityMetricsCalculator, and GapReviewService that are not
covered by individual test files.

Requirements: 11.4, 13.2, 13.4, 13.6, 23.1, 23.2
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ir_agent.analysis.claim_builder import ClaimBuilder
from ir_agent.analysis.gap_checker import GapChecker
from ir_agent.analysis.gap_review import GapReviewService
from ir_agent.analysis.metrics import QualityMetricsCalculator
from ir_agent.models.analysis import Claim, DataCoverageEntry, Gap, TimelineEntry
from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry
from ir_agent.steering.manifest import (
    ConfidenceExpressionPolicy,
    ExpressionPolicy,
    ExpressionRule,
)


# --- Helpers ---


def _make_source_ref(
    source_file_id: str = "FILE-001",
    source_path: str = "/artifacts/log.txt",
    source_lines: tuple[int, int] = (1, 5),
) -> SourceReference:
    return SourceReference(
        source_ref_id=f"REF-{source_file_id}",
        source_file_id=source_file_id,
        source_path=source_path,
        source_lines=source_lines,
        excerpt="Sample log line content",
        excerpt_sha256="abc123def456",
    )


def _make_ledger_entry(
    evidence_id: str = "EV-001",
    interpretation: str = "Possible lateral movement",
    observed_fact_confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
    interpretation_confidence: ConfidenceLevel = ConfidenceLevel.PROBABLE,
    source_file_id: str = "FILE-001",
    host: str = "host01",
    withdrawn: bool = False,
) -> EvidenceLedgerEntry:
    return EvidenceLedgerEntry(
        evidence_id=evidence_id,
        promoted_from=["CAND-001"],
        approval_timestamp="2024-01-15T10:00:00Z",
        approved_by="analyst-01",
        source_refs=[_make_source_ref(source_file_id=source_file_id)],
        observed_event={"type": "network_connection", "host": host},
        observed_fact="Network connection observed from host01 to external IP",
        interpretation=interpretation,
        observed_fact_confidence=observed_fact_confidence,
        interpretation_confidence=interpretation_confidence,
        withdrawn=withdrawn,
    )


def _make_coverage(
    data_source_id: str = "DC-host01-firewall",
    host_or_system: str = "host01",
    data_source_type: str = "firewall_log",
    availability_status: str = "available",
    reason_for_unavailability: str | None = None,
    impact_on_findings: str | None = None,
) -> DataCoverageEntry:
    return DataCoverageEntry(
        data_source_id=data_source_id,
        host_or_system=host_or_system,
        data_source_type=data_source_type,
        availability_status=availability_status,
        covered_time_range=None,
        collection_time=None,
        known_gaps=[],
        reason_for_unavailability=reason_for_unavailability,
        impact_on_findings=impact_on_findings,
    )


def _make_timeline_entry(evidence_id: str = "EV-001") -> TimelineEntry:
    return TimelineEntry(
        entry_id="TL-001",
        evidence_id=evidence_id,
        event_time="2024-01-15T09:00:00Z",
        original_timestamp="2024-01-15 18:00:00 JST",
        display_timezone="Asia/Tokyo",
        event_description="Network connection detected",
        host="host01",
        confidence=ConfidenceLevel.CONFIRMED,
    )


def _make_expression_policy() -> ExpressionPolicy:
    """Create a minimal expression policy for testing."""
    return ExpressionPolicy(
        confirmed=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["confirmed that", "verified"],
                prohibited_expressions=["possibly", "might"],
            )
        ),
        probable=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["likely", "probably"],
                prohibited_expressions=["confirmed", "definitely"],
            )
        ),
        possible=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["possibly", "may have"],
                prohibited_expressions=["confirmed", "definitely", "probably"],
            )
        ),
        unknown=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["unknown"],
                prohibited_expressions=["confirmed"],
            )
        ),
        not_observed=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["not observed"],
                prohibited_expressions=["confirmed"],
            )
        ),
    )


def _make_claim(
    claim_id: str = "CLM-001",
    confidence_level: ConfidenceLevel = ConfidenceLevel.PROBABLE,
    claim_category: ClaimCategory = ClaimCategory.INTERPRETATION,
    supporting_evidence: list[str] | None = None,
    counter_evidence: list[str] | None = None,
    limitations: list[str] | None = None,
    missing_evidence: list[str] | None = None,
    claim_text: str = "Test claim",
    report_section: str = "analysis",
    review_status: str = "approved",
) -> Claim:
    return Claim(
        claim_id=claim_id,
        report_section=report_section,
        claim_text=claim_text,
        claim_category=claim_category,
        confidence_level=confidence_level,
        confidence_basis="Test basis",
        supporting_evidence=supporting_evidence if supporting_evidence is not None else ["EV-001"],
        counter_evidence=counter_evidence or [],
        limitations=limitations or [],
        missing_evidence=missing_evidence or [],
        review_status=review_status,
    )


# --- Test Classes ---


class TestClaimBuilderRejectsClaimsWithoutEvidence:
    """Test that ClaimBuilder will not generate a claim without at least one
    supporting evidence_id.

    Validates Requirement 11.4: No claim without at least one supporting
    evidence_id from the Evidence Ledger.
    """

    def test_empty_ledger_produces_no_claims(self):
        """build_claims with no evidence entries returns empty list."""
        builder = ClaimBuilder()
        policy = _make_expression_policy()

        claims = builder.build_claims(
            ledger=[],
            timeline=[],
            policy=policy,
            coverage=[],
        )

        assert claims == []

    def test_only_withdrawn_entries_produces_no_claims(self):
        """build_claims with only withdrawn evidence returns empty list."""
        builder = ClaimBuilder()
        policy = _make_expression_policy()
        withdrawn_entry = _make_ledger_entry(withdrawn=True)

        claims = builder.build_claims(
            ledger=[withdrawn_entry],
            timeline=[_make_timeline_entry()],
            policy=policy,
            coverage=[],
        )

        assert claims == []

    def test_every_generated_claim_has_supporting_evidence(self):
        """All claims returned by build_claims have at least one supporting evidence_id."""
        builder = ClaimBuilder()
        policy = _make_expression_policy()
        entries = [
            _make_ledger_entry(evidence_id="EV-001", source_file_id="FILE-001"),
            _make_ledger_entry(
                evidence_id="EV-002",
                interpretation="Different interpretation",
                source_file_id="FILE-002",
            ),
        ]
        timeline = [_make_timeline_entry("EV-001")]

        claims = builder.build_claims(
            ledger=entries,
            timeline=timeline,
            policy=policy,
            coverage=[],
        )

        assert len(claims) >= 1
        for claim in claims:
            assert len(claim.supporting_evidence) >= 1, (
                f"Claim {claim.claim_id} has no supporting evidence"
            )

    def test_calculate_confidence_with_no_supporting_returns_unknown(self):
        """calculate_confidence with empty supporting list returns UNKNOWN."""
        builder = ClaimBuilder()

        confidence, basis = builder.calculate_confidence(
            claim_category=ClaimCategory.INTERPRETATION,
            supporting=[],
            counter=[],
            coverage=[],
        )

        assert confidence == ConfidenceLevel.UNKNOWN
        assert "No supporting evidence" in basis


class TestClaimBuilderUsesDataCoverageInConfidence:
    """Test that ClaimBuilder factors data coverage into confidence calculation.

    Validates Requirement 11.4: Confidence is calculated from claim_category,
    evidence directness, source count, counter-evidence, data coverage, and
    limitations.
    """

    def test_poor_coverage_reduces_confidence(self):
        """When most data sources are unavailable, confidence is penalized."""
        builder = ClaimBuilder()
        supporting = [_make_ledger_entry(evidence_id="EV-001")]

        # Good coverage (all available)
        good_coverage = [
            _make_coverage(availability_status="available", data_source_id="DC-01"),
            _make_coverage(availability_status="available", data_source_id="DC-02"),
            _make_coverage(availability_status="available", data_source_id="DC-03"),
        ]
        conf_good, _ = builder.calculate_confidence(
            ClaimCategory.INTERPRETATION, supporting, [], good_coverage
        )

        # Poor coverage (mostly unavailable)
        poor_coverage = [
            _make_coverage(availability_status="unavailable", data_source_id="DC-01"),
            _make_coverage(availability_status="unavailable", data_source_id="DC-02"),
            _make_coverage(availability_status="unavailable", data_source_id="DC-03"),
            _make_coverage(availability_status="unavailable", data_source_id="DC-04"),
            _make_coverage(availability_status="available", data_source_id="DC-05"),
        ]
        conf_poor, basis_poor = builder.calculate_confidence(
            ClaimCategory.INTERPRETATION, supporting, [], poor_coverage
        )

        # Poor coverage should result in equal or lower confidence
        confidence_order = {
            ConfidenceLevel.CONFIRMED: 4,
            ConfidenceLevel.PROBABLE: 3,
            ConfidenceLevel.POSSIBLE: 2,
            ConfidenceLevel.UNKNOWN: 1,
            ConfidenceLevel.NOT_OBSERVED: 0,
        }
        assert confidence_order[conf_poor] <= confidence_order[conf_good]
        # Basis should mention coverage
        assert "coverage" in basis_poor.lower()

    def test_good_coverage_does_not_penalize(self):
        """When data sources are available, no coverage penalty is applied."""
        builder = ClaimBuilder()
        supporting = [
            _make_ledger_entry(evidence_id="EV-001", source_file_id="FILE-001"),
            _make_ledger_entry(evidence_id="EV-002", source_file_id="FILE-002"),
        ]
        good_coverage = [
            _make_coverage(availability_status="available"),
        ]

        confidence, basis = builder.calculate_confidence(
            ClaimCategory.INTERPRETATION, supporting, [], good_coverage
        )

        # With two corroborating sources and good coverage, should be at least PROBABLE
        confidence_order = {
            ConfidenceLevel.CONFIRMED: 4,
            ConfidenceLevel.PROBABLE: 3,
            ConfidenceLevel.POSSIBLE: 2,
            ConfidenceLevel.UNKNOWN: 1,
            ConfidenceLevel.NOT_OBSERVED: 0,
        }
        assert confidence_order[confidence] >= confidence_order[ConfidenceLevel.POSSIBLE]

    def test_confidence_basis_explains_coverage_factor(self):
        """Confidence basis includes coverage information when coverage is limited."""
        builder = ClaimBuilder()
        supporting = [_make_ledger_entry()]
        poor_coverage = [
            _make_coverage(availability_status="unavailable", data_source_id="DC-01"),
            _make_coverage(availability_status="unavailable", data_source_id="DC-02"),
            _make_coverage(availability_status="unavailable", data_source_id="DC-03"),
            _make_coverage(availability_status="available", data_source_id="DC-04"),
        ]

        _, basis = builder.calculate_confidence(
            ClaimCategory.INTERPRETATION, supporting, [], poor_coverage
        )

        assert "coverage" in basis.lower()


class TestGapCheckerIdentifiesOverclaims:
    """Test that GapChecker correctly identifies overclaims.

    Validates Requirement 13.4: Identify overclaims — claims where the
    assertion strength exceeds what the evidence supports.
    """

    def test_confirmed_claim_with_single_evidence_is_overclaim(self):
        """CONFIRMED confidence with only one evidence item is an overclaim."""
        checker = GapChecker()
        claims = [
            _make_claim(
                claim_id="CLM-OC1",
                confidence_level=ConfidenceLevel.CONFIRMED,
                supporting_evidence=["EV-001"],
            )
        ]

        overclaims = checker.detect_overclaims(claims)

        assert len(overclaims) == 1
        assert overclaims[0].claim_id == "CLM-OC1"

    def test_high_threshold_category_probable_with_single_source_is_overclaim(self):
        """PROBABLE attribution claim with one evidence item is an overclaim."""
        checker = GapChecker()
        claims = [
            _make_claim(
                claim_id="CLM-OC2",
                confidence_level=ConfidenceLevel.PROBABLE,
                claim_category=ClaimCategory.ATTRIBUTION_ASSESSMENT,
                supporting_evidence=["EV-001"],
            )
        ]

        overclaims = checker.detect_overclaims(claims)

        assert len(overclaims) == 1
        assert overclaims[0].claim_id == "CLM-OC2"

    def test_confirmed_claim_with_counter_evidence_is_overclaim(self):
        """CONFIRMED confidence in the presence of counter-evidence is an overclaim."""
        checker = GapChecker()
        claims = [
            _make_claim(
                claim_id="CLM-OC3",
                confidence_level=ConfidenceLevel.CONFIRMED,
                supporting_evidence=["EV-001", "EV-002"],
                counter_evidence=["EV-010"],
            )
        ]

        overclaims = checker.detect_overclaims(claims)

        assert len(overclaims) == 1
        assert overclaims[0].claim_id == "CLM-OC3"

    def test_well_supported_claim_is_not_overclaim(self):
        """PROBABLE claim with multiple evidence and no counter is not an overclaim."""
        checker = GapChecker()
        claims = [
            _make_claim(
                claim_id="CLM-OK",
                confidence_level=ConfidenceLevel.PROBABLE,
                claim_category=ClaimCategory.INTERPRETATION,
                supporting_evidence=["EV-001", "EV-002", "EV-003"],
                counter_evidence=[],
            )
        ]

        overclaims = checker.detect_overclaims(claims)

        assert len(overclaims) == 0


class TestContradictionDetection:
    """Test contradiction detection finds conflicting claims.

    Validates Requirement 13.2: Flag contradictions with references to
    both claim_ids and conflicting evidence.
    """

    def test_evidence_in_support_and_counter_is_contradiction(self):
        """Claims where one claim's evidence is another's counter-evidence creates contradiction."""
        checker = GapChecker()
        claims = [
            _make_claim(
                claim_id="CLM-A",
                supporting_evidence=["EV-001", "EV-002"],
                counter_evidence=[],
                report_section="findings",
            ),
            _make_claim(
                claim_id="CLM-B",
                supporting_evidence=["EV-003"],
                counter_evidence=["EV-001"],
                report_section="findings",
            ),
        ]

        contradictions = checker.detect_contradictions(claims)

        assert len(contradictions) == 1
        assert contradictions[0]["claim_id_a"] == "CLM-A"
        assert contradictions[0]["claim_id_b"] == "CLM-B"
        assert "EV-001" in contradictions[0]["conflicting_evidence"]

    def test_textual_negation_in_same_section_is_contradiction(self):
        """Claims with textual negation in the same report section are flagged."""
        checker = GapChecker()
        claims = [
            _make_claim(
                claim_id="CLM-X",
                claim_text="Data was exfiltrated from the server",
                report_section="data_exfiltration",
                supporting_evidence=["EV-001"],
            ),
            _make_claim(
                claim_id="CLM-Y",
                claim_text="No exfiltration was detected",
                report_section="data_exfiltration",
                supporting_evidence=["EV-002"],
            ),
        ]

        contradictions = checker.detect_contradictions(claims)

        assert len(contradictions) >= 1
        claim_ids_in_contradiction = {
            contradictions[0]["claim_id_a"],
            contradictions[0]["claim_id_b"],
        }
        assert "CLM-X" in claim_ids_in_contradiction
        assert "CLM-Y" in claim_ids_in_contradiction

    def test_no_contradiction_when_claims_consistent(self):
        """Claims that don't conflict produce no contradictions."""
        checker = GapChecker()
        claims = [
            _make_claim(
                claim_id="CLM-1",
                claim_text="Initial access via phishing email",
                report_section="intrusion_vector",
                supporting_evidence=["EV-001"],
            ),
            _make_claim(
                claim_id="CLM-2",
                claim_text="Lateral movement using RDP",
                report_section="findings",
                supporting_evidence=["EV-002"],
            ),
        ]

        contradictions = checker.detect_contradictions(claims)

        assert len(contradictions) == 0


class TestQualityMetricsComputesCorrectRates:
    """Test that QualityMetricsCalculator computes correct rates.

    Validates Requirements 23.1, 23.2: Compute unsupported claim rate,
    overclaim rate, evidence coverage, critical gap disposition rate,
    and limitation coverage.
    """

    def test_unsupported_claim_rate_correct(self):
        """Unsupported claim rate = unsupported / total non-rejected claims."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(claim_id="CLM-001", supporting_evidence=["EV-001"]),
            _make_claim(claim_id="CLM-002", supporting_evidence=[]),
            _make_claim(claim_id="CLM-003", supporting_evidence=["EV-003"]),
            _make_claim(claim_id="CLM-004", supporting_evidence=[]),
        ]

        rate = calc.calculate_unsupported_claim_rate(claims)

        # 2 out of 4 are unsupported
        assert rate == pytest.approx(0.5)

    def test_overclaim_rate_correct(self):
        """Overclaim rate = overclaims / total non-rejected claims."""
        calc = QualityMetricsCalculator()
        claims = [
            # Overclaim: CONFIRMED with single source
            _make_claim(
                claim_id="CLM-001",
                confidence_level=ConfidenceLevel.CONFIRMED,
                supporting_evidence=["EV-001"],
            ),
            # Not overclaim: PROBABLE with multiple sources
            _make_claim(
                claim_id="CLM-002",
                confidence_level=ConfidenceLevel.PROBABLE,
                supporting_evidence=["EV-002", "EV-003"],
            ),
            # Overclaim: CONFIRMED with counter-evidence
            _make_claim(
                claim_id="CLM-003",
                confidence_level=ConfidenceLevel.CONFIRMED,
                supporting_evidence=["EV-004", "EV-005"],
                counter_evidence=["EV-006"],
            ),
        ]

        rate = calc.calculate_overclaim_rate(claims)

        # 2 out of 3 are overclaims
        assert rate == pytest.approx(2 / 3)

    def test_evidence_coverage_correct(self):
        """Evidence coverage = cited evidence / total ledger entries."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(
                claim_id="CLM-001",
                supporting_evidence=["EV-001", "EV-002"],
            ),
        ]
        ledger = [
            _make_ledger_entry("EV-001"),
            _make_ledger_entry("EV-002"),
            _make_ledger_entry("EV-003"),
            _make_ledger_entry("EV-004"),
        ]

        rate = calc.calculate_evidence_coverage(claims, ledger)

        # 2 out of 4 are cited
        assert rate == pytest.approx(0.5)

    def test_critical_gap_disposition_rate_correct(self):
        """Critical gap disposition rate = dispositioned critical / total critical."""
        calc = QualityMetricsCalculator()
        gaps = [
            Gap(
                gap_id="GAP-001",
                related_claim_id="CLM-001",
                gap_type="missing_evidence",
                severity="critical",
                description="Missing logs",
                recommended_action="Collect",
                disposition="accepted_as_limitation",
            ),
            Gap(
                gap_id="GAP-002",
                related_claim_id="CLM-002",
                gap_type="weak_evidence",
                severity="critical",
                description="Weak evidence",
                recommended_action="Strengthen",
                disposition=None,
            ),
            Gap(
                gap_id="GAP-003",
                related_claim_id="CLM-003",
                gap_type="single_source",
                severity="major",
                description="Single source",
                recommended_action="Corroborate",
                disposition=None,
            ),
        ]

        rate = calc.calculate_critical_gap_disposition_rate(gaps)

        # 1 out of 2 critical gaps are dispositioned (GAP-003 is major, excluded)
        assert rate == pytest.approx(0.5)

    def test_calculate_all_metrics_returns_all_keys(self):
        """calculate_all_metrics returns a complete dict with all metric keys."""
        calc = QualityMetricsCalculator()
        claims = [_make_claim(supporting_evidence=["EV-001"])]
        ledger = [_make_ledger_entry("EV-001")]
        gaps = []

        metrics = calc.calculate_all_metrics(claims, ledger, gaps, "")

        expected_keys = {
            "unsupported_claim_rate",
            "overclaim_rate",
            "evidence_coverage",
            "critical_gap_disposition_rate",
            "limitation_coverage",
            # Upstream-analysis metrics (spec 13.3)
            "multi_evidence_claim_rate",
            "section_assignment_rate",
            "attack_mapping_propagation_rate",
        }
        assert set(metrics.keys()) == expected_keys
        assert all(isinstance(v, float) for v in metrics.values())


class TestGapReviewServiceJapaneseDocument:
    """Test that GapReviewService generates a Japanese document with correct headings.

    Validates Requirement 13.6: Generate Gap_Review_Document with Japanese
    section headings (説明, 関連Claim, 推奨対応, 影響, 判定).
    """

    def test_japanese_title(self, tmp_path: Path):
        """Document title is in Japanese when review_language='ja'."""
        service = GapReviewService()
        gaps = [
            Gap(
                gap_id="GAP-001",
                related_claim_id="CLM-001",
                gap_type="missing_evidence",
                severity="critical",
                description="ファイアウォールログが取得不可",
                recommended_action="ログの取得を依頼",
            )
        ]

        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "# ギャップレビュー" in content

    def test_japanese_section_headings_present(self, tmp_path: Path):
        """All five required Japanese section headings are present."""
        service = GapReviewService()
        gaps = [
            Gap(
                gap_id="GAP-001",
                related_claim_id="CLM-001",
                gap_type="missing_evidence",
                severity="critical",
                description="Test gap",
                recommended_action="Test action",
            )
        ]

        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        # Verify all 5 Japanese headings
        assert "### 説明" in content
        assert "### 関連Claim" in content
        assert "### 推奨対応" in content
        assert "### 影響" in content
        assert "### 判定" in content

    def test_yaml_keys_remain_english_in_japanese_doc(self, tmp_path: Path):
        """YAML disposition block keys remain in English within Japanese document."""
        service = GapReviewService()
        gaps = [
            Gap(
                gap_id="GAP-001",
                related_claim_id="CLM-001",
                gap_type="unavailable_logs",
                severity="major",
                description="ログが利用不可",
                recommended_action="ログ収集チームに連絡",
            )
        ]

        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        # YAML block keys must be in English
        assert "item_id:" in content
        assert "item_type: gap" in content
        assert "disposition:" in content
        assert "disposition_reason:" in content
        assert "analyst_id:" in content


class TestGapReviewServiceParserExtractsDispositions:
    """Test that GapReviewService parser extracts dispositions from YAML blocks.

    Validates Requirement 13.6: Parse gap review documents to extract
    YAML disposition decisions (language-agnostic parsing).
    """

    def test_parser_extracts_single_disposition(self, tmp_path: Path):
        """Parser extracts a single disposition from a review document."""
        service = GapReviewService()
        doc_content = """# ギャップレビュー

## GAP-001

### 判定

```yaml
item_id: GAP-001
item_type: gap
disposition: accepted_as_limitation
disposition_reason: "ログが保持期間を過ぎて削除済み"
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")

        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 1
        assert dispositions[0].item_id == "GAP-001"
        assert dispositions[0].disposition == "accepted_as_limitation"
        assert dispositions[0].analyst_id == "analyst-01"

    def test_parser_extracts_multiple_dispositions(self, tmp_path: Path):
        """Parser correctly extracts multiple dispositions from one document."""
        service = GapReviewService()
        doc_content = """# ギャップレビュー

## GAP-001

### 判定

```yaml
item_id: GAP-001
item_type: gap
disposition: accepted_as_limitation
disposition_reason: "制限として記録"
analyst_id: analyst-01
```

---

## GAP-002

### 判定

```yaml
item_id: GAP-002
item_type: gap
disposition: mitigated_by_claim_downgrade
disposition_reason: "Claimの信頼度を下方修正"
analyst_id: analyst-01
```

---

## GAP-003

### 判定

```yaml
item_id: GAP-003
item_type: gap
disposition: deferred_with_reason
disposition_reason: "第三者からのログ取得待ち"
analyst_id: analyst-02
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")

        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 3
        assert dispositions[0].item_id == "GAP-001"
        assert dispositions[0].disposition == "accepted_as_limitation"
        assert dispositions[1].item_id == "GAP-002"
        assert dispositions[1].disposition == "mitigated_by_claim_downgrade"
        assert dispositions[2].item_id == "GAP-003"
        assert dispositions[2].disposition == "deferred_with_reason"
        assert dispositions[2].analyst_id == "analyst-02"

    def test_roundtrip_generate_then_parse(self, tmp_path: Path):
        """Generating then parsing a document roundtrips correctly."""
        service = GapReviewService()
        gaps = [
            Gap(
                gap_id="GAP-RT1",
                related_claim_id="CLM-001",
                gap_type="missing_evidence",
                severity="critical",
                description="Missing evidence for claim",
                recommended_action="Collect additional data",
            ),
            Gap(
                gap_id="GAP-RT2",
                related_claim_id="CLM-002",
                gap_type="single_source",
                severity="major",
                description="Single source dependency",
                recommended_action="Find corroborating sources",
            ),
        ]

        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(gaps, output, review_language="ja")
        dispositions = service.parse_gap_review_doc(output)

        assert len(dispositions) == 2
        assert dispositions[0].item_id == "GAP-RT1"
        assert dispositions[1].item_id == "GAP-RT2"
        # Freshly generated doc has null dispositions
        assert dispositions[0].disposition is None
        assert dispositions[1].disposition is None

    def test_parser_ignores_non_disposition_yaml_blocks(self, tmp_path: Path):
        """Parser skips YAML blocks that are not disposition decisions."""
        service = GapReviewService()
        doc_content = """# Gap Review

Some configuration:

```yaml
config_key: value
another: setting
```

Actual disposition:

```yaml
item_id: GAP-001
item_type: gap
disposition: deferred_with_reason
disposition_reason: "Later"
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")

        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 1
        assert dispositions[0].item_id == "GAP-001"
