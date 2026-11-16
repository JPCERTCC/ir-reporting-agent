"""Unit tests for QualityMetricsCalculator.

Tests quality metrics calculation: unsupported claim rate, overclaim rate,
evidence coverage, critical gap disposition rate, and limitation coverage.

Requirements: 23.1, 23.2, 23.3, 23.4, 23.8
"""

import pytest

from ir_agent.analysis.metrics import QualityMetricsCalculator
from ir_agent.models.analysis import Claim, Gap
from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry


def _make_claim(
    claim_id: str = "CLM-001",
    confidence_level: ConfidenceLevel = ConfidenceLevel.PROBABLE,
    supporting_evidence: list[str] | None = None,
    counter_evidence: list[str] | None = None,
    review_status: str = "approved",
) -> Claim:
    """Helper to create a Claim for testing."""
    return Claim(
        claim_id=claim_id,
        report_section="findings",
        claim_text="Test claim text",
        claim_category=ClaimCategory.INTERPRETATION,
        confidence_level=confidence_level,
        confidence_basis="Test basis",
        supporting_evidence=supporting_evidence if supporting_evidence is not None else ["EV-001"],
        counter_evidence=counter_evidence if counter_evidence is not None else [],
        review_status=review_status,
    )


def _make_ledger_entry(evidence_id: str = "EV-001") -> EvidenceLedgerEntry:
    """Helper to create an EvidenceLedgerEntry for testing."""
    return EvidenceLedgerEntry(
        evidence_id=evidence_id,
        promoted_from=["CAND-001"],
        approval_timestamp="2024-01-01T00:00:00Z",
        approved_by="analyst-01",
        source_refs=[
            SourceReference(
                source_ref_id="REF-001",
                source_file_id="FILE-001",
                source_path="/artifacts/log.txt",
                source_lines=(10, 12),
                excerpt="Sample excerpt",
                excerpt_sha256="abc123",
            )
        ],
        observed_event={"type": "login"},
        observed_fact="Login observed",
        interpretation="Possible unauthorized access",
        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
        interpretation_confidence=ConfidenceLevel.PROBABLE,
    )


def _make_gap(
    gap_id: str = "GAP-001",
    severity: str = "critical",
    disposition: str | None = None,
    description: str = "Missing firewall logs for host01",
) -> Gap:
    """Helper to create a Gap for testing."""
    return Gap(
        gap_id=gap_id,
        related_claim_id="CLM-001",
        gap_type="missing_evidence",
        severity=severity,
        description=description,
        recommended_action="Collect additional data",
        disposition=disposition,
    )


class TestUnsupportedClaimRate:
    """Tests for QualityMetricsCalculator.calculate_unsupported_claim_rate."""

    def test_all_claims_supported(self) -> None:
        """Rate should be 0 when all claims have supporting evidence. Req 23.1."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(claim_id="CLM-001", supporting_evidence=["EV-001"]),
            _make_claim(claim_id="CLM-002", supporting_evidence=["EV-002"]),
        ]

        rate = calc.calculate_unsupported_claim_rate(claims)

        assert rate == 0.0

    def test_some_claims_unsupported(self) -> None:
        """Rate should reflect the proportion of unsupported claims."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(claim_id="CLM-001", supporting_evidence=["EV-001"]),
            _make_claim(claim_id="CLM-002", supporting_evidence=[]),
        ]

        rate = calc.calculate_unsupported_claim_rate(claims)

        assert rate == 0.5

    def test_all_claims_unsupported(self) -> None:
        """Rate should be 1.0 when no claims have evidence."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(claim_id="CLM-001", supporting_evidence=[]),
            _make_claim(claim_id="CLM-002", supporting_evidence=[]),
        ]

        rate = calc.calculate_unsupported_claim_rate(claims)

        assert rate == 1.0

    def test_empty_claims_list(self) -> None:
        """Rate should be 0.0 when no claims exist."""
        calc = QualityMetricsCalculator()

        rate = calc.calculate_unsupported_claim_rate([])

        assert rate == 0.0

    def test_rejected_claims_excluded(self) -> None:
        """Rejected claims should not count in the calculation."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(claim_id="CLM-001", supporting_evidence=["EV-001"]),
            _make_claim(claim_id="CLM-002", supporting_evidence=[], review_status="rejected"),
        ]

        rate = calc.calculate_unsupported_claim_rate(claims)

        # Only CLM-001 is relevant and it's supported
        assert rate == 0.0


class TestOverclaimRate:
    """Tests for QualityMetricsCalculator.calculate_overclaim_rate."""

    def test_no_overclaims(self) -> None:
        """Rate should be 0 when no claims exceed evidence confidence. Req 23.2."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(
                claim_id="CLM-001",
                confidence_level=ConfidenceLevel.PROBABLE,
                supporting_evidence=["EV-001", "EV-002"],
            ),
        ]

        rate = calc.calculate_overclaim_rate(claims)

        assert rate == 0.0

    def test_confirmed_with_single_source_is_overclaim(self) -> None:
        """A CONFIRMED claim with single evidence is an overclaim."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(
                claim_id="CLM-001",
                confidence_level=ConfidenceLevel.CONFIRMED,
                supporting_evidence=["EV-001"],  # Only one source
            ),
        ]

        rate = calc.calculate_overclaim_rate(claims)

        assert rate == 1.0

    def test_confirmed_with_counter_evidence_is_overclaim(self) -> None:
        """A CONFIRMED claim with counter-evidence is an overclaim."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(
                claim_id="CLM-001",
                confidence_level=ConfidenceLevel.CONFIRMED,
                supporting_evidence=["EV-001", "EV-002"],
                counter_evidence=["EV-003"],
            ),
        ]

        rate = calc.calculate_overclaim_rate(claims)

        assert rate == 1.0

    def test_mixed_overclaims(self) -> None:
        """Rate should be proportion of overclaims to total claims."""
        calc = QualityMetricsCalculator()
        claims = [
            # Not an overclaim: PROBABLE with multiple sources
            _make_claim(
                claim_id="CLM-001",
                confidence_level=ConfidenceLevel.PROBABLE,
                supporting_evidence=["EV-001", "EV-002"],
            ),
            # Overclaim: CONFIRMED with single source
            _make_claim(
                claim_id="CLM-002",
                confidence_level=ConfidenceLevel.CONFIRMED,
                supporting_evidence=["EV-003"],
            ),
        ]

        rate = calc.calculate_overclaim_rate(claims)

        assert rate == 0.5

    def test_empty_claims_list(self) -> None:
        """Rate should be 0 for empty claims list."""
        calc = QualityMetricsCalculator()

        rate = calc.calculate_overclaim_rate([])

        assert rate == 0.0


class TestEvidenceCoverage:
    """Tests for QualityMetricsCalculator.calculate_evidence_coverage."""

    def test_all_evidence_cited(self) -> None:
        """Coverage should be 1.0 when all ledger evidence is cited. Req 23.3."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(claim_id="CLM-001", supporting_evidence=["EV-001"]),
            _make_claim(claim_id="CLM-002", supporting_evidence=["EV-002"]),
        ]
        ledger = [
            _make_ledger_entry("EV-001"),
            _make_ledger_entry("EV-002"),
        ]

        rate = calc.calculate_evidence_coverage(claims, ledger)

        assert rate == 1.0

    def test_partial_evidence_cited(self) -> None:
        """Coverage should reflect proportion of cited evidence."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(claim_id="CLM-001", supporting_evidence=["EV-001"]),
        ]
        ledger = [
            _make_ledger_entry("EV-001"),
            _make_ledger_entry("EV-002"),
        ]

        rate = calc.calculate_evidence_coverage(claims, ledger)

        assert rate == 0.5

    def test_no_evidence_cited(self) -> None:
        """Coverage should be 0 when no ledger evidence is cited."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(claim_id="CLM-001", supporting_evidence=["EV-999"]),
        ]
        ledger = [
            _make_ledger_entry("EV-001"),
            _make_ledger_entry("EV-002"),
        ]

        rate = calc.calculate_evidence_coverage(claims, ledger)

        assert rate == 0.0

    def test_empty_ledger(self) -> None:
        """Coverage should be 0 when ledger is empty."""
        calc = QualityMetricsCalculator()
        claims = [_make_claim()]

        rate = calc.calculate_evidence_coverage(claims, [])

        assert rate == 0.0

    def test_counter_evidence_counts_as_cited(self) -> None:
        """Evidence in counter_evidence should also count as cited."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(
                claim_id="CLM-001",
                supporting_evidence=["EV-001"],
                counter_evidence=["EV-002"],
            ),
        ]
        ledger = [
            _make_ledger_entry("EV-001"),
            _make_ledger_entry("EV-002"),
        ]

        rate = calc.calculate_evidence_coverage(claims, ledger)

        assert rate == 1.0


class TestCriticalGapDispositionRate:
    """Tests for QualityMetricsCalculator.calculate_critical_gap_disposition_rate."""

    def test_all_critical_gaps_dispositioned(self) -> None:
        """Rate should be 1.0 when all critical gaps are dispositioned. Req 23.4."""
        calc = QualityMetricsCalculator()
        gaps = [
            _make_gap(gap_id="GAP-001", severity="critical", disposition="accepted_as_limitation"),
            _make_gap(gap_id="GAP-002", severity="critical", disposition="deferred_with_reason"),
        ]

        rate = calc.calculate_critical_gap_disposition_rate(gaps)

        assert rate == 1.0

    def test_no_critical_gaps_dispositioned(self) -> None:
        """Rate should be 0 when no critical gaps are dispositioned."""
        calc = QualityMetricsCalculator()
        gaps = [
            _make_gap(gap_id="GAP-001", severity="critical", disposition=None),
            _make_gap(gap_id="GAP-002", severity="critical", disposition=None),
        ]

        rate = calc.calculate_critical_gap_disposition_rate(gaps)

        assert rate == 0.0

    def test_partial_disposition(self) -> None:
        """Rate should reflect proportion of dispositioned critical gaps."""
        calc = QualityMetricsCalculator()
        gaps = [
            _make_gap(gap_id="GAP-001", severity="critical", disposition="accepted_as_limitation"),
            _make_gap(gap_id="GAP-002", severity="critical", disposition=None),
        ]

        rate = calc.calculate_critical_gap_disposition_rate(gaps)

        assert rate == 0.5

    def test_no_critical_gaps(self) -> None:
        """Rate should be 1.0 when there are no critical gaps."""
        calc = QualityMetricsCalculator()
        gaps = [
            _make_gap(gap_id="GAP-001", severity="major"),
            _make_gap(gap_id="GAP-002", severity="minor"),
        ]

        rate = calc.calculate_critical_gap_disposition_rate(gaps)

        assert rate == 1.0

    def test_empty_gaps_list(self) -> None:
        """Rate should be 1.0 for empty gaps list (no gaps = no issues)."""
        calc = QualityMetricsCalculator()

        rate = calc.calculate_critical_gap_disposition_rate([])

        assert rate == 1.0

    def test_non_critical_gaps_ignored(self) -> None:
        """Only critical gaps should be counted."""
        calc = QualityMetricsCalculator()
        gaps = [
            _make_gap(gap_id="GAP-001", severity="critical", disposition="accepted_as_limitation"),
            _make_gap(gap_id="GAP-002", severity="major", disposition=None),
            _make_gap(gap_id="GAP-003", severity="minor", disposition=None),
        ]

        rate = calc.calculate_critical_gap_disposition_rate(gaps)

        # Only one critical gap and it's dispositioned
        assert rate == 1.0


class TestLimitationCoverage:
    """Tests for QualityMetricsCalculator.calculate_limitation_coverage."""

    def test_all_limitations_covered(self) -> None:
        """Rate should be 1.0 when all limitations are in the report. Req 23.8."""
        calc = QualityMetricsCalculator()
        gaps = [
            _make_gap(
                gap_id="GAP-001",
                disposition="accepted_as_limitation",
                description="Missing firewall logs for host01",
            ),
        ]
        report_content = (
            "## Limitations\n"
            "The investigation has the following limitations:\n"
            "- GAP-001: Missing firewall logs for host01\n"
        )

        rate = calc.calculate_limitation_coverage(gaps, report_content)

        assert rate == 1.0

    def test_no_limitations_covered(self) -> None:
        """Rate should be 0 when limitations are not in the report."""
        calc = QualityMetricsCalculator()
        gaps = [
            _make_gap(
                gap_id="GAP-001",
                disposition="accepted_as_limitation",
                description="Missing completely unique XYZ data",
            ),
        ]
        report_content = "## Findings\nThe attack was confirmed."

        rate = calc.calculate_limitation_coverage(gaps, report_content)

        assert rate == 0.0

    def test_no_accepted_limitations(self) -> None:
        """Rate should be 1.0 when there are no accepted limitations."""
        calc = QualityMetricsCalculator()
        gaps = [
            _make_gap(gap_id="GAP-001", disposition="deferred_with_reason"),
        ]
        report_content = "## Report content"

        rate = calc.calculate_limitation_coverage(gaps, report_content)

        assert rate == 1.0

    def test_empty_gaps(self) -> None:
        """Rate should be 1.0 for empty gaps list."""
        calc = QualityMetricsCalculator()

        rate = calc.calculate_limitation_coverage([], "report content")

        assert rate == 1.0

    def test_limitation_covered_by_claim_reference(self) -> None:
        """Limitation is covered if claim_id appears with limitation context."""
        calc = QualityMetricsCalculator()
        gaps = [
            _make_gap(
                gap_id="GAP-001",
                disposition="accepted_as_limitation",
                description="Weak evidence for claim",
            ),
        ]
        # Report mentions the claim_id in a limitation context
        report_content = (
            "## 制約\n"
            "CLM-001 has a known limitation due to insufficient data.\n"
        )

        rate = calc.calculate_limitation_coverage(gaps, report_content)

        assert rate == 1.0


class TestCalculateAllMetrics:
    """Tests for QualityMetricsCalculator.calculate_all_metrics."""

    def test_returns_all_metrics(self) -> None:
        """calculate_all_metrics should return all five metric values."""
        calc = QualityMetricsCalculator()
        claims = [
            _make_claim(claim_id="CLM-001", supporting_evidence=["EV-001"]),
        ]
        ledger = [_make_ledger_entry("EV-001")]
        gaps = [
            _make_gap(severity="critical", disposition="accepted_as_limitation"),
        ]
        report_content = "GAP-001 is documented as a limitation."

        metrics = calc.calculate_all_metrics(claims, ledger, gaps, report_content)

        assert "unsupported_claim_rate" in metrics
        assert "overclaim_rate" in metrics
        assert "evidence_coverage" in metrics
        assert "critical_gap_disposition_rate" in metrics
        assert "limitation_coverage" in metrics
        assert all(0.0 <= v <= 1.0 for v in metrics.values())
