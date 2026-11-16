"""Unit tests for GapChecker.

Tests gap identification, contradiction detection, overclaim detection,
and critical gap resolution checking.

Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.8
"""

import pytest

from ir_agent.analysis.gap_checker import GapChecker
from ir_agent.models.analysis import Claim, DataCoverageEntry, Gap
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel


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
) -> Claim:
    """Helper to create a Claim for testing."""
    return Claim(
        claim_id=claim_id,
        report_section=report_section,
        claim_text=claim_text,
        claim_category=claim_category,
        confidence_level=confidence_level,
        confidence_basis="Test basis",
        supporting_evidence=supporting_evidence or ["EV-001"],
        counter_evidence=counter_evidence or [],
        limitations=limitations or [],
        missing_evidence=missing_evidence or [],
    )


def _make_coverage(
    data_source_id: str = "DC-host01-firewall_log",
    host_or_system: str = "host01",
    data_source_type: str = "firewall_log",
    availability_status: str = "available",
    reason_for_unavailability: str | None = None,
    impact_on_findings: str | None = None,
) -> DataCoverageEntry:
    """Helper to create a DataCoverageEntry for testing."""
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


class TestCheckGaps:
    """Tests for check_gaps method."""

    def test_no_gaps_for_well_supported_claim(self):
        """A claim with sufficient evidence and no issues produces no gaps."""
        checker = GapChecker()
        claim = _make_claim(
            confidence_level=ConfidenceLevel.PROBABLE,
            supporting_evidence=["EV-001", "EV-002"],
        )
        coverage = [_make_coverage()]

        gaps = checker.check_gaps([claim], coverage)

        assert len(gaps) == 0

    def test_missing_evidence_creates_gap(self):
        """Claims with missing_evidence field populated produce a gap."""
        checker = GapChecker()
        claim = _make_claim(
            missing_evidence=["firewall_log from host01 (unavailable)"],
        )
        coverage = []

        gaps = checker.check_gaps([claim], coverage)

        missing_gaps = [g for g in gaps if g.gap_type == "missing_evidence"]
        assert len(missing_gaps) == 1
        assert "missing evidence" in missing_gaps[0].description.lower() or "missing" in missing_gaps[0].description.lower()

    def test_weak_evidence_for_confirmed_claim(self):
        """A CONFIRMED claim with only one evidence item is flagged as weak."""
        checker = GapChecker()
        claim = _make_claim(
            confidence_level=ConfidenceLevel.CONFIRMED,
            supporting_evidence=["EV-001"],
        )
        coverage = []

        gaps = checker.check_gaps([claim], coverage)

        weak_gaps = [g for g in gaps if g.gap_type == "weak_evidence"]
        assert len(weak_gaps) >= 1

    def test_single_source_gap_for_probable_claim(self):
        """A PROBABLE claim with one evidence item is flagged as single-source."""
        checker = GapChecker()
        claim = _make_claim(
            confidence_level=ConfidenceLevel.PROBABLE,
            supporting_evidence=["EV-001"],
        )
        coverage = []

        gaps = checker.check_gaps([claim], coverage)

        single_source_gaps = [g for g in gaps if g.gap_type == "single_source"]
        assert len(single_source_gaps) == 1

    def test_unavailable_logs_gap(self):
        """Unavailable data source relevant to claim creates a gap."""
        checker = GapChecker()
        claim = _make_claim(
            claim_text="Lateral movement detected on host01",
            missing_evidence=["firewall_log from host01 (unavailable)"],
        )
        coverage = [
            _make_coverage(
                availability_status="unavailable",
                reason_for_unavailability="Disk failure",
                impact_on_findings="Cannot verify network connections",
            )
        ]

        gaps = checker.check_gaps([claim], coverage)

        unavailable_gaps = [g for g in gaps if g.gap_type == "unavailable_logs"]
        assert len(unavailable_gaps) >= 1
        assert "unavailable" in unavailable_gaps[0].description.lower()

    def test_logs_outside_scope_gap(self):
        """Data sources outside scope create a gap when relevant."""
        checker = GapChecker()
        claim = _make_claim(
            claim_text="Activity detected on host01",
        )
        coverage = [
            _make_coverage(
                availability_status="outside_scope",
            )
        ]

        gaps = checker.check_gaps([claim], coverage)

        scope_gaps = [g for g in gaps if g.gap_type == "logs_outside_scope"]
        assert len(scope_gaps) >= 1

    def test_logs_not_analyzed_gap(self):
        """Pending/unknown data sources create a logs_not_analyzed gap."""
        checker = GapChecker()
        claim = _make_claim(
            claim_text="Events on host01 indicate compromise",
            missing_evidence=["edr_telemetry from host01 (pending_collection)"],
        )
        coverage = [
            _make_coverage(
                data_source_id="DC-host01-edr_telemetry",
                data_source_type="edr_telemetry",
                availability_status="pending_collection",
            )
        ]

        gaps = checker.check_gaps([claim], coverage)

        not_analyzed_gaps = [g for g in gaps if g.gap_type == "logs_not_analyzed"]
        assert len(not_analyzed_gaps) >= 1

    def test_contradictory_evidence_gap(self):
        """Claims with counter-evidence produce a contradictory_evidence gap."""
        checker = GapChecker()
        claim = _make_claim(
            confidence_level=ConfidenceLevel.PROBABLE,
            counter_evidence=["EV-010", "EV-011"],
        )
        coverage = []

        gaps = checker.check_gaps([claim], coverage)

        contradiction_gaps = [g for g in gaps if g.gap_type == "contradictory_evidence"]
        assert len(contradiction_gaps) == 1
        assert "counter-evidence" in contradiction_gaps[0].description.lower()

    def test_gap_has_required_fields(self):
        """Each gap record contains all required fields."""
        checker = GapChecker()
        claim = _make_claim(
            confidence_level=ConfidenceLevel.CONFIRMED,
            supporting_evidence=["EV-001"],
            missing_evidence=["dns_log from host01"],
        )
        coverage = []

        gaps = checker.check_gaps([claim], coverage)

        for gap in gaps:
            assert gap.gap_id.startswith("GAP-")
            assert gap.related_claim_id == claim.claim_id
            assert gap.gap_type in (
                "missing_evidence", "weak_evidence", "single_source",
                "unavailable_logs", "logs_outside_scope",
                "logs_not_analyzed", "contradictory_evidence",
            )
            assert gap.severity in ("critical", "major", "minor")
            assert gap.description
            assert gap.recommended_action


class TestDetectContradictions:
    """Tests for detect_contradictions method."""

    def test_no_contradictions_for_consistent_claims(self):
        """Consistent claims produce no contradictions."""
        checker = GapChecker()
        claims = [
            _make_claim(claim_id="CLM-001", claim_text="File was accessed"),
            _make_claim(claim_id="CLM-002", claim_text="Network traffic observed"),
        ]

        contradictions = checker.detect_contradictions(claims)

        assert len(contradictions) == 0

    def test_detects_evidence_based_contradiction(self):
        """Finds contradiction when evidence supports one claim but counters another."""
        checker = GapChecker()
        claims = [
            _make_claim(
                claim_id="CLM-001",
                supporting_evidence=["EV-001", "EV-002"],
                counter_evidence=[],
            ),
            _make_claim(
                claim_id="CLM-002",
                supporting_evidence=["EV-003"],
                counter_evidence=["EV-001"],
            ),
        ]

        contradictions = checker.detect_contradictions(claims)

        assert len(contradictions) == 1
        assert contradictions[0]["claim_id_a"] == "CLM-001"
        assert contradictions[0]["claim_id_b"] == "CLM-002"
        assert "EV-001" in contradictions[0]["conflicting_evidence"]

    def test_detects_textual_contradiction_in_same_section(self):
        """Finds contradiction when claim texts are opposing in same section."""
        checker = GapChecker()
        claims = [
            _make_claim(
                claim_id="CLM-001",
                claim_text="The system was compromised via phishing",
                report_section="intrusion_vector",
            ),
            _make_claim(
                claim_id="CLM-002",
                claim_text="The system was not compromised",
                report_section="intrusion_vector",
            ),
        ]

        contradictions = checker.detect_contradictions(claims)

        assert len(contradictions) >= 1

    def test_no_contradiction_for_different_sections(self):
        """Claims in different sections with opposing text are not contradictions."""
        checker = GapChecker()
        claims = [
            _make_claim(
                claim_id="CLM-001",
                claim_text="System was compromised",
                report_section="findings",
            ),
            _make_claim(
                claim_id="CLM-002",
                claim_text="System was not compromised",
                report_section="attribution",
            ),
        ]

        contradictions = checker.detect_contradictions(claims)

        # No contradiction since different sections (different subjects)
        assert len(contradictions) == 0


class TestDetectOverclaims:
    """Tests for detect_overclaims method."""

    def test_confirmed_with_single_evidence_is_overclaim(self):
        """A CONFIRMED claim with single evidence is an overclaim."""
        checker = GapChecker()
        claims = [
            _make_claim(
                confidence_level=ConfidenceLevel.CONFIRMED,
                supporting_evidence=["EV-001"],
            )
        ]

        overclaims = checker.detect_overclaims(claims)

        assert len(overclaims) == 1

    def test_probable_with_multiple_evidence_is_not_overclaim(self):
        """A PROBABLE claim with multiple evidence is not an overclaim."""
        checker = GapChecker()
        claims = [
            _make_claim(
                confidence_level=ConfidenceLevel.PROBABLE,
                supporting_evidence=["EV-001", "EV-002"],
            )
        ]

        overclaims = checker.detect_overclaims(claims)

        assert len(overclaims) == 0

    def test_high_threshold_category_with_single_evidence(self):
        """High-threshold category with single evidence at PROBABLE is an overclaim."""
        checker = GapChecker()
        claims = [
            _make_claim(
                confidence_level=ConfidenceLevel.PROBABLE,
                claim_category=ClaimCategory.ATTRIBUTION_ASSESSMENT,
                supporting_evidence=["EV-001"],
            )
        ]

        overclaims = checker.detect_overclaims(claims)

        assert len(overclaims) == 1

    def test_confirmed_with_counter_evidence_is_overclaim(self):
        """A CONFIRMED claim with counter-evidence is an overclaim."""
        checker = GapChecker()
        claims = [
            _make_claim(
                confidence_level=ConfidenceLevel.CONFIRMED,
                supporting_evidence=["EV-001", "EV-002", "EV-003"],
                counter_evidence=["EV-010"],
            )
        ]

        overclaims = checker.detect_overclaims(claims)

        assert len(overclaims) == 1

    def test_possible_claim_is_not_overclaim(self):
        """A POSSIBLE claim with single evidence is not an overclaim."""
        checker = GapChecker()
        claims = [
            _make_claim(
                confidence_level=ConfidenceLevel.POSSIBLE,
                supporting_evidence=["EV-001"],
            )
        ]

        overclaims = checker.detect_overclaims(claims)

        assert len(overclaims) == 0


class TestHasUnresolvedCriticalGaps:
    """Tests for has_unresolved_critical_gaps method."""

    def test_no_gaps_returns_false(self):
        """Empty gap list returns False."""
        checker = GapChecker()
        assert checker.has_unresolved_critical_gaps([]) is False

    def test_critical_gap_without_disposition_returns_true(self):
        """Critical gap without disposition returns True."""
        checker = GapChecker()
        gaps = [
            Gap(
                gap_id="GAP-001",
                related_claim_id="CLM-001",
                gap_type="missing_evidence",
                severity="critical",
                description="Critical evidence missing",
                recommended_action="Collect evidence",
                disposition=None,
            )
        ]

        assert checker.has_unresolved_critical_gaps(gaps) is True

    def test_critical_gap_with_disposition_returns_false(self):
        """Critical gap with disposition returns False."""
        checker = GapChecker()
        gaps = [
            Gap(
                gap_id="GAP-001",
                related_claim_id="CLM-001",
                gap_type="missing_evidence",
                severity="critical",
                description="Critical evidence missing",
                recommended_action="Collect evidence",
                disposition="accepted_as_limitation",
                disposition_reason="Logs were destroyed",
                dispositioned_by="analyst01",
            )
        ]

        assert checker.has_unresolved_critical_gaps(gaps) is False

    def test_major_gap_without_disposition_returns_false(self):
        """Major (non-critical) gap without disposition returns False."""
        checker = GapChecker()
        gaps = [
            Gap(
                gap_id="GAP-001",
                related_claim_id="CLM-001",
                gap_type="weak_evidence",
                severity="major",
                description="Weak evidence",
                recommended_action="Collect more",
                disposition=None,
            )
        ]

        assert checker.has_unresolved_critical_gaps(gaps) is False

    def test_mixed_gaps_with_undispositioned_critical(self):
        """Mix of gaps where one critical is undispositioned returns True."""
        checker = GapChecker()
        gaps = [
            Gap(
                gap_id="GAP-001",
                related_claim_id="CLM-001",
                gap_type="weak_evidence",
                severity="major",
                description="Weak evidence",
                recommended_action="Collect more",
                disposition=None,
            ),
            Gap(
                gap_id="GAP-002",
                related_claim_id="CLM-002",
                gap_type="missing_evidence",
                severity="critical",
                description="Missing critical evidence",
                recommended_action="Obtain logs",
                disposition=None,
            ),
            Gap(
                gap_id="GAP-003",
                related_claim_id="CLM-003",
                gap_type="single_source",
                severity="critical",
                description="Single source critical",
                recommended_action="Corroborate",
                disposition="mitigated_by_claim_downgrade",
                disposition_reason="Downgraded to possible",
                dispositioned_by="analyst01",
            ),
        ]

        assert checker.has_unresolved_critical_gaps(gaps) is True

    def test_all_critical_gaps_dispositioned_returns_false(self):
        """All critical gaps dispositioned returns False."""
        checker = GapChecker()
        gaps = [
            Gap(
                gap_id="GAP-001",
                related_claim_id="CLM-001",
                gap_type="missing_evidence",
                severity="critical",
                description="Critical gap 1",
                recommended_action="Collect",
                disposition="accepted_as_limitation",
                disposition_reason="Documented",
                dispositioned_by="analyst01",
            ),
            Gap(
                gap_id="GAP-002",
                related_claim_id="CLM-002",
                gap_type="unavailable_logs",
                severity="critical",
                description="Critical gap 2",
                recommended_action="Obtain",
                disposition="deferred_with_reason",
                disposition_reason="Pending court order",
                dispositioned_by="analyst01",
            ),
        ]

        assert checker.has_unresolved_critical_gaps(gaps) is False


class TestGapTypes:
    """Tests that all required gap types are supported."""

    def test_all_gap_types_can_be_produced(self):
        """Verify all required gap types can be generated by the checker."""
        checker = GapChecker()

        # missing_evidence
        claim_missing = _make_claim(
            claim_id="CLM-ME",
            missing_evidence=["dns_log from host01"],
        )
        gaps_missing = checker.check_gaps([claim_missing], [])
        assert any(g.gap_type == "missing_evidence" for g in gaps_missing)

        # weak_evidence
        claim_weak = _make_claim(
            claim_id="CLM-WE",
            confidence_level=ConfidenceLevel.CONFIRMED,
            supporting_evidence=["EV-001"],
        )
        gaps_weak = checker.check_gaps([claim_weak], [])
        assert any(g.gap_type == "weak_evidence" for g in gaps_weak)

        # single_source
        claim_single = _make_claim(
            claim_id="CLM-SS",
            confidence_level=ConfidenceLevel.PROBABLE,
            supporting_evidence=["EV-001"],
        )
        gaps_single = checker.check_gaps([claim_single], [])
        assert any(g.gap_type == "single_source" for g in gaps_single)

        # unavailable_logs
        claim_unavail = _make_claim(
            claim_id="CLM-UL",
            claim_text="Activity on host01",
        )
        coverage_unavail = [
            _make_coverage(availability_status="unavailable"),
        ]
        gaps_unavail = checker.check_gaps([claim_unavail], coverage_unavail)
        assert any(g.gap_type == "unavailable_logs" for g in gaps_unavail)

        # logs_outside_scope
        claim_scope = _make_claim(
            claim_id="CLM-OS",
            claim_text="Events on host01",
        )
        coverage_scope = [
            _make_coverage(availability_status="outside_scope"),
        ]
        gaps_scope = checker.check_gaps([claim_scope], coverage_scope)
        assert any(g.gap_type == "logs_outside_scope" for g in gaps_scope)

        # logs_not_analyzed
        claim_na = _make_claim(
            claim_id="CLM-NA",
            claim_text="Compromise on host01",
            missing_evidence=["firewall_log from host01"],
        )
        coverage_na = [
            _make_coverage(availability_status="pending_collection"),
        ]
        gaps_na = checker.check_gaps([claim_na], coverage_na)
        assert any(g.gap_type == "logs_not_analyzed" for g in gaps_na)

        # contradictory_evidence
        claim_contra = _make_claim(
            claim_id="CLM-CE",
            counter_evidence=["EV-010"],
        )
        gaps_contra = checker.check_gaps([claim_contra], [])
        assert any(g.gap_type == "contradictory_evidence" for g in gaps_contra)
