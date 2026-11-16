"""Property-based tests for Claims and Coverage.

**Validates: Requirements 8, 11, 14.4, 14.5, 16, 22**

Property 1: Evidence Traceability
- Every claim links to at least one evidence_id in the ledger

Property 5: Data Coverage Prerequisite
- not_observed claim is blocked when data source unavailable
- not_observed claim is allowed when source is available and analyzed

Property 3: Confidence Elevation with Basis
- interpretation_confidence never exceeds observed_fact_confidence without basis
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from ir_agent.analysis.claim_builder import ClaimBuilder
from ir_agent.analysis.coverage import DataCoverageService
from ir_agent.models.analysis import DataCoverageEntry, TimelineEntry
from ir_agent.models.base import SourceReference, TimeRange
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry
from ir_agent.steering.manifest import (
    ConfidenceExpressionPolicy,
    ExpressionPolicy,
    ExpressionRule,
)
from ir_agent.storage.store import AppendOnlyStore


# --- Strategies ---

confidence_st = st.sampled_from(list(ConfidenceLevel))

claim_category_st = st.sampled_from(list(ClaimCategory))

analyst_id_st = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_"),
    min_size=1,
    max_size=15,
)

short_text_st = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_"),
    min_size=1,
    max_size=30,
)

interpretation_text_st = st.text(
    alphabet=st.characters(whitelist_categories=("L", "Nd", "Zs"), whitelist_characters=".-_,"),
    min_size=3,
    max_size=80,
).filter(lambda s: s.strip() != "")

# Host name strategy (simple lowercase names)
host_st = st.text(
    alphabet=st.characters(whitelist_categories=("Ll",), whitelist_characters="-"),
    min_size=2,
    max_size=12,
).filter(lambda s: s.strip() != "" and not s.startswith("-") and not s.endswith("-"))

# Data source type from allowed values
data_source_type_st = st.sampled_from([
    "windows_event_log",
    "edr_telemetry",
    "network_flow",
    "firewall_log",
    "dns_log",
    "proxy_log",
])

# Availability status strategy
availability_status_st = st.sampled_from([
    "available",
    "partially_available",
    "unavailable",
    "outside_scope",
    "not_requested",
    "pending_collection",
    "unknown",
])


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


def _make_expression_policy() -> ExpressionPolicy:
    """Create a minimal ExpressionPolicy for testing."""
    default_rule = ExpressionRule(
        recommended_expressions=["possibly", "may have"],
        prohibited_expressions=["confirmed", "definitely"],
    )
    default_policy = ConfidenceExpressionPolicy(default=default_rule)
    return ExpressionPolicy(
        confirmed=default_policy,
        probable=default_policy,
        possible=default_policy,
        unknown=default_policy,
        not_observed=default_policy,
    )


@st.composite
def ledger_entry_st(draw, file_id: Optional[str] = None):
    """Strategy to generate a valid EvidenceLedgerEntry."""
    evidence_id = f"EV-{draw(short_text_st)}"
    observed_fact_conf = draw(confidence_st)
    interpretation_conf = draw(confidence_st)
    interpretation = draw(interpretation_text_st)
    fid = file_id or f"file-{draw(short_text_st)}"

    return EvidenceLedgerEntry(
        evidence_id=evidence_id,
        promoted_from=[f"cand-{uuid.uuid4().hex[:8]}"],
        approval_timestamp="2024-01-15T10:00:00+00:00",
        approved_by="analyst-01",
        source_refs=[_make_source_ref(fid)],
        observed_event={"type": "test_event", "host": "host01"},
        observed_fact="Test observed fact",
        interpretation=interpretation,
        observed_fact_confidence=observed_fact_conf,
        interpretation_confidence=interpretation_conf,
    )


@st.composite
def ledger_entries_unique_st(draw, min_size=1, max_size=8):
    """Strategy for a list of ledger entries with unique evidence_ids and unique interpretations."""
    n = draw(st.integers(min_value=min_size, max_value=max_size))
    entries = []
    used_ids = set()
    used_interpretations = set()
    for _ in range(n):
        entry = draw(ledger_entry_st())
        # Ensure unique evidence IDs
        while entry.evidence_id in used_ids:
            entry = draw(ledger_entry_st())
        # Ensure unique interpretations (so each forms its own claim)
        while entry.interpretation in used_interpretations:
            entry = draw(ledger_entry_st())
        used_ids.add(entry.evidence_id)
        used_interpretations.add(entry.interpretation)
        entries.append(entry)
    return entries


# --- Property 1: Evidence Traceability ---


class TestEvidenceTraceability:
    """Property 1: Evidence Traceability.

    **Validates: Requirements 8, 11, 16**

    Every Claim generated by ClaimBuilder MUST link to at least one
    evidence_id that exists in the Evidence Ledger.
    """

    @given(
        entries=ledger_entries_unique_st(min_size=1, max_size=6),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.large_base_example])
    def test_every_claim_links_to_at_least_one_evidence_id(
        self,
        entries: list[EvidenceLedgerEntry],
    ):
        """For any non-empty set of ledger entries, every generated claim
        has at least one supporting_evidence entry.

        **Validates: Requirements 8, 11, 16**
        """
        builder = ClaimBuilder()
        policy = _make_expression_policy()
        coverage: list[DataCoverageEntry] = []
        timeline: list[TimelineEntry] = []

        claims = builder.build_claims(entries, timeline, policy, coverage)

        # Every generated claim must have at least one supporting evidence_id
        for claim in claims:
            assert len(claim.supporting_evidence) >= 1, (
                f"Claim {claim.claim_id} has no supporting evidence: "
                f"supporting_evidence={claim.supporting_evidence}"
            )

    @given(
        entries=ledger_entries_unique_st(min_size=1, max_size=6),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.large_base_example])
    def test_all_claim_evidence_ids_exist_in_ledger(
        self,
        entries: list[EvidenceLedgerEntry],
    ):
        """Every evidence_id referenced by a claim MUST exist in the
        provided ledger entries.

        **Validates: Requirements 8, 11, 16**
        """
        builder = ClaimBuilder()
        policy = _make_expression_policy()
        coverage: list[DataCoverageEntry] = []
        timeline: list[TimelineEntry] = []

        claims = builder.build_claims(entries, timeline, policy, coverage)

        # Collect all evidence_ids from the ledger
        ledger_ids = {e.evidence_id for e in entries}

        for claim in claims:
            for eid in claim.supporting_evidence:
                assert eid in ledger_ids, (
                    f"Claim {claim.claim_id} references evidence_id '{eid}' "
                    f"that does not exist in the ledger. "
                    f"Ledger IDs: {ledger_ids}"
                )

    @given(
        entries=ledger_entries_unique_st(min_size=1, max_size=6),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.large_base_example])
    def test_no_claims_generated_from_empty_ledger(
        self,
        entries: list[EvidenceLedgerEntry],
    ):
        """When all entries are withdrawn, no claims should be generated
        (as there is no active evidence to link to).

        **Validates: Requirements 8, 11, 16**
        """
        # Mark all entries as withdrawn
        withdrawn_entries = []
        for entry in entries:
            withdrawn_entry = entry.model_copy(update={"withdrawn": True})
            withdrawn_entries.append(withdrawn_entry)

        builder = ClaimBuilder()
        policy = _make_expression_policy()
        coverage: list[DataCoverageEntry] = []
        timeline: list[TimelineEntry] = []

        claims = builder.build_claims(withdrawn_entries, timeline, policy, coverage)

        assert len(claims) == 0, (
            f"Expected no claims from all-withdrawn ledger, got {len(claims)}"
        )


# --- Property 5: Data Coverage Prerequisite ---


class TestDataCoveragePrerequisite:
    """Property 5: Data Coverage Prerequisite.

    **Validates: Requirements 14.4, 14.5**

    - not_observed claim is blocked when data source is unavailable
    - not_observed claim is allowed when source is available and analyzed
    """

    @given(
        host=host_st,
        ds_type=data_source_type_st,
        unavailable_status=st.sampled_from([
            "unavailable",
            "partially_available",
            "outside_scope",
            "not_requested",
            "pending_collection",
            "unknown",
        ]),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.large_base_example])
    def test_not_observed_blocked_when_source_unavailable(
        self,
        host: str,
        ds_type: str,
        unavailable_status: str,
        tmp_path_factory,
    ):
        """can_support_not_observed returns False when the data source
        availability status is anything other than 'available'.

        A not_observed claim MUST NOT be generated when the relevant
        data source is unavailable.

        **Validates: Requirements 14.4, 14.5**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_coverage_blocked")
        store_path = tmp_dir / "data" / "data_coverage.jsonl"
        store = AppendOnlyStore(file_path=store_path, model_class=DataCoverageEntry)
        service = DataCoverageService(store=store)

        time_range = TimeRange(
            start="2024-01-01T00:00:00+00:00",
            end="2024-01-31T23:59:59+00:00",
        )

        # Create a coverage entry with non-available status
        entry = DataCoverageEntry(
            data_source_id=f"DC-{host}-{ds_type}",
            host_or_system=host,
            data_source_type=ds_type,
            availability_status=unavailable_status,
            covered_time_range=time_range,
            collection_time=None,
            known_gaps=[],
            reason_for_unavailability="Test unavailability",
            impact_on_findings=None,
        )
        store.append(entry)

        # Even if we mark it analyzed, it should still return False
        # because availability is not 'available'
        service.mark_analyzed(entry.data_source_id, time_range)

        result = service.can_support_not_observed(host, ds_type, time_range)

        assert result is False, (
            f"can_support_not_observed returned True for status='{unavailable_status}'. "
            f"not_observed claims must be blocked when data source is not 'available'."
        )

    @given(
        host=host_st,
        ds_type=data_source_type_st,
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.large_base_example])
    def test_not_observed_blocked_when_source_available_but_not_analyzed(
        self,
        host: str,
        ds_type: str,
        tmp_path_factory,
    ):
        """can_support_not_observed returns False when the data source
        is available but has NOT been analyzed for the time range.

        Both conditions (available AND analyzed) must be met.

        **Validates: Requirements 14.4, 14.5**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_coverage_not_analyzed")
        store_path = tmp_dir / "data" / "data_coverage.jsonl"
        store = AppendOnlyStore(file_path=store_path, model_class=DataCoverageEntry)
        service = DataCoverageService(store=store)

        time_range = TimeRange(
            start="2024-01-01T00:00:00+00:00",
            end="2024-01-31T23:59:59+00:00",
        )

        # Create a coverage entry that IS available
        entry = DataCoverageEntry(
            data_source_id=f"DC-{host}-{ds_type}",
            host_or_system=host,
            data_source_type=ds_type,
            availability_status="available",
            covered_time_range=time_range,
            collection_time=None,
            known_gaps=[],
            reason_for_unavailability=None,
            impact_on_findings=None,
        )
        store.append(entry)

        # Do NOT call mark_analyzed — source is available but not analyzed
        result = service.can_support_not_observed(host, ds_type, time_range)

        assert result is False, (
            f"can_support_not_observed returned True for available but un-analyzed source. "
            f"Both availability AND analysis are required for not_observed claims."
        )

    @given(
        host=host_st,
        ds_type=data_source_type_st,
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.large_base_example])
    def test_not_observed_allowed_when_source_available_and_analyzed(
        self,
        host: str,
        ds_type: str,
        tmp_path_factory,
    ):
        """can_support_not_observed returns True when the data source
        is 'available' AND has been analyzed for the relevant time range.

        **Validates: Requirements 14.4, 14.5**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_coverage_allowed")
        store_path = tmp_dir / "data" / "data_coverage.jsonl"
        store = AppendOnlyStore(file_path=store_path, model_class=DataCoverageEntry)
        service = DataCoverageService(store=store)

        time_range = TimeRange(
            start="2024-01-01T00:00:00+00:00",
            end="2024-01-31T23:59:59+00:00",
        )

        # Create a coverage entry that IS available
        entry = DataCoverageEntry(
            data_source_id=f"DC-{host}-{ds_type}",
            host_or_system=host,
            data_source_type=ds_type,
            availability_status="available",
            covered_time_range=time_range,
            collection_time=None,
            known_gaps=[],
            reason_for_unavailability=None,
            impact_on_findings=None,
        )
        store.append(entry)

        # Mark as analyzed for the full time range
        service.mark_analyzed(entry.data_source_id, time_range)

        result = service.can_support_not_observed(host, ds_type, time_range)

        assert result is True, (
            f"can_support_not_observed returned False for available and analyzed source. "
            f"host={host}, ds_type={ds_type}, status='available', analyzed=True"
        )

    @given(
        host=host_st,
        ds_type=data_source_type_st,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.large_base_example])
    def test_not_observed_blocked_when_no_coverage_entry_exists(
        self,
        host: str,
        ds_type: str,
        tmp_path_factory,
    ):
        """can_support_not_observed returns False when there is no
        coverage entry at all for the given host/type.

        **Validates: Requirements 14.4, 14.5**
        """
        tmp_dir = tmp_path_factory.mktemp("prop_coverage_missing")
        store_path = tmp_dir / "data" / "data_coverage.jsonl"
        store = AppendOnlyStore(file_path=store_path, model_class=DataCoverageEntry)
        service = DataCoverageService(store=store)

        time_range = TimeRange(
            start="2024-01-01T00:00:00+00:00",
            end="2024-01-31T23:59:59+00:00",
        )

        # Empty store — no coverage entries
        result = service.can_support_not_observed(host, ds_type, time_range)

        assert result is False, (
            f"can_support_not_observed returned True with no coverage entries. "
            f"Cannot assert 'not observed' without coverage data."
        )


# --- Property 3: Confidence Elevation with Basis ---


class TestConfidenceElevationWithBasis:
    """Property 3: Confidence Elevation with Basis.

    **Validates: Requirements 8, 11, 22**

    interpretation_confidence of a Claim never exceeds
    the interpretation_confidence of the weakest single supporting evidence
    item WITHOUT the confidence_basis recording the elevation rationale.
    """

    @given(
        entries=ledger_entries_unique_st(min_size=1, max_size=6),
        category=claim_category_st,
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.large_base_example])
    def test_elevation_always_documented_in_basis(
        self,
        entries: list[EvidenceLedgerEntry],
        category: ClaimCategory,
    ):
        """When claim confidence exceeds the weakest single supporting
        evidence interpretation_confidence, the confidence_basis MUST
        contain an elevation explanation.

        **Validates: Requirements 8, 11, 22**
        """
        builder = ClaimBuilder()
        counter: list[EvidenceLedgerEntry] = []
        coverage: list[DataCoverageEntry] = []

        confidence_level, basis = builder.calculate_confidence(
            claim_category=category,
            supporting=entries,
            counter=counter,
            coverage=coverage,
        )

        # Find the weakest interpretation confidence among supporting evidence
        confidence_order = {
            ConfidenceLevel.CONFIRMED: 4,
            ConfidenceLevel.PROBABLE: 3,
            ConfidenceLevel.POSSIBLE: 2,
            ConfidenceLevel.UNKNOWN: 1,
            ConfidenceLevel.NOT_OBSERVED: 0,
        }

        min_interp_score = min(
            confidence_order[e.interpretation_confidence] for e in entries
        )
        claim_score = confidence_order[confidence_level]

        # If claim confidence exceeds weakest single evidence, basis must document it
        if claim_score > min_interp_score:
            assert "ELEVATION" in basis or "elevation" in basis.lower(), (
                f"Claim confidence ({confidence_level.value}, score={claim_score}) "
                f"exceeds weakest evidence interpretation confidence "
                f"(score={min_interp_score}) but confidence_basis does not "
                f"document the elevation. Basis: '{basis}'"
            )

    @given(
        entries=ledger_entries_unique_st(min_size=1, max_size=6),
        category=claim_category_st,
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.large_base_example])
    def test_confidence_basis_always_non_empty(
        self,
        entries: list[EvidenceLedgerEntry],
        category: ClaimCategory,
    ):
        """The confidence_basis explanation is always non-empty, providing
        transparency on how confidence was determined.

        **Validates: Requirements 8, 11, 22**
        """
        builder = ClaimBuilder()
        counter: list[EvidenceLedgerEntry] = []
        coverage: list[DataCoverageEntry] = []

        _, basis = builder.calculate_confidence(
            claim_category=category,
            supporting=entries,
            counter=counter,
            coverage=coverage,
        )

        assert len(basis) > 0, (
            "confidence_basis must always be non-empty to explain "
            "how the confidence level was determined."
        )

    @given(
        entries=ledger_entries_unique_st(min_size=1, max_size=6),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.large_base_example])
    def test_claims_from_build_have_elevation_documented(
        self,
        entries: list[EvidenceLedgerEntry],
    ):
        """When build_claims produces a claim with elevated confidence,
        the confidence_basis in the claim itself documents the elevation.

        **Validates: Requirements 8, 11, 22**
        """
        builder = ClaimBuilder()
        policy = _make_expression_policy()
        coverage: list[DataCoverageEntry] = []
        timeline: list[TimelineEntry] = []

        claims = builder.build_claims(entries, timeline, policy, coverage)

        confidence_order = {
            ConfidenceLevel.CONFIRMED: 4,
            ConfidenceLevel.PROBABLE: 3,
            ConfidenceLevel.POSSIBLE: 2,
            ConfidenceLevel.UNKNOWN: 1,
            ConfidenceLevel.NOT_OBSERVED: 0,
        }

        for claim in claims:
            # Find supporting evidence for this claim
            supporting_entries = [
                e for e in entries if e.evidence_id in claim.supporting_evidence
            ]
            if not supporting_entries:
                continue

            min_interp_score = min(
                confidence_order[e.interpretation_confidence]
                for e in supporting_entries
            )
            claim_score = confidence_order[claim.confidence_level]

            if claim_score > min_interp_score:
                assert "ELEVATION" in claim.confidence_basis or "elevation" in claim.confidence_basis.lower(), (
                    f"Claim {claim.claim_id} has confidence "
                    f"({claim.confidence_level.value}, score={claim_score}) "
                    f"exceeding weakest supporting evidence "
                    f"(score={min_interp_score}) but confidence_basis "
                    f"lacks elevation documentation. "
                    f"Basis: '{claim.confidence_basis}'"
                )
