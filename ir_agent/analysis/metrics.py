"""Quality Metrics Calculator for the Analysis Layer.

Computes quality metrics for generated reports to help analysts assess
report reliability before finalizing. Metrics measure evidence coverage,
claim grounding, and gap resolution completeness.

Requirements: 23.1, 23.2, 23.3, 23.4, 23.8
"""

from __future__ import annotations

import logging
from typing import Optional

from ir_agent.models.analysis import Claim, DataCoverageEntry, Gap
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry

logger = logging.getLogger(__name__)

# Confidence level ordering for overclaim detection
_CONFIDENCE_ORDER: dict[ConfidenceLevel, int] = {
    ConfidenceLevel.CONFIRMED: 4,
    ConfidenceLevel.PROBABLE: 3,
    ConfidenceLevel.POSSIBLE: 2,
    ConfidenceLevel.UNKNOWN: 1,
    ConfidenceLevel.NOT_OBSERVED: 0,
}


class QualityMetricsCalculator:
    """Calculates quality metrics for IR reports.

    Computes the following metrics:
    - Unsupported Claim Rate: % of claims without linked evidence
    - Overclaim Rate: % of claims where assertion confidence exceeds evidence
    - Evidence Coverage: % of ledger evidence cited in at least one claim
    - Critical Gap Disposition Rate: % of critical gaps that are addressed
    - Limitation Coverage: % of accepted limitations described in the report

    These metrics are presented alongside the draft report to help the
    analyst assess report reliability.

    Requirements: 23.1, 23.2, 23.3, 23.4, 23.8
    """

    def calculate_unsupported_claim_rate(
        self, claims: list[Claim]
    ) -> float:
        """Calculate the percentage of claims without linked evidence.

        A claim is unsupported if its supporting_evidence list is empty.
        Only approved or pending claims are considered (rejected claims
        are excluded from the calculation).

        Requirement 23.1: Calculate the Unsupported Claim Rate (percentage
        of claims without linked evidence).

        Args:
            claims: List of claims to evaluate.

        Returns:
            Rate as a float between 0.0 and 1.0. Returns 0.0 if no
            relevant claims exist.
        """
        relevant_claims = [
            c for c in claims if c.review_status != "rejected"
        ]

        if not relevant_claims:
            return 0.0

        unsupported_count = sum(
            1 for c in relevant_claims if not c.supporting_evidence
        )

        return unsupported_count / len(relevant_claims)

    def calculate_overclaim_rate(self, claims: list[Claim]) -> float:
        """Calculate the percentage of claims where assertion confidence
        exceeds evidence confidence.

        An overclaim occurs when a claim's confidence_level is higher
        than what the supporting evidence warrants. This is detected when:
        - A CONFIRMED claim has only one supporting evidence item
        - A claim has counter-evidence but maintains high confidence
        - A claim's confidence exceeds PROBABLE with single-source support

        Requirement 23.2: Calculate the Overclaim Rate (percentage of claims
        where assertion confidence exceeds evidence confidence).

        Args:
            claims: List of claims to evaluate.

        Returns:
            Rate as a float between 0.0 and 1.0. Returns 0.0 if no
            relevant claims exist.
        """
        relevant_claims = [
            c for c in claims if c.review_status != "rejected"
        ]

        if not relevant_claims:
            return 0.0

        overclaim_count = sum(
            1 for c in relevant_claims if self._is_overclaim(c)
        )

        return overclaim_count / len(relevant_claims)

    def calculate_evidence_coverage(
        self,
        claims: list[Claim],
        ledger: list[EvidenceLedgerEntry],
    ) -> float:
        """Calculate the percentage of ledger evidence cited in claims.

        Measures how much of the approved evidence base is actually
        used in claims. High evidence coverage indicates the report
        comprehensively addresses available evidence.

        Requirement 23.3: Calculate Evidence Coverage (percentage of ledger
        evidence cited in at least one claim).

        Args:
            claims: List of claims (including their evidence references).
            ledger: List of active evidence ledger entries.

        Returns:
            Rate as a float between 0.0 and 1.0. Returns 0.0 if the
            ledger is empty.
        """
        if not ledger:
            return 0.0

        # Collect all evidence IDs referenced by non-rejected claims
        cited_evidence_ids: set[str] = set()
        for claim in claims:
            if claim.review_status != "rejected":
                cited_evidence_ids.update(claim.supporting_evidence)
                cited_evidence_ids.update(claim.counter_evidence)

        # Count how many ledger entries are cited
        ledger_ids = {entry.evidence_id for entry in ledger}
        cited_count = len(cited_evidence_ids & ledger_ids)

        return cited_count / len(ledger_ids)

    def calculate_critical_gap_disposition_rate(
        self, gaps: list[Gap]
    ) -> float:
        """Calculate the rate of critical gaps that have been dispositioned.

        Measures what fraction of critical-severity gaps have been
        addressed (any disposition counts: accepted_as_limitation,
        mitigated_by_claim_downgrade, addressed_by_additional_evidence,
        out_of_scope_with_analyst_approval, deferred_with_reason).

        Requirement 23.4: Calculate Critical Gap Disposition Rate:
        number of critical gaps addressed / total critical gaps.

        Args:
            gaps: List of gap records.

        Returns:
            Rate as a float between 0.0 and 1.0. Returns 1.0 if no
            critical gaps exist (all gaps are resolved by default).
        """
        critical_gaps = [g for g in gaps if g.severity == "critical"]

        if not critical_gaps:
            return 1.0

        dispositioned_count = sum(
            1 for g in critical_gaps if g.disposition is not None
        )

        return dispositioned_count / len(critical_gaps)

    def calculate_limitation_coverage(
        self,
        gaps: list[Gap],
        report_content: str,
    ) -> float:
        """Calculate the percentage of accepted limitations described in the report.

        Measures whether all gaps accepted as limitations are actually
        documented in the report text. Checks for the presence of gap
        descriptions or related claim references in the report content.

        Requirement 23.8: Calculate Limitation Coverage: number of accepted
        limitations described in the report / total accepted limitations.

        Args:
            gaps: List of gap records.
            report_content: The full text content of the draft/final report.

        Returns:
            Rate as a float between 0.0 and 1.0. Returns 1.0 if no
            accepted limitations exist.
        """
        accepted_limitations = [
            g for g in gaps if g.disposition == "accepted_as_limitation"
        ]

        if not accepted_limitations:
            return 1.0

        covered_count = 0
        report_lower = report_content.lower()

        for gap in accepted_limitations:
            if self._is_limitation_covered_in_report(gap, report_lower):
                covered_count += 1

        return covered_count / len(accepted_limitations)

    def calculate_field_grounding_rate(self, groundings: list) -> float:
        """Rate of grounded observed_event fields (upstream spec 13.3).

        Counts fixed-field FieldGroundingRecord entries whose status is
        grounded or partially_grounded among all applicable (non-empty)
        fields. Returns 1.0 when no applicable records exist.
        """
        applicable = [
            g for g in groundings
            if getattr(g, "kind", "fixed") == "fixed"
            and getattr(g, "status", "") != "not_applicable"
        ]
        if not applicable:
            return 1.0
        grounded = sum(
            1 for g in applicable
            if g.status in ("grounded", "partially_grounded")
        )
        return grounded / len(applicable)

    def calculate_multi_evidence_claim_rate(self, claims: list[Claim]) -> float:
        """Rate of claims supported by two or more evidence items."""
        if not claims:
            return 0.0
        multi = sum(1 for c in claims if len(c.supporting_evidence) >= 2)
        return multi / len(claims)

    def calculate_section_assignment_rate(self, claims: list[Claim]) -> float:
        """Rate of claims assigned to the fixed 3.1-3.7 chapter taxonomy."""
        if not claims:
            return 0.0
        fixed_sections = {"3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7"}
        assigned = sum(
            1 for c in claims if c.report_section in fixed_sections
        )
        return assigned / len(claims)

    def calculate_attack_mapping_propagation_rate(
        self,
        claims: list[Claim],
        ledger: list[EvidenceLedgerEntry],
    ) -> float:
        """Rate of evidence-level ATT&CK techniques carried into claims.

        Returns 1.0 when no evidence has ATT&CK candidates.
        """
        evidence_techniques: set[str] = set()
        for entry in ledger:
            for mapping in entry.attack_mapping_candidates or []:
                evidence_techniques.add(mapping.technique_id)
        if not evidence_techniques:
            return 1.0
        claim_techniques: set[str] = set()
        for claim in claims:
            for mapping in claim.attack_mappings or []:
                claim_techniques.add(mapping.technique_id)
        propagated = evidence_techniques & claim_techniques
        return len(propagated) / len(evidence_techniques)

    def calculate_all_metrics(
        self,
        claims: list[Claim],
        ledger: list[EvidenceLedgerEntry],
        gaps: list[Gap],
        report_content: str = "",
    ) -> dict[str, float]:
        """Calculate all quality metrics at once.

        Convenience method that computes all five metrics and returns
        them as a dictionary.

        Args:
            claims: List of claims to evaluate.
            ledger: List of active evidence ledger entries.
            gaps: List of gap records.
            report_content: The report text (for limitation coverage).

        Returns:
            Dictionary with metric names as keys and rates as values.
        """
        return {
            "unsupported_claim_rate": self.calculate_unsupported_claim_rate(
                claims
            ),
            "overclaim_rate": self.calculate_overclaim_rate(claims),
            "evidence_coverage": self.calculate_evidence_coverage(
                claims, ledger
            ),
            "critical_gap_disposition_rate": (
                self.calculate_critical_gap_disposition_rate(gaps)
            ),
            "limitation_coverage": self.calculate_limitation_coverage(
                gaps, report_content
            ),
            "multi_evidence_claim_rate": (
                self.calculate_multi_evidence_claim_rate(claims)
            ),
            "section_assignment_rate": (
                self.calculate_section_assignment_rate(claims)
            ),
            "attack_mapping_propagation_rate": (
                self.calculate_attack_mapping_propagation_rate(claims, ledger)
            ),
        }

    # --- Private helper methods ---

    def _is_overclaim(self, claim: Claim) -> bool:
        """Determine if a claim's confidence exceeds what evidence supports.

        An overclaim exists when:
        1. A CONFIRMED claim has fewer than 2 supporting evidence items
        2. A claim has counter-evidence but maintains CONFIRMED confidence
        3. A PROBABLE claim has counter-evidence and only single-source support

        Args:
            claim: The claim to assess.

        Returns:
            True if the claim is an overclaim.
        """
        confidence_rank = _CONFIDENCE_ORDER.get(claim.confidence_level, 0)
        evidence_count = len(claim.supporting_evidence)
        counter_count = len(claim.counter_evidence)

        # Rule 1: CONFIRMED claims need multiple evidence sources
        if (
            claim.confidence_level == ConfidenceLevel.CONFIRMED
            and evidence_count < 2
        ):
            return True

        # Rule 2: Counter-evidence with CONFIRMED confidence
        if counter_count > 0 and claim.confidence_level == ConfidenceLevel.CONFIRMED:
            return True

        # Rule 3: PROBABLE with counter-evidence and single source
        if (
            claim.confidence_level == ConfidenceLevel.PROBABLE
            and counter_count > 0
            and evidence_count == 1
        ):
            return True

        return False

    def _is_limitation_covered_in_report(
        self, gap: Gap, report_lower: str
    ) -> bool:
        """Check if a limitation gap is described in the report.

        Uses heuristic matching to determine if the report mentions
        the limitation. Checks for:
        - The gap_id reference
        - Key terms from the gap description
        - The related claim_id

        Args:
            gap: The accepted limitation gap.
            report_lower: Lowercased report content.

        Returns:
            True if the limitation appears to be covered in the report.
        """
        # Check for explicit gap_id mention
        if gap.gap_id.lower() in report_lower:
            return True

        # Check for related claim mention in a limitations context
        if gap.related_claim_id.lower() in report_lower:
            # Check if "limitation" or equivalent appears near the claim reference
            if "limitation" in report_lower or "制約" in report_lower:
                return True

        # Check for key description terms (use first significant words)
        description_words = gap.description.lower().split()
        # Use significant words (skip very common ones)
        significant_words = [
            w for w in description_words
            if len(w) > 4 and w not in (
                "claim", "claims", "evidence", "source", "the",
                "that", "this", "with", "from", "have", "has",
            )
        ]

        # If at least half of significant words appear in report, consider covered
        if significant_words:
            found_count = sum(
                1 for w in significant_words if w in report_lower
            )
            if found_count >= max(1, len(significant_words) // 2):
                return True

        return False
