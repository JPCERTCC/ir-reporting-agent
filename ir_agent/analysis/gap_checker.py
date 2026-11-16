"""Gap and contradiction checker for the Analysis Layer.

Implements GapChecker which identifies evidence gaps per claim, detects
contradictions between claims, identifies overclaims, and determines
whether unresolved critical gaps should block report generation.

The GapChecker uses the Data Coverage Ledger to distinguish between:
- missing_evidence: Expected evidence not present
- weak_evidence: Evidence exists but is insufficient for claim strength
- single_source: Claim relies on only one source
- unavailable_logs: Data source is unavailable
- logs_outside_scope: Data source exists but is outside investigation scope
- logs_not_analyzed: Data source available but not yet analyzed
- contradictory_evidence: Counter-evidence conflicts with the claim

Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.8
"""

from __future__ import annotations

import logging
from uuid import uuid4

from ir_agent.models.analysis import Claim, DataCoverageEntry, Gap
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel

logger = logging.getLogger(__name__)

# Confidence level ordering for comparison
_CONFIDENCE_ORDER: dict[ConfidenceLevel, int] = {
    ConfidenceLevel.CONFIRMED: 4,
    ConfidenceLevel.PROBABLE: 3,
    ConfidenceLevel.POSSIBLE: 2,
    ConfidenceLevel.UNKNOWN: 1,
    ConfidenceLevel.NOT_OBSERVED: 0,
}

# Minimum number of supporting evidence items for each confidence level
_MIN_EVIDENCE_FOR_CONFIDENCE: dict[ConfidenceLevel, int] = {
    ConfidenceLevel.CONFIRMED: 2,
    ConfidenceLevel.PROBABLE: 1,
    ConfidenceLevel.POSSIBLE: 1,
    ConfidenceLevel.UNKNOWN: 1,
    ConfidenceLevel.NOT_OBSERVED: 1,
}

# Categories that require stronger evidence support
_HIGH_EVIDENCE_CATEGORIES: set[ClaimCategory] = {
    ClaimCategory.CAUSAL_RELATIONSHIP,
    ClaimCategory.ATTRIBUTION_ASSESSMENT,
    ClaimCategory.DATA_EXFILTRATION_ASSESSMENT,
}


class GapChecker:
    """Checks claims for evidence gaps, contradictions, and overclaims.

    The GapChecker examines each claim against the data coverage ledger
    and other claims to identify:
    - Evidence gaps (missing, weak, single-source)
    - Data coverage gaps (unavailable logs, logs outside scope, unanalyzed)
    - Contradictions between claims
    - Overclaims where assertion strength exceeds evidence support

    Critical gaps without disposition block final report generation.

    Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.8
    """

    def check_gaps(
        self,
        claims: list[Claim],
        coverage: list[DataCoverageEntry],
    ) -> list[Gap]:
        """Identify evidence gaps per claim.

        Checks each claim for sufficient evidence coverage by examining:
        1. Whether supporting evidence is adequate for the confidence level
        2. Whether the claim relies on a single source
        3. Whether relevant data sources are unavailable or unanalyzed
        4. Whether counter-evidence creates contradictions

        Requirement 13.1: Check each Claim for sufficient evidence coverage.
        Requirement 13.2: Generate a Gap record for insufficient evidence.
        Requirement 13.8: Distinguish between missing evidence, unavailable
        logs, logs outside scope, logs available but not yet analyzed,
        and contradictory evidence.

        Args:
            claims: List of claims to check for gaps.
            coverage: Data coverage entries describing available data sources.

        Returns:
            List of Gap records identifying evidence deficiencies.
        """
        gaps: list[Gap] = []

        for claim in claims:
            # Check for missing evidence
            gaps.extend(self._check_missing_evidence(claim))

            # Check for weak evidence
            gaps.extend(self._check_weak_evidence(claim))

            # Check for single source dependency
            gaps.extend(self._check_single_source(claim))

            # Check for data coverage gaps
            gaps.extend(self._check_coverage_gaps(claim, coverage))

            # Check for contradictory evidence
            gaps.extend(self._check_contradictory_evidence(claim))

            # Check for case-specific analytical constraints expressed in the
            # claim (e.g. artifact body missing, encrypted content, limited
            # preservation, point-in-time-only observations). (UP-07)
            gaps.extend(self._check_constraint_gaps(claim))

        # Consolidate constraint-derived gaps so limitations shared by
        # multiple claims in the same report section do not multiply
        # (upstream-analysis spec section 9).
        gaps = self.consolidate_limitation_gaps(gaps, claims)

        return gaps

    # Constraint gap types consolidated per report section: the same
    # investigation constraint restated by several claims in one chapter is
    # one finding, not many.
    _CONSOLIDATABLE_GAP_TYPES = {
        "artifact_body_missing",
        "content_not_recoverable",
        "limited_preservation",
        "point_in_time_only",
        "scope_limitation",
        "causal_link_unconfirmed",
    }

    # Coverage gap types describe a case-level data fact (a data source on a
    # host is unavailable / out of scope / unanalyzed), so they are emitted
    # once per data source rather than once per claim that touches it. Their
    # descriptions are built purely from the coverage entry, which makes the
    # description a stable per-data-source key.
    _COVERAGE_GAP_TYPES = {
        "unavailable_logs",
        "logs_outside_scope",
        "logs_not_analyzed",
    }

    def consolidate_limitation_gaps(
        self, gaps: list[Gap], claims: list[Claim]
    ) -> list[Gap]:
        """Merge gaps that restate the same finding across several claims.

        Two kinds are consolidated (upstream-analysis spec section 9):

        - Constraint gaps: one per (gap_type, severity, report_section),
          since the same investigation constraint in one chapter is one
          finding.
        - Coverage gaps: one per data source, since "this log on this host
          was not analyzed" is a case-level fact that would otherwise be
          repeated for every claim touching that host.

        Evidence-specific gaps (missing_evidence, single_source,
        contradictory_evidence, ...) stay per-claim.
        """
        section_by_claim = {c.claim_id: c.report_section for c in claims}

        merged: dict[tuple, Gap] = {}
        merged_claims: dict[tuple, list[str]] = {}
        result: list[Gap] = []

        for gap in gaps:
            if gap.gap_type in self._CONSOLIDATABLE_GAP_TYPES:
                section = section_by_claim.get(gap.related_claim_id, "")
                key = ("constraint", gap.gap_type, gap.severity, section)
            elif gap.gap_type in self._COVERAGE_GAP_TYPES:
                key = ("coverage", gap.gap_type, gap.severity, gap.description)
            else:
                result.append(gap)
                continue

            if key not in merged:
                merged[key] = gap
                merged_claims[key] = [gap.related_claim_id]
                result.append(gap)
            elif gap.related_claim_id not in merged_claims[key]:
                merged_claims[key].append(gap.related_claim_id)

        for key, gap in merged.items():
            claim_ids = merged_claims[key]
            if len(claim_ids) <= 1:
                continue
            if key[0] == "constraint":
                gap.description = (
                    f"複数の分析結果 ({', '.join(claim_ids)}) に調査上の制約"
                    f"({gap.gap_type})が含まれます。"
                )
            else:
                # Keep the data-source description and record its reach.
                gap.description = (
                    f"{gap.description} "
                    f"(affects {len(claim_ids)} claims: {', '.join(claim_ids)})"
                )

        return result

    def detect_contradictions(
        self, claims: list[Claim]
    ) -> list[dict]:
        """Find contradictory assertions between claims.

        Examines all pairs of claims to identify those making conflicting
        assertions. Contradictions are identified when:
        - Two claims about the same subject assert opposite conclusions
        - One claim confirms and another denies the same event
        - Causal claims create logical inconsistencies

        Requirement 13.3: Flag contradictions with references to both
        claim_ids and conflicting evidence.

        Args:
            claims: List of claims to check for contradictions.

        Returns:
            List of contradiction records, each containing:
            - claim_id_a: First conflicting claim
            - claim_id_b: Second conflicting claim
            - description: Description of the contradiction
            - conflicting_evidence: Evidence IDs involved
        """
        contradictions: list[dict] = []

        for i, claim_a in enumerate(claims):
            for claim_b in claims[i + 1:]:
                contradiction = self._check_pair_contradiction(claim_a, claim_b)
                if contradiction is not None:
                    contradictions.append(contradiction)

        return contradictions

    def detect_overclaims(
        self, claims: list[Claim]
    ) -> list[Claim]:
        """Find claims where assertion strength exceeds evidence support.

        An overclaim occurs when:
        - A claim has CONFIRMED confidence but only possible/probable evidence
        - A high-evidence-threshold category claim has elevated confidence
          without sufficient corroboration
        - A claim's confidence exceeds what the number and quality of
          supporting evidence can justify

        Requirement 13.4: Identify overclaims — claims where the assertion
        strength exceeds what the evidence supports.

        Args:
            claims: List of claims to check for overclaims.

        Returns:
            List of claims identified as overclaims.
        """
        overclaims: list[Claim] = []

        for claim in claims:
            if self._is_overclaim(claim):
                overclaims.append(claim)

        return overclaims

    def has_unresolved_critical_gaps(self, gaps: list[Gap]) -> bool:
        """Check if any critical gaps lack disposition.

        Returns True only if there are critical-severity gaps that have
        not been dispositioned. Critical gaps with any disposition
        (accepted_as_limitation, mitigated_by_claim_downgrade, etc.)
        do NOT block report generation.

        Requirement 13.6: Unresolved and undispositioned critical gaps
        block final report generation.

        Args:
            gaps: List of Gap records to check.

        Returns:
            True if critical gaps without disposition exist, False otherwise.
        """
        for gap in gaps:
            if gap.severity == "critical" and gap.disposition is None:
                return True
        return False

    # --- Private helper methods ---

    def _check_missing_evidence(self, claim: Claim) -> list[Gap]:
        """Check if a claim has missing evidence items.

        A claim has missing evidence if it explicitly lists items in
        its missing_evidence field, indicating known gaps in support.

        Args:
            claim: The claim to check.

        Returns:
            List of Gap records for missing evidence.
        """
        gaps: list[Gap] = []

        if claim.missing_evidence:
            # Determine severity based on confidence level and category
            severity = self._determine_missing_evidence_severity(claim)

            gap = Gap(
                gap_id=f"GAP-{uuid4().hex[:8]}",
                related_claim_id=claim.claim_id,
                gap_type="missing_evidence",
                severity=severity,
                description=(
                    f"Claim '{claim.claim_id}' has {len(claim.missing_evidence)} "
                    f"missing evidence item(s): {'; '.join(claim.missing_evidence)}"
                ),
                recommended_action=(
                    "Collect or document the missing evidence, or downgrade "
                    "claim confidence to match available evidence."
                ),
            )
            gaps.append(gap)

        return gaps

    def _check_weak_evidence(self, claim: Claim) -> list[Gap]:
        """Check if a claim's evidence is too weak for its confidence level.

        A claim has weak evidence when the number of supporting evidence
        items is below the minimum required for the stated confidence level.

        Args:
            claim: The claim to check.

        Returns:
            List of Gap records for weak evidence.
        """
        gaps: list[Gap] = []

        min_required = _MIN_EVIDENCE_FOR_CONFIDENCE.get(
            claim.confidence_level, 1
        )

        # High-evidence categories require more evidence
        if claim.claim_category in _HIGH_EVIDENCE_CATEGORIES:
            min_required += 1

        evidence_count = len(claim.supporting_evidence)

        if evidence_count < min_required:
            severity = "major" if claim.confidence_level in (
                ConfidenceLevel.CONFIRMED, ConfidenceLevel.PROBABLE
            ) else "minor"

            gap = Gap(
                gap_id=f"GAP-{uuid4().hex[:8]}",
                related_claim_id=claim.claim_id,
                gap_type="weak_evidence",
                severity=severity,
                description=(
                    f"Claim '{claim.claim_id}' has {evidence_count} supporting "
                    f"evidence item(s) but requires at least {min_required} for "
                    f"confidence level '{claim.confidence_level.value}' "
                    f"(category: {claim.claim_category.value})."
                ),
                recommended_action=(
                    "Collect additional supporting evidence or downgrade "
                    "the claim confidence level."
                ),
            )
            gaps.append(gap)

        return gaps

    # Constraint markers → (gap_type, severity, recommended_action). The
    # marker phrases are matched against the claim text and its limitations;
    # each is the analyst-authored expression of a genuine investigative
    # limit that would otherwise live only in report prose. (UP-07)
    _CONSTRAINT_RULES: list[tuple[list[str], str, str, str]] = [
        (
            ["本体は取得できていない", "本体は未取得", "本体未取得", "未取得"],
            "artifact_body_missing",
            "major",
            "アーティファクト本体の回収を試み、回収できない場合は制約として明記する。",
        ),
        (
            ["暗号化されており", "暗号化されているため", "暗号化のため"],
            "content_not_recoverable",
            "major",
            "復号可能なデータや別経路のログ(プロキシ/DNS等)の取得を検討し、内容不明を制約として明記する。",
        ),
        (
            ["保全が限定", "ディスク保全が限定", "削除痕跡", "切り詰め", "truncat"],
            "limited_preservation",
            "minor",
            "追加のフォレンジック保全を検討し、確認範囲の制約を明記する。",
        ),
        (
            ["取得時点", "開始時刻はこの記録", "開始時刻は取得時点", "待受の開始時刻"],
            "point_in_time_only",
            "minor",
            "継続的なログ・EDRテレメトリで発生・開始時刻の特定を試み、時点情報の制約を明記する。",
        ),
        (
            ["対象外ホスト", "未提供ログ", "提供されていないログ", "調査範囲外"],
            "scope_limitation",
            "minor",
            "対象外ホスト・未提供ログの追加取得を検討し、確認範囲の制約を明記する。",
        ),
        (
            ["因果関係を示す証拠", "直接的な因果", "因果関係は確認できません"],
            "causal_link_unconfirmed",
            "minor",
            "時刻・値の一致と因果関係を区別し、因果を示す追加証拠の取得を検討する。",
        ),
    ]

    def _check_constraint_gaps(self, claim: Claim) -> list[Gap]:
        """Derive case-specific analytical gaps from a claim's constraints.

        Scans the claim text and its limitations for analyst-authored
        constraint markers and emits a typed Gap per matched constraint.
        At most one gap of each type per claim. (UP-07)
        """
        gaps: list[Gap] = []
        haystack = " ".join(
            [claim.claim_text] + list(claim.limitations or [])
        )
        for markers, gap_type, severity, action in self._CONSTRAINT_RULES:
            if any(marker in haystack for marker in markers):
                gaps.append(
                    Gap(
                        gap_id=f"GAP-{uuid4().hex[:8]}",
                        related_claim_id=claim.claim_id,
                        gap_type=gap_type,
                        severity=severity,
                        description=(
                            f"分析結果 '{claim.claim_id}' には調査上の制約"
                            f"({gap_type})が含まれます。"
                        ),
                        recommended_action=action,
                    )
                )
        return gaps

    def _check_single_source(self, claim: Claim) -> list[Gap]:
        """Check if a claim relies on a single source.

        Claims with CONFIRMED or PROBABLE confidence that rely on only
        one supporting evidence item are flagged as single-source risks.

        Args:
            claim: The claim to check.

        Returns:
            List of Gap records for single-source dependency.
        """
        gaps: list[Gap] = []

        if len(claim.supporting_evidence) == 1 and _CONFIDENCE_ORDER.get(
            claim.confidence_level, 0
        ) >= _CONFIDENCE_ORDER[ConfidenceLevel.PROBABLE]:
            severity = "major" if claim.confidence_level == ConfidenceLevel.CONFIRMED else "minor"

            gap = Gap(
                gap_id=f"GAP-{uuid4().hex[:8]}",
                related_claim_id=claim.claim_id,
                gap_type="single_source",
                severity=severity,
                description=(
                    f"Claim '{claim.claim_id}' with confidence "
                    f"'{claim.confidence_level.value}' relies on a single "
                    f"evidence source ({claim.supporting_evidence[0]})."
                ),
                recommended_action=(
                    "Seek corroborating evidence from independent sources, "
                    "or document as a limitation."
                ),
            )
            gaps.append(gap)

        return gaps

    def _check_coverage_gaps(
        self, claim: Claim, coverage: list[DataCoverageEntry]
    ) -> list[Gap]:
        """Check for data coverage gaps affecting a claim.

        Examines the data coverage ledger for data sources that are
        unavailable, outside scope, or not yet analyzed, and flags
        relevant gaps per claim.

        Requirement 13.8: Distinguish between unavailable_logs,
        logs_outside_scope, and logs_not_analyzed.

        Args:
            claim: The claim to check.
            coverage: Data coverage entries.

        Returns:
            List of Gap records for coverage-related gaps.
        """
        gaps: list[Gap] = []

        for entry in coverage:
            if entry.availability_status == "unavailable":
                # Check if this unavailable source is relevant to the claim
                if self._coverage_relevant_to_claim(entry, claim):
                    severity = self._coverage_gap_severity(claim, entry)
                    gap = Gap(
                        gap_id=f"GAP-{uuid4().hex[:8]}",
                        related_claim_id=claim.claim_id,
                        gap_type="unavailable_logs",
                        severity=severity,
                        description=(
                            f"Data source '{entry.data_source_type}' on "
                            f"'{entry.host_or_system}' is unavailable. "
                            f"Reason: {entry.reason_for_unavailability or 'Unknown'}. "
                            f"Impact: {entry.impact_on_findings or 'Unknown'}."
                        ),
                        recommended_action=(
                            "Attempt to obtain the data source, or document "
                            "as a limitation in the report."
                        ),
                    )
                    gaps.append(gap)

            elif entry.availability_status == "outside_scope":
                if self._coverage_relevant_to_claim(entry, claim):
                    gap = Gap(
                        gap_id=f"GAP-{uuid4().hex[:8]}",
                        related_claim_id=claim.claim_id,
                        gap_type="logs_outside_scope",
                        severity="minor",
                        description=(
                            f"Data source '{entry.data_source_type}' on "
                            f"'{entry.host_or_system}' is outside investigation scope."
                        ),
                        recommended_action=(
                            "Consider expanding scope if evidence is critical, "
                            "or document as out-of-scope limitation."
                        ),
                    )
                    gaps.append(gap)

            elif entry.availability_status in ("unknown", "pending_collection"):
                if self._coverage_relevant_to_claim(entry, claim):
                    gap = Gap(
                        gap_id=f"GAP-{uuid4().hex[:8]}",
                        related_claim_id=claim.claim_id,
                        gap_type="logs_not_analyzed",
                        severity="major",
                        description=(
                            f"Data source '{entry.data_source_type}' on "
                            f"'{entry.host_or_system}' has not been analyzed "
                            f"(status: {entry.availability_status})."
                        ),
                        recommended_action=(
                            "Analyze the pending data source before finalizing "
                            "claims, or document as a limitation."
                        ),
                    )
                    gaps.append(gap)

        return gaps

    def _check_contradictory_evidence(self, claim: Claim) -> list[Gap]:
        """Check if a claim has counter-evidence creating contradictions.

        Claims with non-empty counter_evidence fields have internal
        contradictions that should be addressed.

        Args:
            claim: The claim to check.

        Returns:
            List of Gap records for contradictory evidence.
        """
        gaps: list[Gap] = []

        if claim.counter_evidence:
            severity = "critical" if _CONFIDENCE_ORDER.get(
                claim.confidence_level, 0
            ) >= _CONFIDENCE_ORDER[ConfidenceLevel.PROBABLE] else "major"

            gap = Gap(
                gap_id=f"GAP-{uuid4().hex[:8]}",
                related_claim_id=claim.claim_id,
                gap_type="contradictory_evidence",
                severity=severity,
                description=(
                    f"Claim '{claim.claim_id}' has {len(claim.counter_evidence)} "
                    f"counter-evidence item(s) that contradict the assertion. "
                    f"Counter-evidence IDs: {', '.join(claim.counter_evidence)}."
                ),
                recommended_action=(
                    "Resolve the contradiction by reviewing counter-evidence, "
                    "adjusting the claim, or documenting as a limitation."
                ),
            )
            gaps.append(gap)

        return gaps

    def _check_pair_contradiction(
        self, claim_a: Claim, claim_b: Claim
    ) -> dict | None:
        """Check if two claims contradict each other.

        Two claims are contradictory if:
        - They share overlapping evidence but reach opposite conclusions
        - One claim confirms and the other denies the same subject
        - They make mutually exclusive assertions

        Args:
            claim_a: First claim.
            claim_b: Second claim.

        Returns:
            Contradiction record dict, or None if no contradiction found.
        """
        # Check for shared evidence used in opposing ways
        a_supporting = set(claim_a.supporting_evidence)
        b_supporting = set(claim_b.supporting_evidence)
        a_counter = set(claim_a.counter_evidence)
        b_counter = set(claim_b.counter_evidence)

        # Evidence supporting one claim but countering another
        supporting_a_countering_b = a_supporting & b_counter
        supporting_b_countering_a = b_supporting & a_counter

        if supporting_a_countering_b or supporting_b_countering_a:
            conflicting_evidence = list(
                supporting_a_countering_b | supporting_b_countering_a
            )
            return {
                "claim_id_a": claim_a.claim_id,
                "claim_id_b": claim_b.claim_id,
                "description": (
                    f"Claims '{claim_a.claim_id}' and '{claim_b.claim_id}' "
                    f"have evidence that supports one but counters the other."
                ),
                "conflicting_evidence": conflicting_evidence,
            }

        # Check for textual contradiction patterns
        if self._texts_contradict(claim_a.claim_text, claim_b.claim_text):
            # They must also be about the same subject/section
            if claim_a.report_section == claim_b.report_section:
                return {
                    "claim_id_a": claim_a.claim_id,
                    "claim_id_b": claim_b.claim_id,
                    "description": (
                        f"Claims '{claim_a.claim_id}' and '{claim_b.claim_id}' "
                        f"make potentially contradictory assertions in the same "
                        f"report section '{claim_a.report_section}'."
                    ),
                    "conflicting_evidence": list(
                        a_supporting | b_supporting
                    ),
                }

        return None

    def _texts_contradict(self, text_a: str, text_b: str) -> bool:
        """Check if two claim texts appear to contradict each other.

        Uses heuristic patterns to detect negation and opposing assertions.

        Args:
            text_a: First claim text.
            text_b: Second claim text.

        Returns:
            True if texts appear contradictory.
        """
        negation_pairs = [
            ("confirmed", "not confirmed"),
            ("successful", "unsuccessful"),
            ("compromised", "not compromised"),
            ("accessed", "not accessed"),
            ("exfiltrated", "no exfiltration"),
            ("occurred", "did not occur"),
            ("present", "not present"),
            ("detected", "not detected"),
            ("active", "inactive"),
            ("malicious", "benign"),
        ]

        a_lower = text_a.lower()
        b_lower = text_b.lower()

        for positive, negative in negation_pairs:
            if (positive in a_lower and negative in b_lower) or (
                negative in a_lower and positive in b_lower
            ):
                return True

        return False

    def _is_overclaim(self, claim: Claim) -> bool:
        """Determine if a claim is an overclaim.

        An overclaim exists when:
        1. A CONFIRMED claim has only one supporting evidence item
        2. A high-threshold category claim has CONFIRMED/PROBABLE confidence
           with fewer than 3 supporting evidence items
        3. A claim has counter-evidence but maintains high confidence

        Args:
            claim: The claim to assess.

        Returns:
            True if the claim is an overclaim.
        """
        confidence_rank = _CONFIDENCE_ORDER.get(claim.confidence_level, 0)
        evidence_count = len(claim.supporting_evidence)
        counter_count = len(claim.counter_evidence)

        # Rule 1: CONFIRMED claims need multiple evidence sources
        if claim.confidence_level == ConfidenceLevel.CONFIRMED and evidence_count < 2:
            return True

        # Rule 2: High-threshold categories need stronger support
        if (
            claim.claim_category in _HIGH_EVIDENCE_CATEGORIES
            and confidence_rank >= _CONFIDENCE_ORDER[ConfidenceLevel.PROBABLE]
            and evidence_count < 2
        ):
            return True

        # Rule 3: Counter-evidence with high confidence is suspicious
        if (
            counter_count > 0
            and confidence_rank >= _CONFIDENCE_ORDER[ConfidenceLevel.CONFIRMED]
        ):
            return True

        # Rule 4: PROBABLE claims with counter-evidence and single source
        if (
            claim.confidence_level == ConfidenceLevel.PROBABLE
            and counter_count > 0
            and evidence_count == 1
        ):
            return True

        return False

    def _determine_missing_evidence_severity(self, claim: Claim) -> str:
        """Determine severity for a missing evidence gap.

        Severity is based on claim confidence level and category:
        - Critical: CONFIRMED claims in high-threshold categories
        - Major: CONFIRMED/PROBABLE claims in any category
        - Minor: POSSIBLE/UNKNOWN claims

        Args:
            claim: The claim with missing evidence.

        Returns:
            Severity string: "critical", "major", or "minor".
        """
        confidence_rank = _CONFIDENCE_ORDER.get(claim.confidence_level, 0)

        if (
            claim.claim_category in _HIGH_EVIDENCE_CATEGORIES
            and confidence_rank >= _CONFIDENCE_ORDER[ConfidenceLevel.CONFIRMED]
        ):
            return "critical"
        elif confidence_rank >= _CONFIDENCE_ORDER[ConfidenceLevel.PROBABLE]:
            return "major"
        else:
            return "minor"

    def _coverage_relevant_to_claim(
        self, entry: DataCoverageEntry, claim: Claim
    ) -> bool:
        """Check if a coverage entry is relevant to a claim.

        A coverage entry is relevant if it could potentially provide
        evidence for or against the claim. Uses claim text and
        limitations to determine relevance.

        Args:
            entry: The data coverage entry.
            claim: The claim to check relevance against.

        Returns:
            True if the coverage entry is relevant to the claim.
        """
        # Check if the host/system is mentioned in claim limitations or
        # missing evidence
        host_lower = entry.host_or_system.lower()
        ds_type_lower = entry.data_source_type.lower()

        # Check missing evidence references
        for missing in claim.missing_evidence:
            missing_lower = missing.lower()
            if host_lower in missing_lower or ds_type_lower in missing_lower:
                return True

        # Check limitations references
        for limitation in claim.limitations:
            limitation_lower = limitation.lower()
            if host_lower in limitation_lower or ds_type_lower in limitation_lower:
                return True

        # Check if the claim text references the host
        if host_lower in claim.claim_text.lower():
            return True

        return False

    def _coverage_gap_severity(
        self, claim: Claim, entry: DataCoverageEntry
    ) -> str:
        """Determine severity for a coverage-related gap.

        Based on the claim's confidence level and the potential impact
        of the missing data source.

        Args:
            claim: The related claim.
            entry: The coverage entry.

        Returns:
            Severity string: "critical", "major", or "minor".
        """
        confidence_rank = _CONFIDENCE_ORDER.get(claim.confidence_level, 0)

        # If impact_on_findings is set and sounds critical, escalate
        if entry.impact_on_findings:
            impact_lower = entry.impact_on_findings.lower()
            if any(
                word in impact_lower
                for word in ("critical", "significant", "major", "essential")
            ):
                return "critical"

        # Base on confidence level
        if confidence_rank >= _CONFIDENCE_ORDER[ConfidenceLevel.CONFIRMED]:
            return "critical"
        elif confidence_rank >= _CONFIDENCE_ORDER[ConfidenceLevel.PROBABLE]:
            return "major"
        else:
            return "minor"
