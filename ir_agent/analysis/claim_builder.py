"""Claim building for the Analysis Layer.

Implements ClaimBuilder which generates report claims from approved evidence
in the Evidence Ledger. Each claim is linked to at least one evidence_id,
assigned a confidence level via multi-factor analysis, and annotated with
expression policy recommendations.

Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6
"""

from typing import Optional
from uuid import uuid4

from ir_agent.analysis.coverage import infer_data_source_type
from ir_agent.models.analysis import Claim, DataCoverageEntry, TimelineEntry
from ir_agent.models.correlation import AnalysisGroup, CorrelationHint, EntityLink
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.events import ATTCKMapping
from ir_agent.models.evidence import EvidenceLedgerEntry
from ir_agent.steering.manifest import ExpressionPolicy


class EvidenceCoverageError(Exception):
    """Raised when approved evidence would silently drop out of all claims.

    The inverse of "No Evidence, No Report": grouping must never make an
    approved evidence item disappear from the report (spec section 5.4).
    """

    def __init__(self, missing_evidence_ids: list[str]) -> None:
        self.missing_evidence_ids = missing_evidence_ids
        super().__init__(
            "Approved evidence not covered by any claim: "
            + ", ".join(missing_evidence_ids)
        )


# Confidence level ordering for comparison
_CONFIDENCE_ORDER: dict[ConfidenceLevel, int] = {
    ConfidenceLevel.CONFIRMED: 4,
    ConfidenceLevel.PROBABLE: 3,
    ConfidenceLevel.POSSIBLE: 2,
    ConfidenceLevel.UNKNOWN: 1,
    ConfidenceLevel.NOT_OBSERVED: 0,
}

# Categories that inherently require stronger evidence for high confidence
_HIGH_EVIDENCE_THRESHOLD_CATEGORIES: set[ClaimCategory] = {
    ClaimCategory.CAUSAL_RELATIONSHIP,
    ClaimCategory.ATTRIBUTION_ASSESSMENT,
    ClaimCategory.DATA_EXFILTRATION_ASSESSMENT,
}


class ClaimBuilder:
    """Generates report claims from approved evidence entries.

    Every claim is explicitly linked to at least one supporting evidence_id.
    Confidence is calculated using multi-factor analysis considering:
    - Claim category
    - Directness of evidence
    - Number of independent source references
    - Counter-evidence
    - Data coverage
    - Known limitations

    The builder does NOT mechanically downgrade to the weakest single
    supporting evidence item (Requirement 11.5).

    Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6
    """

    def build_claims(
        self,
        ledger: list[EvidenceLedgerEntry],
        timeline: list[TimelineEntry],
        policy: ExpressionPolicy,
        coverage: list[DataCoverageEntry],
    ) -> list[Claim]:
        """Generate claims from approved evidence, timeline, and coverage data.

        Groups evidence by interpretation topic, generates a claim for each
        group, calculates confidence via multi-factor analysis, and applies
        expression policy.

        Requirement 11.1: Generate Claims linking report assertions to
        supporting evidence when Evidence_Ledger and timeline are available.

        Requirement 11.4: No claim is generated without at least one
        supporting evidence_id from the Evidence_Ledger.

        Args:
            ledger: Approved evidence ledger entries (active, non-withdrawn).
            timeline: Constructed timeline entries.
            policy: Expression policy from the case manifest.
            coverage: Data coverage entries for the investigation.

        Returns:
            List of generated Claim objects, each with at least one
            supporting evidence_id.
        """
        # Filter to active (non-withdrawn) entries only
        active_entries = [e for e in ledger if not e.withdrawn]

        if not active_entries:
            return []

        # Group evidence by interpretation to form claim clusters
        claim_groups = self._group_evidence_for_claims(active_entries)

        claims: list[Claim] = []
        for group in claim_groups:
            claim = self._build_single_claim(group, active_entries, coverage)
            if claim is not None:
                # Apply expression policy (Requirement 11.6)
                claim = self.apply_expression_policy(claim, policy)
                claims.append(claim)

        return claims

    def build_claims_from_groups(
        self,
        groups: list[AnalysisGroup],
        ledger: list[EvidenceLedgerEntry],
        policy: ExpressionPolicy,
        coverage: list[DataCoverageEntry],
        entity_links: Optional[list[EntityLink]] = None,
        hints: Optional[list[CorrelationHint]] = None,
    ) -> list[Claim]:
        """Generate claims from validated analysis groups (spec section 5.4).

        Group-derived claims carry the group's report_section, claim_text,
        limitations, group_basis, and merged ATT&CK mappings. Evidence not
        covered by any group falls back to single-evidence claims via the
        legacy path so no approved evidence disappears from the report.

        Raises:
            EvidenceCoverageError: If any approved, non-withdrawn evidence
                would not appear in at least one claim.
        """
        active_entries = [e for e in ledger if not e.withdrawn]
        by_id = {e.evidence_id: e for e in active_entries}

        usable_groups = [
            g for g in groups if g.validation_status != "rejected"
        ]
        verified_links = [
            l for l in (entity_links or [])
            if l.validation_status != "rejected"
        ]
        links_by_id = {l.entity_link_id: l for l in verified_links}
        hints_by_id = {h.hint_id: h for h in (hints or [])}

        claims: list[Claim] = []
        grouped_evidence: set[str] = set()

        for group in usable_groups:
            supporting = [
                by_id[eid] for eid in group.supporting_evidence if eid in by_id
            ]
            if not supporting:
                continue
            claim = self._build_group_claim(
                group, supporting, active_entries, coverage,
                links_by_id, hints_by_id,
            )
            claim = self.apply_expression_policy(claim, policy)
            claims.append(claim)
            grouped_evidence.update(e.evidence_id for e in supporting)

        # Ungrouped evidence keeps its legacy single-evidence claims so
        # grouping never removes approved evidence from the report.
        ungrouped = [
            e for e in active_entries if e.evidence_id not in grouped_evidence
        ]
        if ungrouped:
            claims.extend(
                self.build_claims(ungrouped, [], policy, coverage)
            )

        # Reconcile: every approved evidence id must appear in >= 1 claim.
        covered: set[str] = set()
        for claim in claims:
            covered.update(claim.supporting_evidence)
        missing = sorted(
            eid for eid in by_id if eid not in covered
        )
        if missing:
            raise EvidenceCoverageError(missing)

        return claims

    def _build_group_claim(
        self,
        group: AnalysisGroup,
        supporting: list[EvidenceLedgerEntry],
        all_entries: list[EvidenceLedgerEntry],
        coverage: list[DataCoverageEntry],
        links_by_id: dict[str, EntityLink],
        hints_by_id: dict[str, CorrelationHint],
    ) -> Claim:
        """Build one claim from a validated analysis group."""
        try:
            category = ClaimCategory(group.claim_category)
        except ValueError:
            category = ClaimCategory.INTERPRETATION

        counter = self._find_counter_evidence(supporting, all_entries)
        relevant_coverage = self._select_relevant_coverage(supporting, coverage)

        # Corroboration is only credited when the relationship between the
        # evidence items is grounded by a verified link or hint (spec 7.2).
        verified_correlation = self._correlation_grounded(
            group, supporting, links_by_id, hints_by_id
        )

        confidence_level, confidence_basis = self.calculate_confidence(
            claim_category=category,
            supporting=supporting,
            counter=counter,
            coverage=relevant_coverage,
            verified_correlation=verified_correlation,
        )

        if verified_correlation:
            anchors = list(group.related_entity_link_ids) + list(
                group.related_hint_ids
            )
            if anchors:
                confidence_basis += (
                    "; Correlation grounded by: " + ", ".join(anchors)
                )

        limitations = list(group.limitations)
        for extra in self._identify_limitations(supporting, relevant_coverage):
            if extra not in limitations:
                limitations.append(extra)

        return Claim(
            claim_id=f"CLM-{uuid4().hex[:8]}",
            report_section=group.report_section,
            claim_text=group.claim_text,
            claim_category=category,
            confidence_level=confidence_level,
            confidence_basis=confidence_basis,
            supporting_evidence=[e.evidence_id for e in supporting],
            counter_evidence=[e.evidence_id for e in counter],
            limitations=limitations,
            missing_evidence=self._identify_missing_evidence(relevant_coverage),
            recommended_expressions=[],
            prohibited_expressions=[],
            review_status="pending",
            attack_mappings=self._merge_group_attack_mappings(group, supporting),
            analysis_group_id=group.analysis_group_id,
            group_basis=group.group_basis or None,
            related_entity_link_ids=list(group.related_entity_link_ids),
            related_hint_ids=list(group.related_hint_ids),
        )

    def _correlation_grounded(
        self,
        group: AnalysisGroup,
        supporting: list[EvidenceLedgerEntry],
        links_by_id: dict[str, EntityLink],
        hints_by_id: dict[str, CorrelationHint],
    ) -> bool:
        """True when a verified entity link or hint ties the group's evidence."""
        supporting_ids = {e.evidence_id for e in supporting}
        for link_id in group.related_entity_link_ids:
            link = links_by_id.get(link_id)
            if link and len(
                supporting_ids & {m.evidence_id for m in link.members}
            ) >= 2:
                return True
        for hint_id in group.related_hint_ids:
            hint = hints_by_id.get(hint_id)
            if hint and len(supporting_ids & set(hint.evidence_ids)) >= 2:
                return True
        return False

    def _merge_group_attack_mappings(
        self,
        group: AnalysisGroup,
        supporting: list[EvidenceLedgerEntry],
    ) -> list[ATTCKMapping]:
        """Merge group + evidence ATT&CK candidates per spec section 8.1.

        Same technique_id collapses to one mapping; supporting evidence ids
        are kept; confidence never exceeds the interpretation confidence of
        the evidence backing the mapping.
        """
        interp_by_id = {
            e.evidence_id: e.interpretation_confidence for e in supporting
        }

        merged: dict[str, ATTCKMapping] = {}

        def cap_for(evidence_ids: list[str]) -> ConfidenceLevel:
            orders = [
                _CONFIDENCE_ORDER[interp_by_id[eid]]
                for eid in evidence_ids
                if eid in interp_by_id
            ]
            if not orders:
                return ConfidenceLevel.POSSIBLE
            cap = max(orders)
            for level, order in _CONFIDENCE_ORDER.items():
                if order == cap:
                    return level
            return ConfidenceLevel.POSSIBLE

        def add(
            technique_id: str,
            technique_name: str,
            tactic: str,
            confidence: Optional[ConfidenceLevel],
            reason: str,
            evidence_ids: list[str],
        ) -> None:
            cap = cap_for(evidence_ids)
            level = confidence or cap
            if _CONFIDENCE_ORDER[level] > _CONFIDENCE_ORDER[cap]:
                level = cap
            existing = merged.get(technique_id)
            if existing is None:
                merged[technique_id] = ATTCKMapping(
                    tactic=tactic,
                    technique_id=technique_id,
                    technique_name=technique_name,
                    confidence=level,
                    mapping_reason=reason,
                    supporting_evidence=list(dict.fromkeys(evidence_ids)),
                )
            else:
                combined = list(
                    dict.fromkeys(existing.supporting_evidence + evidence_ids)
                )
                existing.supporting_evidence = combined
                if reason and reason not in existing.mapping_reason:
                    existing.mapping_reason = (
                        f"{existing.mapping_reason}; {reason}"
                        if existing.mapping_reason
                        else reason
                    )

        for mapping in group.attack_mappings:
            add(
                mapping.technique_id,
                mapping.technique_name,
                mapping.tactic,
                mapping.confidence,
                mapping.mapping_reason,
                mapping.supporting_evidence or [e.evidence_id for e in supporting],
            )

        # Inherit evidence-level candidates not restated by the group.
        for entry in supporting:
            for cand in entry.attack_mapping_candidates or []:
                add(
                    cand.technique_id,
                    cand.technique_name,
                    cand.tactic,
                    cand.confidence,
                    cand.mapping_reason,
                    [entry.evidence_id],
                )

        return list(merged.values())

    def calculate_confidence(
        self,
        claim_category: ClaimCategory,
        supporting: list[EvidenceLedgerEntry],
        counter: list[EvidenceLedgerEntry],
        coverage: list[DataCoverageEntry],
        verified_correlation: Optional[bool] = None,
    ) -> tuple[ConfidenceLevel, str]:
        """Calculate claim confidence using multi-factor analysis.

        Considers multiple factors rather than simply using the weakest
        evidence item. Factors include:
        - Claim category (some categories inherently need stronger evidence)
        - Directness of evidence (observed_fact_confidence vs interpretation)
        - Number of independent source references (corroboration)
        - Counter-evidence presence and strength
        - Data coverage completeness
        - Known limitations

        Requirement 11.5: Does NOT mechanically downgrade to the weakest
        single supporting evidence item. If confidence is elevated above
        the interpretation_confidence of any single supporting evidence,
        records a confidence_basis explaining the elevation rationale.

        Args:
            claim_category: The category of claim being assessed.
            supporting: Evidence entries supporting this claim.
            counter: Evidence entries contradicting this claim.
            coverage: Data coverage entries relevant to this claim.

        Returns:
            Tuple of (ConfidenceLevel, basis_explanation) where
            basis_explanation describes how confidence was determined.
        """
        if not supporting:
            return (ConfidenceLevel.UNKNOWN, "No supporting evidence available")

        # Factor 1: Base confidence from evidence interpretation levels
        base_confidence = self._assess_base_confidence(supporting)

        # Factor 2: Corroboration bonus (multiple independent sources)
        if verified_correlation is None:
            corroboration_boost = self._assess_corroboration(supporting)
        else:
            # Upstream-analysis path (spec 7.2): corroboration counts only
            # when >=2 supporting items are strictly independent (different
            # source files AND different host or data source type), their
            # relationship is grounded by a verified link/hint, and no
            # counter-evidence exists.
            corroboration_boost = (
                1
                if (
                    len(supporting) >= 2
                    and self._has_strictly_independent_sources(supporting)
                    and verified_correlation
                    and not counter
                )
                else 0
            )

        # Factor 3: Counter-evidence penalty
        counter_penalty = self._assess_counter_evidence(counter)

        # Factor 4: Data coverage assessment
        coverage_factor = self._assess_data_coverage(coverage)

        # Factor 5: Category-specific adjustment
        category_adjustment = self._assess_category_requirement(claim_category)

        # Combine factors into final confidence score
        # Start with base, apply adjustments
        score = (
            _CONFIDENCE_ORDER[base_confidence]
            + corroboration_boost
            - counter_penalty
            + coverage_factor
            + category_adjustment
        )

        # Map score to confidence level
        final_confidence = self._score_to_confidence(score)

        # Spec 7.2: a group-derived claim must never exceed any supporting
        # evidence's interpretation_confidence by two or more levels.
        if verified_correlation is not None and supporting:
            min_interp_order = min(
                _CONFIDENCE_ORDER[e.interpretation_confidence]
                for e in supporting
            )
            cap_order = min(
                min_interp_order + 1,
                _CONFIDENCE_ORDER[ConfidenceLevel.CONFIRMED],
            )
            if _CONFIDENCE_ORDER[final_confidence] > cap_order:
                final_confidence = self._order_to_confidence(cap_order)

        # Build explanation
        basis_parts: list[str] = []

        basis_parts.append(
            f"Base confidence from evidence: {base_confidence.value}"
        )

        if corroboration_boost > 0:
            source_count = self._count_independent_sources(supporting)
            basis_parts.append(
                f"Corroboration from {source_count} independent sources (+{corroboration_boost})"
            )

        if counter_penalty > 0:
            basis_parts.append(
                f"Counter-evidence penalty: {len(counter)} item(s) (-{counter_penalty})"
            )

        if coverage_factor != 0:
            coverage_desc = "good" if coverage_factor > 0 else "limited"
            basis_parts.append(f"Data coverage: {coverage_desc} ({coverage_factor:+d})")

        if category_adjustment != 0:
            basis_parts.append(
                f"Category '{claim_category.value}' adjustment ({category_adjustment:+d})"
            )

        basis_parts.append(f"Final confidence: {final_confidence.value}")

        # Check if confidence is elevated above any single evidence item
        min_interp_confidence = min(
            _CONFIDENCE_ORDER[e.interpretation_confidence] for e in supporting
        )
        if _CONFIDENCE_ORDER[final_confidence] > min_interp_confidence:
            basis_parts.append(
                "ELEVATION: Confidence elevated above weakest single evidence "
                "interpretation_confidence due to corroborating sources and "
                "multi-factor analysis. Requires explicit analyst approval."
            )

        basis_explanation = "; ".join(basis_parts)

        return (final_confidence, basis_explanation)

    def apply_expression_policy(
        self, claim: Claim, policy: ExpressionPolicy
    ) -> Claim:
        """Apply expression policy to set recommended and prohibited expressions.

        Uses the ExpressionPolicy from the CaseManifest to determine which
        expressions are recommended and which are prohibited for this claim,
        based on its confidence_level and claim_category.

        Requirement 11.6: Apply the Expression_Policy to determine
        recommended_expressions and prohibited_expressions for each Claim
        based on its Confidence_Level.

        Args:
            claim: The claim to annotate with expression guidance.
            policy: The expression policy from the case manifest.

        Returns:
            The claim updated with recommended_expressions and
            prohibited_expressions set according to the policy.
        """
        rule = policy.get_rule(claim.confidence_level, claim.claim_category)

        claim.recommended_expressions = list(rule.recommended_expressions)
        claim.prohibited_expressions = list(rule.prohibited_expressions)

        return claim

    # --- Private helper methods ---

    def _group_evidence_for_claims(
        self, entries: list[EvidenceLedgerEntry]
    ) -> list[dict]:
        """Group evidence entries into claim-forming clusters.

        Each group becomes a potential claim. Groups are formed based on
        the interpretation text, which indicates what the evidence means
        for the investigation.

        Args:
            entries: Active (non-withdrawn) evidence ledger entries.

        Returns:
            List of claim group dicts with keys:
            - supporting: list of EvidenceLedgerEntry
            - interpretation: the shared interpretation text
            - category: inferred ClaimCategory
            - report_section: inferred report section
        """
        # Group entries by interpretation similarity
        # For now, each unique interpretation forms its own claim group.
        # In a production system, this would use semantic similarity.
        groups: list[dict] = []
        seen_evidence_ids: set[str] = set()

        for entry in entries:
            if entry.evidence_id in seen_evidence_ids:
                continue

            # Find related entries (same interpretation or closely related)
            related = self._find_related_entries(entry, entries, seen_evidence_ids)
            all_entries_in_group = [entry] + related

            for e in all_entries_in_group:
                seen_evidence_ids.add(e.evidence_id)

            category = self._infer_claim_category(entry)
            report_section = self._infer_report_section(category)

            groups.append({
                "supporting": all_entries_in_group,
                "interpretation": entry.interpretation,
                "category": category,
                "report_section": report_section,
            })

        return groups

    def _find_related_entries(
        self,
        target: EvidenceLedgerEntry,
        all_entries: list[EvidenceLedgerEntry],
        already_grouped: set[str],
    ) -> list[EvidenceLedgerEntry]:
        """Find evidence entries related to the target entry.

        Looks for entries with the same interpretation text, indicating
        they support the same claim from different sources.

        Args:
            target: The entry to find related entries for.
            all_entries: All active evidence entries.
            already_grouped: Set of evidence_ids already in other groups.

        Returns:
            List of related entries (excluding target itself).
        """
        related: list[EvidenceLedgerEntry] = []

        for entry in all_entries:
            if entry.evidence_id == target.evidence_id:
                continue
            if entry.evidence_id in already_grouped:
                continue
            # Same interpretation means same claim
            if entry.interpretation == target.interpretation:
                related.append(entry)

        return related

    def _build_single_claim(
        self,
        group: dict,
        all_entries: list[EvidenceLedgerEntry],
        coverage: list[DataCoverageEntry],
    ) -> Optional[Claim]:
        """Build a single claim from a grouped set of evidence.

        Requirement 11.4: No claim without at least one supporting evidence_id.

        Args:
            group: Claim group dict with supporting entries and metadata.
            all_entries: All active evidence entries (for counter-evidence).
            coverage: Data coverage entries.

        Returns:
            Claim object or None if the group has no supporting evidence.
        """
        supporting: list[EvidenceLedgerEntry] = group["supporting"]

        # Requirement 11.4: Must have at least one supporting evidence_id
        if not supporting:
            return None

        category: ClaimCategory = group["category"]
        report_section: str = group["report_section"]

        # Identify counter-evidence
        counter = self._find_counter_evidence(supporting, all_entries)

        # Restrict coverage to the sources this claim's evidence actually came
        # from. A claim grounded in analyzed sources must not be downgraded
        # because unrelated sources (e.g. DNS/proxy logs never in scope) are
        # missing. When no relevant coverage exists, an empty list is passed,
        # which the coverage assessment treats as neutral. (UP-02)
        relevant_coverage = self._select_relevant_coverage(supporting, coverage)

        # Calculate confidence (Requirement 11.3, 11.5)
        confidence_level, confidence_basis = self.calculate_confidence(
            claim_category=category,
            supporting=supporting,
            counter=counter,
            coverage=relevant_coverage,
        )

        # Identify limitations
        limitations = self._identify_limitations(supporting, relevant_coverage)

        # Identify missing evidence
        missing_evidence = self._identify_missing_evidence(relevant_coverage)

        # Build claim text from the group interpretation
        claim_text = group["interpretation"]

        claim = Claim(
            claim_id=f"CLM-{uuid4().hex[:8]}",
            report_section=report_section,
            claim_text=claim_text,
            claim_category=category,
            confidence_level=confidence_level,
            confidence_basis=confidence_basis,
            supporting_evidence=[e.evidence_id for e in supporting],
            counter_evidence=[e.evidence_id for e in counter],
            limitations=limitations,
            missing_evidence=missing_evidence,
            recommended_expressions=[],
            prohibited_expressions=[],
            review_status="pending",
            attack_mappings=self._propagate_attack_candidates(supporting),
        )

        return claim

    def merge_attack_mapping_records(
        self,
        claims: list[Claim],
        records: list[dict],
        ledger: list[EvidenceLedgerEntry],
    ) -> list[Claim]:
        """Merge evidence-level ATT&CK records (attack_mappings.jsonl) into
        claims whose supporting evidence backs them (spec 8.1).

        Used when evidence entries carry no inline attack_mapping_candidates
        because the mappings were produced separately by map-attack.
        Confidence never exceeds the backing evidence's
        interpretation_confidence, and same technique_id collapses to one
        mapping per claim.
        """
        interp_by_id = {
            e.evidence_id: e.interpretation_confidence
            for e in ledger
            if not e.withdrawn
        }

        by_evidence: dict[str, list[dict]] = {}
        for record in records:
            eid = record.get("evidence_id")
            if eid and record.get("technique_id"):
                by_evidence.setdefault(eid, []).append(record)

        for claim in claims:
            existing = {m.technique_id: m for m in claim.attack_mappings}
            for eid in claim.supporting_evidence:
                interp = interp_by_id.get(eid)
                if interp is None:
                    continue
                for record in by_evidence.get(eid, []):
                    try:
                        level = ConfidenceLevel(
                            record.get("confidence", "possible")
                        )
                    except ValueError:
                        level = ConfidenceLevel.POSSIBLE
                    if _CONFIDENCE_ORDER[level] > _CONFIDENCE_ORDER[interp]:
                        level = interp
                    tid = record["technique_id"]
                    mapping = existing.get(tid)
                    if mapping is None:
                        mapping = ATTCKMapping(
                            tactic=record.get("tactic", ""),
                            technique_id=tid,
                            technique_name=record.get("technique_name", ""),
                            confidence=level,
                            mapping_reason=record.get("mapping_reason", ""),
                            supporting_evidence=[eid],
                        )
                        existing[tid] = mapping
                        claim.attack_mappings.append(mapping)
                    elif eid not in mapping.supporting_evidence:
                        mapping.supporting_evidence.append(eid)
        return claims

    def _propagate_attack_candidates(
        self, supporting: list[EvidenceLedgerEntry]
    ) -> list[ATTCKMapping]:
        """Carry evidence-level ATT&CK candidates onto the claim (spec 8.1).

        Same technique_id collapses to one mapping with the supporting
        evidence ids retained; confidence never exceeds the interpretation
        confidence of the evidence backing the mapping.
        """
        merged: dict[str, ATTCKMapping] = {}
        for entry in supporting:
            interp_order = _CONFIDENCE_ORDER[entry.interpretation_confidence]
            for cand in entry.attack_mapping_candidates or []:
                level = cand.confidence
                if _CONFIDENCE_ORDER[level] > interp_order:
                    level = entry.interpretation_confidence
                existing = merged.get(cand.technique_id)
                if existing is None:
                    merged[cand.technique_id] = ATTCKMapping(
                        tactic=cand.tactic,
                        technique_id=cand.technique_id,
                        technique_name=cand.technique_name,
                        confidence=level,
                        mapping_reason=cand.mapping_reason,
                        supporting_evidence=[entry.evidence_id],
                    )
                else:
                    if entry.evidence_id not in existing.supporting_evidence:
                        existing.supporting_evidence.append(entry.evidence_id)
                    if _CONFIDENCE_ORDER[level] > _CONFIDENCE_ORDER[
                        existing.confidence
                    ]:
                        existing.confidence = level
        return list(merged.values())

    def _infer_claim_category(
        self, entry: EvidenceLedgerEntry
    ) -> ClaimCategory:
        """Infer the claim category from an evidence entry.

        Uses heuristics based on interpretation text and observed event
        content to determine which claim category best fits.

        Args:
            entry: The primary evidence entry for the claim.

        Returns:
            The inferred ClaimCategory.
        """
        interpretation_lower = entry.interpretation.lower()
        observed_event = entry.observed_event or {}

        # Check for attribution indicators
        if any(
            keyword in interpretation_lower
            for keyword in ("attacker", "threat actor", "attributed", "apt", "group")
        ):
            return ClaimCategory.ATTRIBUTION_ASSESSMENT

        # Check for data exfiltration indicators
        if any(
            keyword in interpretation_lower
            for keyword in ("exfiltrat", "data theft", "data leak", "stolen data")
        ):
            return ClaimCategory.DATA_EXFILTRATION_ASSESSMENT

        # Check for intrusion vector indicators
        if any(
            keyword in interpretation_lower
            for keyword in (
                "initial access", "entry point", "exploit", "phishing",
                "intrusion vector", "compromise vector",
            )
        ):
            return ClaimCategory.INTRUSION_VECTOR_ASSESSMENT

        # Check for impact indicators
        if any(
            keyword in interpretation_lower
            for keyword in ("impact", "damage", "affected", "disruption", "loss")
        ):
            return ClaimCategory.IMPACT_ASSESSMENT

        # Check for causal relationship indicators
        if any(
            keyword in interpretation_lower
            for keyword in ("caused", "led to", "resulted in", "because", "therefore")
        ):
            return ClaimCategory.CAUSAL_RELATIONSHIP

        # Check if it's a direct observation vs interpretation
        if entry.observed_fact_confidence == ConfidenceLevel.CONFIRMED:
            # If the observed fact is confirmed and interpretation is simple
            if entry.interpretation_confidence == ConfidenceLevel.CONFIRMED:
                return ClaimCategory.OBSERVED_FACT

        return ClaimCategory.INTERPRETATION

    def _infer_report_section(self, category: ClaimCategory) -> str:
        """Infer the report section based on claim category.

        Args:
            category: The claim category.

        Returns:
            Suggested report section name.
        """
        section_map: dict[ClaimCategory, str] = {
            ClaimCategory.OBSERVED_FACT: "findings",
            ClaimCategory.INTERPRETATION: "analysis",
            ClaimCategory.CAUSAL_RELATIONSHIP: "analysis",
            ClaimCategory.IMPACT_ASSESSMENT: "impact",
            ClaimCategory.DATA_EXFILTRATION_ASSESSMENT: "data_exfiltration",
            ClaimCategory.INTRUSION_VECTOR_ASSESSMENT: "intrusion_vector",
            ClaimCategory.ATTRIBUTION_ASSESSMENT: "attribution",
        }
        return section_map.get(category, "analysis")

    def _find_counter_evidence(
        self,
        supporting: list[EvidenceLedgerEntry],
        all_entries: list[EvidenceLedgerEntry],
    ) -> list[EvidenceLedgerEntry]:
        """Find evidence that contradicts the claim's supporting evidence.

        Looks for entries whose interpretation contradicts the supporting
        evidence's interpretation. Uses simple heuristic: entries with
        opposing observed facts for the same host/event.

        Args:
            supporting: Evidence entries supporting this claim.
            all_entries: All active evidence entries.

        Returns:
            List of entries that contradict the claim.
        """
        supporting_ids = {e.evidence_id for e in supporting}
        counter: list[EvidenceLedgerEntry] = []

        # Simple heuristic: entries about the same host/event with
        # different interpretations that weren't in our supporting group
        supporting_hosts = set()
        for e in supporting:
            host = (e.observed_event or {}).get("host")
            if host:
                supporting_hosts.add(host)

        for entry in all_entries:
            if entry.evidence_id in supporting_ids:
                continue

            entry_host = (entry.observed_event or {}).get("host")
            if entry_host and entry_host in supporting_hosts:
                # Check if interpretation suggests contradiction
                if self._interpretations_contradict(
                    supporting[0].interpretation, entry.interpretation
                ):
                    counter.append(entry)

        return counter

    def _interpretations_contradict(
        self, interp_a: str, interp_b: str
    ) -> bool:
        """Check if two interpretations appear to contradict each other.

        Simple heuristic checking for negation patterns and opposing terms.

        Args:
            interp_a: First interpretation text.
            interp_b: Second interpretation text.

        Returns:
            True if interpretations appear to contradict.
        """
        negation_pairs = [
            ("confirmed", "not confirmed"),
            ("successful", "unsuccessful"),
            ("compromised", "not compromised"),
            ("accessed", "not accessed"),
            ("exfiltrated", "no exfiltration"),
        ]

        a_lower = interp_a.lower()
        b_lower = interp_b.lower()

        for positive, negative in negation_pairs:
            if (positive in a_lower and negative in b_lower) or (
                negative in a_lower and positive in b_lower
            ):
                return True

        return False

    def _assess_base_confidence(
        self, supporting: list[EvidenceLedgerEntry]
    ) -> ConfidenceLevel:
        """Assess the base confidence from supporting evidence.

        Uses the modal (most common) interpretation confidence as the
        baseline, rather than mechanically using the weakest item.

        Args:
            supporting: Supporting evidence entries.

        Returns:
            Base confidence level.
        """
        if not supporting:
            return ConfidenceLevel.UNKNOWN

        # Count occurrences of each interpretation confidence level
        confidence_counts: dict[ConfidenceLevel, int] = {}
        for entry in supporting:
            level = entry.interpretation_confidence
            confidence_counts[level] = confidence_counts.get(level, 0) + 1

        # Use the most common (modal) confidence as base
        # In case of tie, pick the higher confidence
        max_count = max(confidence_counts.values())
        candidates = [
            level for level, count in confidence_counts.items()
            if count == max_count
        ]

        # Sort by confidence order (highest first) and pick the highest
        candidates.sort(key=lambda c: _CONFIDENCE_ORDER[c], reverse=True)
        return candidates[0]

    def _assess_corroboration(
        self, supporting: list[EvidenceLedgerEntry]
    ) -> int:
        """Assess corroboration bonus from multiple independent sources.

        Multiple independent source references strengthen confidence.

        Args:
            supporting: Supporting evidence entries.

        Returns:
            Integer boost value (0, 1, or 2).
        """
        source_count = self._count_independent_sources(supporting)

        if source_count >= 3:
            return 1  # Strong corroboration
        elif source_count >= 2:
            return 1  # Moderate corroboration from 2+ independent sources
        return 0  # Single source, no corroboration bonus

    def _has_strictly_independent_sources(
        self, entries: list[EvidenceLedgerEntry]
    ) -> bool:
        """Strict independence per spec 7.2: at least two entries with
        different source files AND (different hosts or different data
        source types). Multiple lines of the same log/export never count
        as independent corroboration.
        """
        source_files: set[str] = set()
        hosts: set[str] = set()
        ds_types: set[str] = set()
        for entry in entries:
            for ref in entry.source_refs or []:
                source_files.add(ref.source_file_id)
                ds_types.add(infer_data_source_type(ref.source_path))
            host = str((entry.observed_event or {}).get("host") or "").lower()
            if host:
                hosts.add(host)
        return (
            len(source_files) >= 2
            and (len(hosts) >= 2 or len(ds_types) >= 2)
        )

    def _order_to_confidence(self, order: int) -> ConfidenceLevel:
        """Inverse of _CONFIDENCE_ORDER."""
        for level, value in _CONFIDENCE_ORDER.items():
            if value == order:
                return level
        return ConfidenceLevel.UNKNOWN

    def _count_independent_sources(
        self, entries: list[EvidenceLedgerEntry]
    ) -> int:
        """Count independent source files across evidence entries.

        Args:
            entries: Evidence entries to analyze.

        Returns:
            Number of distinct source files referenced.
        """
        source_file_ids: set[str] = set()
        for entry in entries:
            for ref in entry.source_refs:
                source_file_ids.add(ref.source_file_id)
        return len(source_file_ids)

    def _assess_counter_evidence(
        self, counter: list[EvidenceLedgerEntry]
    ) -> int:
        """Assess penalty from counter-evidence.

        Counter-evidence reduces confidence. Stronger counter-evidence
        has a larger penalty.

        Args:
            counter: Counter-evidence entries.

        Returns:
            Integer penalty value (0, 1, or 2).
        """
        if not counter:
            return 0

        # Check strength of counter-evidence
        strong_counter = sum(
            1 for e in counter
            if _CONFIDENCE_ORDER[e.interpretation_confidence]
            >= _CONFIDENCE_ORDER[ConfidenceLevel.PROBABLE]
        )

        if strong_counter >= 2:
            return 2  # Strong counter-evidence from multiple sources
        elif strong_counter >= 1:
            return 1  # Some strong counter-evidence
        elif len(counter) >= 1:
            return 1  # Weak counter-evidence still reduces confidence
        return 0

    def _select_relevant_coverage(
        self,
        supporting: list[EvidenceLedgerEntry],
        coverage: list[DataCoverageEntry],
    ) -> list[DataCoverageEntry]:
        """Return coverage entries relevant to a claim's supporting evidence.

        Relevance is by the (host, data_source_type) pairs the supporting
        evidence was drawn from. Sources unrelated to the claim (for example
        DNS/proxy logs that were never in scope) are excluded so their absence
        does not lower the claim's confidence. (UP-02)
        """
        if not coverage:
            return []
        relevant_keys: set[tuple[str, str]] = set()
        for entry in supporting:
            observed = entry.observed_event or {}
            host = observed.get("host") or ""
            for sr in entry.source_refs or []:
                path = getattr(sr, "source_path", "") or ""
                host_h = host or (path.split("/", 1)[0] if "/" in path else "")
                relevant_keys.add((host_h, infer_data_source_type(path)))
        return [
            c for c in coverage
            if (c.host_or_system, c.data_source_type) in relevant_keys
        ]

    def _assess_data_coverage(
        self, coverage: list[DataCoverageEntry]
    ) -> int:
        """Assess data coverage quality.

        Good coverage (all relevant sources available) supports confidence.
        Poor coverage (missing sources) reduces confidence.

        Args:
            coverage: Data coverage entries.

        Returns:
            Integer adjustment (-1, 0, or 1).
        """
        if not coverage:
            return 0

        available_count = sum(
            1 for c in coverage
            if c.availability_status in ("available", "partially_available")
        )
        unavailable_count = sum(
            1 for c in coverage
            if c.availability_status in ("unavailable", "outside_scope", "unknown")
        )

        total = available_count + unavailable_count
        if total == 0:
            return 0

        coverage_ratio = available_count / total

        if coverage_ratio >= 0.8:
            return 0  # Good coverage, no adjustment needed
        elif coverage_ratio >= 0.5:
            return 0  # Adequate coverage
        else:
            return -1  # Poor coverage, reduce confidence

    def _assess_category_requirement(
        self, category: ClaimCategory,
    ) -> int:
        """Assess category-specific confidence adjustment.

        Some claim categories inherently require stronger evidence
        (e.g., attribution, causal relationships) and receive a
        downward adjustment to avoid overconfidence.

        Args:
            category: The claim category.

        Returns:
            Integer adjustment (typically -1 or 0).
        """
        if category in _HIGH_EVIDENCE_THRESHOLD_CATEGORIES:
            return -1  # Requires stronger evidence for same confidence
        return 0

    def _score_to_confidence(self, score: float) -> ConfidenceLevel:
        """Map a numerical score to a ConfidenceLevel.

        Score ranges:
        - >= 4: CONFIRMED
        - >= 3: PROBABLE
        - >= 2: POSSIBLE
        - >= 1: UNKNOWN
        - < 1: NOT_OBSERVED

        Args:
            score: Numerical confidence score.

        Returns:
            Corresponding ConfidenceLevel.
        """
        if score >= 4:
            return ConfidenceLevel.CONFIRMED
        elif score >= 3:
            return ConfidenceLevel.PROBABLE
        elif score >= 2:
            return ConfidenceLevel.POSSIBLE
        elif score >= 1:
            return ConfidenceLevel.UNKNOWN
        else:
            return ConfidenceLevel.NOT_OBSERVED

    def _identify_limitations(
        self,
        supporting: list[EvidenceLedgerEntry],
        coverage: list[DataCoverageEntry],
    ) -> list[str]:
        """Identify limitations relevant to this claim.

        Args:
            supporting: Supporting evidence entries.
            coverage: Data coverage entries.

        Returns:
            List of limitation description strings.
        """
        limitations: list[str] = []

        # Check for single-source claims
        source_count = self._count_independent_sources(supporting)
        if source_count == 1:
            limitations.append("Based on single source only")

        # Check for weak evidence
        weak_count = sum(
            1 for e in supporting
            if _CONFIDENCE_ORDER[e.interpretation_confidence]
            <= _CONFIDENCE_ORDER[ConfidenceLevel.POSSIBLE]
        )
        if weak_count > 0 and weak_count == len(supporting):
            limitations.append("All supporting evidence has low interpretation confidence")

        # Check coverage gaps
        unavailable = [
            c for c in coverage
            if c.availability_status in ("unavailable", "outside_scope")
        ]
        for entry in unavailable:
            if entry.impact_on_findings:
                limitations.append(
                    f"Data source '{entry.data_source_type}' on "
                    f"'{entry.host_or_system}' is {entry.availability_status}: "
                    f"{entry.impact_on_findings}"
                )

        return limitations

    def _identify_missing_evidence(
        self, coverage: list[DataCoverageEntry]
    ) -> list[str]:
        """Identify evidence that would strengthen or refute this claim.

        Args:
            coverage: Data coverage entries.

        Returns:
            List of missing evidence description strings.
        """
        missing: list[str] = []

        for entry in coverage:
            if entry.availability_status in (
                "unavailable", "pending_collection", "not_requested"
            ):
                missing.append(
                    f"{entry.data_source_type} from {entry.host_or_system} "
                    f"({entry.availability_status})"
                )

        return missing
