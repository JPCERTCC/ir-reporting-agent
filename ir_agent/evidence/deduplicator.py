"""Evidence Deduplication for the IR Reporting Support Agent.

Implements evidence candidate deduplication by comparing observed_fact
similarity and overlapping source references. Handles merging of duplicate
candidates, confidence recalculation, and grouping of corroborating evidence.

Validates Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
"""

from __future__ import annotations

import uuid
from typing import Optional

from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceCandidate


# Threshold for word overlap similarity to consider candidates as duplicates
DUPLICATE_SIMILARITY_THRESHOLD = 0.7

# Threshold for word overlap similarity to consider candidates as corroborating
CORROBORATING_SIMILARITY_THRESHOLD = 0.4


def _tokenize(text: str) -> set[str]:
    """Tokenize text into lowercase word tokens for comparison."""
    return set(text.lower().split())


def _word_overlap_similarity(text_a: str, text_b: str) -> float:
    """Compute Jaccard similarity based on word overlap.

    Returns a value between 0.0 and 1.0, where 1.0 means identical word sets.
    """
    tokens_a = _tokenize(text_a)
    tokens_b = _tokenize(text_b)
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)


def _source_refs_overlap(refs_a: list[SourceReference], refs_b: list[SourceReference]) -> bool:
    """Check if two source reference lists have overlapping sources.

    Overlap is defined as sharing a source_file_id with overlapping line ranges.
    """
    for ref_a in refs_a:
        for ref_b in refs_b:
            if ref_a.source_file_id == ref_b.source_file_id:
                # Check line range overlap
                a_start, a_end = ref_a.source_lines
                b_start, b_end = ref_b.source_lines
                if a_start <= b_end and b_start <= a_end:
                    return True
    return False


def _count_independent_sources(source_refs: list[SourceReference]) -> int:
    """Count the number of independent source files in the reference list."""
    unique_files = set(ref.source_file_id for ref in source_refs)
    return len(unique_files)


def _assess_source_reliability(source_refs: list[SourceReference]) -> float:
    """Assess reliability of sources based on available metadata.

    Returns a score between 0.0 and 1.0.
    Sources with parser_name (rule-based extraction) are considered more reliable
    than those without (LLM extraction).
    """
    if not source_refs:
        return 0.0
    reliable_count = sum(1 for ref in source_refs if ref.parser_name is not None)
    return reliable_count / len(source_refs)


def _assess_directness(source_refs: list[SourceReference]) -> float:
    """Assess directness of observation based on excerpt characteristics.

    A longer excerpt generally indicates a more direct observation.
    Returns a score between 0.0 and 1.0.
    """
    if not source_refs:
        return 0.0
    # Heuristic: excerpts with more content tend to be more direct observations
    scores = []
    for ref in source_refs:
        excerpt_len = len(ref.excerpt)
        if excerpt_len > 200:
            scores.append(1.0)
        elif excerpt_len > 100:
            scores.append(0.8)
        elif excerpt_len > 50:
            scores.append(0.6)
        else:
            scores.append(0.4)
    return sum(scores) / len(scores)


def _assess_consistency(candidates: list[EvidenceCandidate]) -> float:
    """Assess consistency between candidate observed facts and interpretations.

    Higher consistency means the candidates agree on what was observed.
    Returns a score between 0.0 and 1.0.
    """
    if len(candidates) <= 1:
        return 1.0

    # Compare all pairs of observed_facts
    similarities = []
    for i in range(len(candidates)):
        for j in range(i + 1, len(candidates)):
            sim = _word_overlap_similarity(
                candidates[i].observed_fact,
                candidates[j].observed_fact,
            )
            similarities.append(sim)

    return sum(similarities) / len(similarities) if similarities else 1.0


class EvidenceDeduplicator:
    """Identifies and merges duplicate evidence candidates.

    Implements deduplication logic based on observed_fact similarity
    and source reference overlap. Supports multi-factor confidence
    recalculation and corroborating evidence grouping.
    """

    def __init__(
        self,
        duplicate_threshold: float = DUPLICATE_SIMILARITY_THRESHOLD,
        corroborating_threshold: float = CORROBORATING_SIMILARITY_THRESHOLD,
    ) -> None:
        self.duplicate_threshold = duplicate_threshold
        self.corroborating_threshold = corroborating_threshold

    def find_duplicates(
        self, candidates: list[EvidenceCandidate]
    ) -> list[tuple[list[str], str]]:
        """Identify candidates that describe the same observed event.

        Compares candidates based on observed_fact similarity and overlapping
        source_refs. Two candidates are duplicates if they have high text
        similarity in their observed_fact AND share overlapping source data.

        Args:
            candidates: List of evidence candidates to check for duplicates.

        Returns:
            List of (candidate_id_groups, merge_reason) tuples where each group
            contains candidate_ids that should be merged together.
        """
        if len(candidates) <= 1:
            return []

        # Track which candidates have already been grouped
        grouped: set[str] = set()
        duplicate_groups: list[tuple[list[str], str]] = []

        for i, cand_a in enumerate(candidates):
            if cand_a.candidate_id in grouped:
                continue

            group = [cand_a.candidate_id]
            reasons: list[str] = []

            for j in range(i + 1, len(candidates)):
                cand_b = candidates[j]
                if cand_b.candidate_id in grouped:
                    continue

                # Check observed_fact similarity
                fact_similarity = _word_overlap_similarity(
                    cand_a.observed_fact, cand_b.observed_fact
                )

                # Check source reference overlap
                has_overlap = _source_refs_overlap(
                    cand_a.source_refs, cand_b.source_refs
                )

                # Candidates are duplicates if they have high text similarity
                # AND either overlap in source data or describe very similar events
                if fact_similarity >= self.duplicate_threshold and has_overlap:
                    group.append(cand_b.candidate_id)
                    grouped.add(cand_b.candidate_id)
                    reasons.append(
                        f"observed_fact similarity={fact_similarity:.2f} "
                        f"with overlapping source references"
                    )
                elif fact_similarity >= 0.9:
                    # Very high similarity even without source overlap
                    # (same event reported from different sources)
                    group.append(cand_b.candidate_id)
                    grouped.add(cand_b.candidate_id)
                    reasons.append(
                        f"very high observed_fact similarity={fact_similarity:.2f} "
                        f"(same event from different sources)"
                    )

            if len(group) > 1:
                grouped.add(cand_a.candidate_id)
                merge_reason = "; ".join(reasons) if reasons else "duplicate observed events"
                duplicate_groups.append((group, merge_reason))

        return duplicate_groups

    def merge_candidates(
        self,
        candidate_ids: list[str],
        candidates: list[EvidenceCandidate],
    ) -> EvidenceCandidate:
        """Merge multiple candidates into a single candidate.

        Preserves all source references from all originals and generates
        a new candidate_id for the merged result. Recalculates confidence
        based on multi-factor analysis rather than taking the highest.

        Args:
            candidate_ids: List of candidate_ids to merge.
            candidates: Full list of candidates to search within.

        Returns:
            A new merged EvidenceCandidate with all source_refs preserved.

        Raises:
            ValueError: If no candidates match the provided IDs.
        """
        # Find the candidates to merge
        to_merge = [c for c in candidates if c.candidate_id in candidate_ids]
        if not to_merge:
            raise ValueError(
                f"No candidates found matching IDs: {candidate_ids}"
            )

        # Collect all source references (preserving each original's refs)
        all_source_refs: list[SourceReference] = []
        seen_ref_ids: set[str] = set()
        for cand in to_merge:
            for ref in cand.source_refs:
                if ref.source_ref_id not in seen_ref_ids:
                    all_source_refs.append(ref)
                    seen_ref_ids.add(ref.source_ref_id)

        # Recalculate confidence based on merged sources
        fact_confidence, fact_rationale = self.recalculate_confidence(
            all_source_refs, to_merge
        )

        # For interpretation confidence, use the same multi-factor analysis
        # but factor in the interpretation consistency
        interp_consistency = self._assess_interpretation_consistency(to_merge)
        interp_confidence, _ = self.recalculate_confidence(
            all_source_refs, to_merge, is_interpretation=True
        )

        # Use the first candidate as the base for observed_event and text fields
        # (they describe the same event, so the first is representative)
        base = to_merge[0]

        # Merge observed_event dictionaries
        merged_event = dict(base.observed_event)
        for cand in to_merge[1:]:
            for key, value in cand.observed_event.items():
                if key not in merged_event:
                    merged_event[key] = value

        # Merge ATT&CK mappings (deduplicate by technique_id)
        seen_techniques: set[str] = set()
        merged_attack_mappings = []
        for cand in to_merge:
            for mapping in cand.attack_mapping_candidates:
                if mapping.technique_id not in seen_techniques:
                    merged_attack_mappings.append(mapping)
                    seen_techniques.add(mapping.technique_id)

        # Merge from_normalized_event_ids
        merged_event_ids: list[str] = []
        seen_event_ids: set[str] = set()
        for cand in to_merge:
            for eid in cand.from_normalized_event_ids:
                if eid not in seen_event_ids:
                    merged_event_ids.append(eid)
                    seen_event_ids.add(eid)

        # Generate new candidate_id for the merged result
        new_candidate_id = f"merged-{uuid.uuid4().hex[:12]}"

        return EvidenceCandidate(
            candidate_id=new_candidate_id,
            source_refs=all_source_refs,
            observed_event=merged_event,
            observed_fact=base.observed_fact,
            interpretation=base.interpretation,
            observed_fact_confidence=fact_confidence,
            interpretation_confidence=interp_confidence,
            attack_mapping_candidates=merged_attack_mappings,
            from_normalized_event_ids=merged_event_ids,
            candidate_status="merged",
            review_status="pending",
        )

    def recalculate_confidence(
        self,
        merged_sources: list[SourceReference],
        candidates: Optional[list[EvidenceCandidate]] = None,
        is_interpretation: bool = False,
    ) -> tuple[ConfidenceLevel, str]:
        """Recalculate confidence based on multi-factor analysis.

        Factors considered:
        1. Number of independent sources
        2. Source reliability (rule-based vs LLM extraction)
        3. Directness of observation (excerpt detail)
        4. Consistency between sources
        5. Limitations/counter-evidence indicators

        This does NOT simply take the highest confidence from source candidates.

        Args:
            merged_sources: All source references from merged candidates.
            candidates: Optional list of original candidates for consistency check.
            is_interpretation: Whether recalculating for interpretation confidence.

        Returns:
            Tuple of (ConfidenceLevel, rationale_string) explaining the assessment.
        """
        if not merged_sources:
            return ConfidenceLevel.UNKNOWN, "No source references available"

        # Factor 1: Number of independent sources (0-25 points)
        independent_count = _count_independent_sources(merged_sources)
        if independent_count >= 3:
            source_count_score = 25.0
        elif independent_count == 2:
            source_count_score = 18.0
        else:
            source_count_score = 10.0

        # Factor 2: Source reliability (0-25 points)
        reliability = _assess_source_reliability(merged_sources)
        reliability_score = reliability * 25.0

        # Factor 3: Directness of observation (0-25 points)
        directness = _assess_directness(merged_sources)
        directness_score = directness * 25.0

        # Factor 4: Consistency between sources (0-25 points)
        if candidates and len(candidates) > 1:
            consistency = _assess_consistency(candidates)
        else:
            consistency = 1.0
        consistency_score = consistency * 25.0

        # Factor 5: Limitations/counter-evidence (penalty, 0 to -20 points)
        limitation_penalty = 0.0
        if candidates:
            for cand in candidates:
                # Check for limitation indicators in interpretation
                limitation_keywords = [
                    "however", "but", "limitation", "unclear",
                    "insufficient", "contradicts", "inconsistent",
                    "counter", "despite",
                ]
                interp_lower = cand.interpretation.lower()
                for keyword in limitation_keywords:
                    if keyword in interp_lower:
                        limitation_penalty += 2.0
                        break  # Only penalize once per candidate

        # Calculate total score (0-100, minus penalties)
        total_score = (
            source_count_score
            + reliability_score
            + directness_score
            + consistency_score
            - limitation_penalty
        )
        total_score = max(0.0, min(100.0, total_score))

        # Apply interpretation penalty (interpretations are inherently less certain)
        if is_interpretation:
            total_score *= 0.8

        # Map score to confidence level
        if total_score >= 80:
            confidence = ConfidenceLevel.CONFIRMED
        elif total_score >= 60:
            confidence = ConfidenceLevel.PROBABLE
        elif total_score >= 35:
            confidence = ConfidenceLevel.POSSIBLE
        else:
            confidence = ConfidenceLevel.UNKNOWN

        # Build rationale
        rationale_parts = [
            f"independent_sources={independent_count} (score={source_count_score:.0f}/25)",
            f"reliability={reliability:.2f} (score={reliability_score:.0f}/25)",
            f"directness={directness:.2f} (score={directness_score:.0f}/25)",
            f"consistency={consistency:.2f} (score={consistency_score:.0f}/25)",
        ]
        if limitation_penalty > 0:
            rationale_parts.append(
                f"limitation_penalty=-{limitation_penalty:.0f}"
            )
        rationale_parts.append(f"total_score={total_score:.0f}/100")
        rationale = "; ".join(rationale_parts)

        return confidence, rationale

    def group_corroborating(
        self, candidates: list[EvidenceCandidate]
    ) -> list[list[str]]:
        """Group related but non-duplicate candidates as corroborating evidence.

        Identifies candidates that are related (e.g., same incident from different
        angles) but are NOT exact duplicates. These provide corroborating context
        rather than requiring merge.

        Args:
            candidates: List of evidence candidates to group.

        Returns:
            List of candidate_id groups where each group contains IDs of
            corroborating candidates.
        """
        if len(candidates) <= 1:
            return []

        # First, identify duplicates so we can exclude them from corroboration
        duplicate_groups = self.find_duplicates(candidates)
        duplicate_pairs: set[tuple[str, str]] = set()
        for group_ids, _ in duplicate_groups:
            for i, id_a in enumerate(group_ids):
                for id_b in group_ids[i + 1:]:
                    duplicate_pairs.add((min(id_a, id_b), max(id_a, id_b)))

        # Build corroborating groups
        grouped: set[str] = set()
        corroborating_groups: list[list[str]] = []

        for i, cand_a in enumerate(candidates):
            if cand_a.candidate_id in grouped:
                continue

            group = [cand_a.candidate_id]

            for j in range(i + 1, len(candidates)):
                cand_b = candidates[j]
                if cand_b.candidate_id in grouped:
                    continue

                # Skip if they are already identified as duplicates
                pair_key = (
                    min(cand_a.candidate_id, cand_b.candidate_id),
                    max(cand_a.candidate_id, cand_b.candidate_id),
                )
                if pair_key in duplicate_pairs:
                    continue

                # Check for corroborating relationship:
                # moderate similarity but not high enough for duplicate
                fact_similarity = _word_overlap_similarity(
                    cand_a.observed_fact, cand_b.observed_fact
                )
                interp_similarity = _word_overlap_similarity(
                    cand_a.interpretation, cand_b.interpretation
                )

                # Related if observed_fact or interpretation show moderate similarity
                is_corroborating = (
                    self.corroborating_threshold
                    <= fact_similarity
                    < self.duplicate_threshold
                ) or (
                    interp_similarity >= self.corroborating_threshold
                    and fact_similarity >= 0.2
                )

                # Also check shared normalized event IDs
                if not is_corroborating and cand_a.from_normalized_event_ids and cand_b.from_normalized_event_ids:
                    shared_events = set(cand_a.from_normalized_event_ids) & set(
                        cand_b.from_normalized_event_ids
                    )
                    if shared_events:
                        is_corroborating = True

                if is_corroborating:
                    group.append(cand_b.candidate_id)
                    grouped.add(cand_b.candidate_id)

            if len(group) > 1:
                grouped.add(cand_a.candidate_id)
                corroborating_groups.append(group)

        return corroborating_groups

    def _assess_interpretation_consistency(
        self, candidates: list[EvidenceCandidate]
    ) -> float:
        """Assess how consistent interpretations are across candidates."""
        if len(candidates) <= 1:
            return 1.0

        similarities = []
        for i in range(len(candidates)):
            for j in range(i + 1, len(candidates)):
                sim = _word_overlap_similarity(
                    candidates[i].interpretation,
                    candidates[j].interpretation,
                )
                similarities.append(sim)

        return sum(similarities) / len(similarities) if similarities else 1.0
