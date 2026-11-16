"""Report Planner for the IR Reporting Layer.

Generates a ReportPlan that defines the structure and content of the final
report based on approved claims, timeline, and case manifest. The plan
assigns claims to report sections, links evidence references, and defines
narrative flow.

The report structure follows:
1. Investigation Overview
2. Executive Summary
3. TTP-Based Findings
4. Per-System Findings
5. Remediation Recommendations
6. Appendices (IoC list, ATT&CK mapping)
"""

from __future__ import annotations

from typing import Optional

from ir_agent.models.analysis import Claim, Gap, TimelineEntry
from ir_agent.models.reporting import ReportPlan
from ir_agent.reporting.localization import LocalizationEngine
from ir_agent.steering.manifest import CaseManifest


# Standard report section keys in order
_STANDARD_SECTIONS = [
    "investigation_overview",
    "executive_summary",
    "ttp_based_findings",
    "per_system_findings",
    "remediation_recommendations",
    "limitations",
    "appendix_ioc_list",
    "appendix_attack_mapping",
]


class ReportPlanner:
    """Generates a report plan from approved claims, timeline, and manifest.

    The planner organizes claims into report sections based on their
    report_section field and claim_category, assigns evidence references,
    and defines narrative flow for each section.
    """

    def __init__(self, localization: Optional[LocalizationEngine] = None):
        """Initialize the ReportPlanner.

        Args:
            localization: Optional LocalizationEngine instance. If not provided,
                a default one will be created.
        """
        self._localization = localization or LocalizationEngine()

    def generate_plan(
        self,
        claims: list[Claim],
        timeline: list[TimelineEntry],
        manifest: CaseManifest,
    ) -> ReportPlan:
        """Generate a report plan from approved claims and timeline.

        Creates a ReportPlan with sections, claims assignment, evidence
        references, and narrative flow. Only approved or edited claims
        are included.

        Args:
            claims: List of claims (only approved/edited ones will be used).
            timeline: Chronological timeline entries for narrative ordering.
            manifest: Case manifest with report language and configuration.

        Returns:
            A ReportPlan instance with sections populated.
        """
        language = manifest.report_language
        headers = self._localization.get_section_headers(language)

        # Filter to only approved claims
        approved_claims = [
            c for c in claims if c.review_status in ("approved", "edited")
        ]

        # Build section -> claims mapping
        section_claims = self._assign_claims_to_sections(approved_claims)

        # Build timeline index for narrative ordering
        timeline_index = self._build_timeline_index(timeline)

        # Generate plan sections
        sections: list[dict] = []

        for section_key in _STANDARD_SECTIONS:
            heading = headers.get(section_key, section_key)
            assigned_claims = section_claims.get(section_key, [])

            # Sort claims by timeline order (earliest evidence event first)
            sorted_claims = self._sort_claims_by_timeline(
                assigned_claims, timeline_index
            )

            # Collect all evidence refs for the section
            evidence_refs = []
            for claim in sorted_claims:
                for eid in claim.supporting_evidence:
                    if eid not in evidence_refs:
                        evidence_refs.append(eid)

            # Define narrative flow based on section type
            narrative_flow = self._determine_narrative_flow(
                section_key, sorted_claims, timeline_index
            )

            sections.append(
                {
                    "section_key": section_key,
                    "heading": heading,
                    "claims": [c.claim_id for c in sorted_claims],
                    "evidence_refs": evidence_refs,
                    "narrative_flow": narrative_flow,
                }
            )

        # Determine structure type based on language
        structure_type = "japanese_ir" if language == "ja" else "standard"

        return ReportPlan(sections=sections, structure_type=structure_type)

    def _assign_claims_to_sections(
        self, claims: list[Claim]
    ) -> dict[str, list[Claim]]:
        """Assign claims to report sections based on their report_section field.

        Maps claim report_section values to standard section keys. Claims
        with unrecognized sections are placed in ttp_based_findings as default.

        Args:
            claims: List of approved claims to assign.

        Returns:
            Dictionary mapping section keys to lists of claims.
        """
        section_mapping: dict[str, str] = {
            "investigation_overview": "investigation_overview",
            "executive_summary": "executive_summary",
            "ttp_based_findings": "ttp_based_findings",
            "per_system_findings": "per_system_findings",
            "remediation_recommendations": "remediation_recommendations",
            "limitations": "limitations",
            "appendix_ioc_list": "appendix_ioc_list",
            "appendix_attack_mapping": "appendix_attack_mapping",
            # Common alternative names
            "overview": "investigation_overview",
            "summary": "executive_summary",
            "findings": "ttp_based_findings",
            "ttp_findings": "ttp_based_findings",
            "system_findings": "per_system_findings",
            "remediation": "remediation_recommendations",
            "recommendations": "remediation_recommendations",
            # Fixed chapter taxonomy from the upstream-analysis flow:
            # 3.1-3.7 route to the TTP findings chapter, context to the
            # overview, limitation to the limitations section.
            "3.1": "ttp_based_findings",
            "3.2": "ttp_based_findings",
            "3.3": "ttp_based_findings",
            "3.4": "ttp_based_findings",
            "3.5": "ttp_based_findings",
            "3.6": "ttp_based_findings",
            "3.7": "ttp_based_findings",
            "context": "investigation_overview",
            "limitation": "limitations",
        }

        result: dict[str, list[Claim]] = {key: [] for key in _STANDARD_SECTIONS}

        for claim in claims:
            section_key = section_mapping.get(
                claim.report_section, "ttp_based_findings"
            )
            result[section_key].append(claim)

        return result

    def _build_timeline_index(
        self, timeline: list[TimelineEntry]
    ) -> dict[str, str]:
        """Build an index mapping evidence_id to event_time for ordering.

        Args:
            timeline: List of timeline entries.

        Returns:
            Dictionary mapping evidence_id to event_time string.
        """
        index: dict[str, str] = {}
        for entry in timeline:
            if entry.evidence_id not in index:
                index[entry.evidence_id] = entry.event_time
        return index

    def _sort_claims_by_timeline(
        self,
        claims: list[Claim],
        timeline_index: dict[str, str],
    ) -> list[Claim]:
        """Sort claims by the earliest timeline event of their supporting evidence.

        Claims whose evidence doesn't appear in the timeline are placed at the end.

        Args:
            claims: Claims to sort.
            timeline_index: Mapping of evidence_id to event_time.

        Returns:
            Sorted list of claims.
        """

        def earliest_time(claim: Claim) -> str:
            times = [
                timeline_index[eid]
                for eid in claim.supporting_evidence
                if eid in timeline_index
            ]
            if times:
                return min(times)
            # Place claims without timeline info at the end
            return "9999-12-31T23:59:59Z"

        def sort_key(claim: Claim) -> tuple[str, str]:
            # Fixed-chapter claims (3.1-3.7) keep their chapter order first
            # so the TTP findings read in attack-phase order.
            section = claim.report_section
            chapter = section if section and section[:1].isdigit() else "~"
            return (chapter, earliest_time(claim))

        return sorted(claims, key=sort_key)

    def _determine_narrative_flow(
        self,
        section_key: str,
        claims: list[Claim],
        timeline_index: dict[str, str],
    ) -> str:
        """Determine the narrative flow description for a section.

        Different sections use different narrative approaches:
        - Overview/Summary: high-level summary flow
        - TTP findings: chronological/attack-phase flow
        - Per-system: system-grouped flow
        - Remediation: priority-based flow
        - Limitations: coverage-gap flow

        Args:
            section_key: The section identifier.
            claims: Claims assigned to this section.
            timeline_index: Timeline index for context.

        Returns:
            A string describing the narrative flow for the section.
        """
        if not claims:
            return "empty"

        if section_key == "investigation_overview":
            return "summary_narrative"
        elif section_key == "executive_summary":
            return "high_level_summary"
        elif section_key == "ttp_based_findings":
            return "chronological_attack_phase"
        elif section_key == "per_system_findings":
            return "system_grouped_chronological"
        elif section_key == "remediation_recommendations":
            return "priority_based"
        elif section_key == "limitations":
            return "coverage_gap_listing"
        elif section_key in ("appendix_ioc_list", "appendix_attack_mapping"):
            return "tabular_reference"
        else:
            return "chronological"
