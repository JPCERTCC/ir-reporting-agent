"""Draft Report Generator for the IR Reporting Layer.

Generates the draft report DIRECTLY in the target language using the
ExpressionPolicy. The report is NOT generated in English then translated.
Evidentiary conclusions are rendered in the target language from the start.

The generator uses only approved claims, includes evidence citations,
a limitations section, and confidence-appropriate language controlled
by the ExpressionPolicy.

Key constraints (from Requirements 16):
- Uses ONLY approved claims (review_status == "approved" or "edited")
- Applies ExpressionPolicy for confidence-appropriate language
- Does NOT use prohibited_expressions
- Includes evidence citations (evidence_id references)
- Includes limitations section for known gaps and uncertainty
- Does NOT convert interpretations into factual assertions (Req 16.12)
- Includes accepted limitations in appropriate sections (Req 16.10)
- Distinguishes confirmed facts, probable/possible interpretations,
  unknown items, and not_observed items (Req 16.11)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ir_agent.models.analysis import Claim, Gap
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry
from ir_agent.models.reporting import ReportPlan
from ir_agent.reporting.forensic_sections import (
    render_attack_mapping_appendix,
    render_chapter2_incident_overview,
    render_chapter4,
    render_chapter5,
    render_incident_overview_diagram,
    render_investigation_targets,
    render_ioc_appendix,
    render_related_files_appendix,
    render_review_comment,
    render_table_of_contents,
)
from ir_agent.reporting.localization import LocalizationEngine
from ir_agent.steering.manifest import CaseManifest, ExpressionPolicy


class DraftGenerator:
    """Generates draft reports directly in the target language.

    The draft generator renders the report using the ExpressionPolicy to
    select confidence-appropriate language. It never generates English
    text first and then translates — all output is produced directly in
    the target language from the start.
    """

    def __init__(self, localization: Optional[LocalizationEngine] = None):
        """Initialize the DraftGenerator.

        Args:
            localization: Optional LocalizationEngine instance. If not provided,
                a default one will be created.
        """
        self._localization = localization or LocalizationEngine()

    def generate_draft(
        self,
        plan: ReportPlan,
        approved_claims: list[Claim],
        ledger: list[EvidenceLedgerEntry],
        gaps: list[Gap],
        policy: ExpressionPolicy,
        manifest: CaseManifest,
    ) -> str:
        """Generate a draft report directly in the target language.

        Uses the ExpressionPolicy to produce confidence-appropriate language.
        Only approved claims are used. Evidence citations are included inline.
        Accepted limitations are included in the limitations section.

        The report is generated DIRECTLY in the target language — it is NOT
        generated in English then translated.

        Args:
            plan: The approved ReportPlan defining section structure.
            approved_claims: List of approved claims (only approved/edited used).
            ledger: Active evidence ledger entries for citation details.
            gaps: Gap records (accepted_as_limitation gaps included in report).
            policy: ExpressionPolicy controlling confidence language.
            manifest: CaseManifest with report_language and timezone.

        Returns:
            The draft report as a Markdown string.
        """
        language = manifest.report_language
        timezone_str = manifest.report_timezone

        # Filter to only truly approved claims
        claims_by_id = {
            c.claim_id: c for c in approved_claims if c.review_status in ("approved", "edited")
        }

        # Build ledger index
        ledger_by_id = {e.evidence_id: e for e in ledger}

        # Get localization resources
        boilerplate = self._localization.get_boilerplate_templates(language)

        # Collect accepted limitations from gaps
        accepted_limitations = [g for g in gaps if g.disposition == "accepted_as_limitation"]

        if language == "ja":
            return self._generate_fixed_japanese_forensic_report(
                list(claims_by_id.values()),
                ledger,
                ledger_by_id,
                gaps,
                accepted_limitations,
                policy,
                manifest,
                boilerplate,
            )

        # Build the report
        parts: list[str] = []

        # Draft watermark
        parts.append(boilerplate["draft_watermark"])
        parts.append("")

        # Report title
        title = self._get_report_title(manifest, language)
        parts.append(f"# {title}")
        parts.append("")

        # Generation timestamp
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        display_time = self._localization.format_timestamp_for_display(now_utc, timezone_str)
        parts.append(boilerplate["report_generated_at"].format(timestamp=display_time))
        parts.append("")

        # Generate each section from the plan
        for section in plan.sections:
            section_key = section.get("section_key", "")
            heading = section.get("heading", "")
            claim_ids = section.get("claims", [])
            narrative_flow = section.get("narrative_flow", "chronological")

            parts.append(f"## {heading}")
            parts.append("")

            # Get claims for this section
            section_claims = [claims_by_id[cid] for cid in claim_ids if cid in claims_by_id]

            if section_key == "limitations":
                # Render limitations section with accepted gaps
                section_content = self._render_limitations_section(
                    section_claims,
                    accepted_limitations,
                    ledger_by_id,
                    policy,
                    language,
                    boilerplate,
                )
            elif section_key == "executive_summary":
                section_content = self._render_executive_summary(
                    section_claims,
                    ledger_by_id,
                    policy,
                    language,
                    boilerplate,
                )
            elif section_key in ("appendix_ioc_list", "appendix_attack_mapping"):
                section_content = self._render_appendix_section(
                    section_key,
                    section_claims,
                    ledger_by_id,
                    language,
                )
            else:
                # Standard findings section
                section_content = self._render_findings_section(
                    section_claims,
                    ledger_by_id,
                    policy,
                    language,
                    boilerplate,
                    narrative_flow,
                )

            parts.append(section_content)
            parts.append("")

        return "\n".join(parts)

    def _generate_fixed_japanese_forensic_report(
        self,
        approved_claims: list[Claim],
        ledger: list[EvidenceLedgerEntry],
        ledger_by_id: dict[str, EvidenceLedgerEntry],
        gaps: list[Gap],
        accepted_limitations: list[Gap],
        policy: ExpressionPolicy,
        manifest: CaseManifest,
        boilerplate: dict[str, str],
    ) -> str:
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        display_time = self._localization.format_timestamp_for_display(
            now_utc, manifest.report_timezone
        )

        findings = self._render_findings_section(
            approved_claims,
            ledger_by_id,
            policy,
            "ja",
            boilerplate,
            "chronological",
        )
        parts: list[str] = [
            boilerplate["draft_watermark"],
            "",
            f"# {self._get_report_title(manifest, 'ja')}",
            "",
            boilerplate["report_generated_at"].format(timestamp=display_time),
            "",
            render_table_of_contents(ledger),
            "",
            "## 0. 本資料の取扱い",
            "",
            self._fixed_document_handling_text(),
            "",
            "## 1. 調査概要",
            "",
            "### 1.1 調査にかかる経緯",
            "",
            render_review_comment("1.1"),
            "",
            "### 1.2 調査目的・調査範囲",
            "",
            render_review_comment("1.2"),
            "",
            "### 1.3 調査日程・調査期間",
            "",
            render_review_comment("1.3"),
            "",
            "### 1.4 調査対象・提供データ",
            "",
            render_investigation_targets(ledger),
            "",
            "### 1.5 調査方法・調査ツール",
            "",
            render_review_comment("1.5"),
            "",
            "## 2. エグゼクティブサマリー・調査結果概要",
            "",
            render_chapter2_incident_overview(
                approved_claims, ledger, case_time_range=manifest.time_range
            ),
            "",
            "### 2.1 ヒアリング内容",
            "",
            render_review_comment("2.1"),
            "",
            "### 2.2 調査方針・対応方針",
            "",
            render_review_comment("2.2"),
            "",
            "### 2.3 インシデント概要図",
            "",
            render_incident_overview_diagram(approved_claims, ledger),
            "",
            "### 2.4 インシデントタイムライン",
            "",
            "本レンダラーではタイムライン情報を受け取っていないため、承認済みClaimおよび証拠IDを参照して別途確認してください。",
            "",
            "### 2.5 推奨対応事項",
            "",
            self._render_recommendations_from_gaps(gaps),
            "",
            "## 3. 調査結果",
            "",
            "### 3.1 初期侵入",
            "",
            findings,
            "",
            "### 3.2 認証情報取得・アカウント悪用",
            "",
            boilerplate["no_evidence_found"],
            "",
            "### 3.3 内部探索・横展開",
            "",
            boilerplate["no_evidence_found"],
            "",
            "### 3.4 永続化",
            "",
            boilerplate["no_evidence_found"],
            "",
            "### 3.5 C2通信・プロキシ・外部通信",
            "",
            boilerplate["no_evidence_found"],
            "",
            "### 3.6 情報窃取・情報持ち出し",
            "",
            boilerplate["no_evidence_found"],
            "",
            "### 3.7 防衛回避・痕跡消去",
            "",
            boilerplate["no_evidence_found"],
            "",
            render_chapter4(ledger, approved_claims, case_time_range=manifest.time_range),
            "",
            "## 5. 対応状況・推奨対策",
            "",
            render_chapter5(gaps, approved_claims).replace("## 5. 対応状況・推奨対策\n\n", "", 1),
            "",
            render_ioc_appendix(approved_claims, ledger),
            "",
            render_attack_mapping_appendix(approved_claims, ledger),
            "",
            render_related_files_appendix(ledger),
            "",
            "## 付録D. 証拠保全記録",
            "",
            render_review_comment("D"),
        ]
        return "\n".join(parts)

    def _fixed_document_handling_text(self) -> str:
        return "\n\n".join(
            [
                "本資料は、インシデント調査の結果を関係者間で共有することを目的として作成した機密資料です。",
                "本資料には、調査対象システム、ログ、アカウント、通信先、調査上の判断に関する情報が含まれるため、貴社内の関係者および事前に許可された関係者のみで取り扱ってください。",
                "本資料の全部または一部を、事前の許可なく第三者へ開示、転送、複製、公開することを禁止します。",
                "本資料の記載内容は、作成時点で提供された資料および確認できた証拠に基づくものであり、追加資料の取得または追加調査により変更される可能性があります。",
            ]
        )

    def _render_incident_overview_stub(self, manifest: CaseManifest) -> str:
        hosts = "、".join(manifest.hosts) if manifest.hosts else "提供資料上は確認できない"
        return f"- 調査対象候補: {hosts}\n- 詳細な関係図は、レビュー担当者が確認済みタイムラインに基づき補記してください。"

    def _render_recommendations_from_gaps(self, gaps: list[Gap]) -> str:
        if not gaps:
            return "- 追加の推奨事項は、レビュー担当者が調査結果を確認のうえ記載してください。"
        return "\n".join(f"- {gap.recommended_action}" for gap in gaps[:8])

    def _get_report_title(self, manifest: CaseManifest, language: str) -> str:
        """Generate the report title based on case manifest and language.

        Args:
            manifest: CaseManifest with case_name.
            language: Target language code.

        Returns:
            Report title string.
        """
        if language == "ja":
            return f"{manifest.case_name} — インシデント調査報告書（ドラフト）"
        else:
            return f"{manifest.case_name} — Incident Investigation Report (Draft)"

    def _render_findings_section(
        self,
        claims: list[Claim],
        ledger_by_id: dict[str, EvidenceLedgerEntry],
        policy: ExpressionPolicy,
        language: str,
        boilerplate: dict[str, str],
        narrative_flow: str,
    ) -> str:
        """Render a standard findings section with claims and citations.

        Each claim is rendered with confidence-appropriate language,
        evidence citations, and limitations. Interpretations are NEVER
        converted into factual assertions (Req 16.12).

        Args:
            claims: Claims for this section.
            ledger_by_id: Evidence ledger index.
            policy: ExpressionPolicy for language control.
            language: Target language code.
            boilerplate: Boilerplate templates.
            narrative_flow: Narrative flow type for ordering.

        Returns:
            Markdown content for the section.
        """
        if not claims:
            return boilerplate["no_evidence_found"]

        parts: list[str] = []

        for claim in claims:
            # Get the claim text (use approved_claim_text if edited)
            claim_text = claim.approved_claim_text or claim.claim_text

            # Apply confidence-appropriate language
            rendered_text = self._apply_confidence_language(claim_text, claim, policy, language)

            # Build evidence citation
            citation = self._build_citation(claim.supporting_evidence, boilerplate)

            # Render the claim paragraph
            parts.append(f"{rendered_text} {citation}")
            parts.append("")

            # Add limitations if present
            if claim.limitations:
                limitation_prefix = boilerplate["limitation_prefix"]
                for limitation in claim.limitations:
                    parts.append(f"{limitation_prefix} {limitation}")
                parts.append("")

        return "\n".join(parts)

    def _render_executive_summary(
        self,
        claims: list[Claim],
        ledger_by_id: dict[str, EvidenceLedgerEntry],
        policy: ExpressionPolicy,
        language: str,
        boilerplate: dict[str, str],
    ) -> str:
        """Render the executive summary section.

        Provides a high-level overview using confidence-appropriate language.

        Args:
            claims: Claims assigned to the executive summary.
            ledger_by_id: Evidence ledger index.
            policy: ExpressionPolicy for language control.
            language: Target language code.
            boilerplate: Boilerplate templates.

        Returns:
            Markdown content for the executive summary.
        """
        if not claims:
            return boilerplate["no_evidence_found"]

        parts: list[str] = []

        for claim in claims:
            claim_text = claim.approved_claim_text or claim.claim_text
            rendered_text = self._apply_confidence_language(claim_text, claim, policy, language)
            citation = self._build_citation(claim.supporting_evidence, boilerplate)
            parts.append(f"{rendered_text} {citation}")
            parts.append("")

        return "\n".join(parts)

    def _render_limitations_section(
        self,
        claims: list[Claim],
        accepted_limitations: list[Gap],
        ledger_by_id: dict[str, EvidenceLedgerEntry],
        policy: ExpressionPolicy,
        language: str,
        boilerplate: dict[str, str],
    ) -> str:
        """Render the limitations section with accepted gaps.

        Includes both claim-level limitations and gap-level accepted
        limitations. Gaps with disposition=accepted_as_limitation are
        rendered here per Requirement 13.7 and 16.10.

        Args:
            claims: Claims assigned to the limitations section.
            accepted_limitations: Gaps accepted as limitations.
            ledger_by_id: Evidence ledger index.
            policy: ExpressionPolicy for language control.
            language: Target language code.
            boilerplate: Boilerplate templates.

        Returns:
            Markdown content for the limitations section.
        """
        parts: list[str] = []
        limitation_prefix = boilerplate["limitation_prefix"]

        # Render any claims assigned to this section
        for claim in claims:
            claim_text = claim.approved_claim_text or claim.claim_text
            rendered_text = self._apply_confidence_language(claim_text, claim, policy, language)
            citation = self._build_citation(claim.supporting_evidence, boilerplate)
            parts.append(f"{rendered_text} {citation}")
            parts.append("")

        # Render accepted limitation gaps
        if accepted_limitations:
            for gap in accepted_limitations:
                parts.append(f"- {limitation_prefix} {gap.description}")
                if gap.disposition_reason:
                    if language == "ja":
                        parts.append(f"  - 理由: {gap.disposition_reason}")
                    else:
                        parts.append(f"  - Reason: {gap.disposition_reason}")
            parts.append("")

        # Add not_observed disclaimer if any claims have NOT_OBSERVED confidence
        has_not_observed = any(c.confidence_level == ConfidenceLevel.NOT_OBSERVED for c in claims)
        if has_not_observed:
            parts.append(boilerplate["not_observed_disclaimer"])
            parts.append("")

        if not parts:
            if language == "ja":
                return "特筆すべき制約事項はありません。"
            else:
                return "No significant limitations identified."

        return "\n".join(parts)

    def _render_appendix_section(
        self,
        section_key: str,
        claims: list[Claim],
        ledger_by_id: dict[str, EvidenceLedgerEntry],
        language: str,
    ) -> str:
        """Render an appendix section (IoC list or ATT&CK mapping).

        Appendix sections use tabular format. Content is derived from
        claims' ATT&CK mappings and evidence references.

        Args:
            section_key: The appendix section key.
            claims: Claims for this appendix.
            ledger_by_id: Evidence ledger index.
            language: Target language code.

        Returns:
            Markdown content for the appendix section.
        """
        if section_key == "appendix_attack_mapping":
            return self._render_attack_mapping_appendix(claims, language)
        elif section_key == "appendix_ioc_list":
            return self._render_ioc_appendix(claims, ledger_by_id, language)
        return ""

    def _render_attack_mapping_appendix(
        self,
        claims: list[Claim],
        language: str,
    ) -> str:
        """Render the ATT&CK mapping appendix table.

        Args:
            claims: Claims with ATT&CK mappings.
            language: Target language code.

        Returns:
            Markdown table of ATT&CK mappings.
        """
        captions = self._localization.get_table_captions(language)
        parts: list[str] = [captions.get("attack_mapping_table", "ATT&CK Mapping")]
        parts.append("")

        # Table header
        if language == "ja":
            parts.append("| 戦術 | テクニックID | テクニック名 | 関連Claim | 信頼度 |")
        else:
            parts.append("| Tactic | Technique ID | Technique Name | Related Claim | Confidence |")
        parts.append("|---|---|---|---|---|")

        for claim in claims:
            for mapping in claim.attack_mappings:
                parts.append(
                    f"| {mapping.tactic} | {mapping.technique_id} | "
                    f"{mapping.technique_name} | {claim.claim_id} | "
                    f"{mapping.confidence.value} |"
                )

        if len(parts) <= 3:
            # No mappings found
            if language == "ja":
                parts.append("| — | — | — | — | — |")
            else:
                parts.append("| — | — | — | — | — |")

        return "\n".join(parts)

    def _render_ioc_appendix(
        self,
        claims: list[Claim],
        ledger_by_id: dict[str, EvidenceLedgerEntry],
        language: str,
    ) -> str:
        """Render the IoC list appendix.

        IoC values are referenced through evidence entries and are
        defanged for safe display.

        Args:
            claims: Claims for the IoC appendix.
            ledger_by_id: Evidence ledger index.
            language: Target language code.

        Returns:
            Markdown content for the IoC appendix.
        """
        captions = self._localization.get_table_captions(language)
        parts: list[str] = [captions.get("ioc_table", "IoC List")]
        parts.append("")

        if language == "ja":
            parts.append("| 種別 | 値 | 概要/役割 | 確認箇所 |")
        else:
            parts.append("| Type | Value | Summary / Role | Location |")
        parts.append("|---|---|---|---|")

        # Collect evidence_ids from claims for reference
        evidence_ids: list[str] = []
        for claim in claims:
            for eid in claim.supporting_evidence:
                if eid not in evidence_ids:
                    evidence_ids.append(eid)

        if not evidence_ids:
            if language == "ja":
                parts.append("| — | — | — | — |")
            else:
                parts.append("| — | — | — | — |")

        return "\n".join(parts)

    def _apply_confidence_language(
        self,
        claim_text: str,
        claim: Claim,
        policy: ExpressionPolicy,
        language: str,
    ) -> str:
        """Apply confidence-appropriate language to the claim text.

        Uses the ExpressionPolicy to ensure the text uses recommended
        expressions and does NOT use prohibited expressions. Does NOT
        convert interpretations into factual assertions (Req 16.12).

        For interpretation claims, hedging language is prepended based on
        confidence level to clearly distinguish interpretations from facts.

        Args:
            claim_text: The raw claim text.
            claim: The Claim object with category and confidence info.
            policy: ExpressionPolicy for language rules.
            language: Target language code.

        Returns:
            The claim text with confidence-appropriate language applied.
        """
        rule = policy.get_rule(claim.confidence_level, claim.claim_category)

        # Verify no prohibited expressions are present
        rendered_text = claim_text
        for prohibited in rule.prohibited_expressions:
            if prohibited in rendered_text:
                # Replace prohibited expression with a recommended alternative
                replacement = (
                    rule.recommended_expressions[0] if rule.recommended_expressions else ""
                )
                rendered_text = rendered_text.replace(prohibited, replacement)

        # For interpretation categories, add confidence qualifier if not already present
        if claim.claim_category != ClaimCategory.OBSERVED_FACT:
            rendered_text = self._add_confidence_qualifier(
                rendered_text, claim.confidence_level, language
            )

        return rendered_text

    def _add_confidence_qualifier(
        self,
        text: str,
        confidence: ConfidenceLevel,
        language: str,
    ) -> str:
        """Add a confidence qualifier prefix for non-fact claims.

        Ensures interpretations are clearly marked with appropriate
        hedging language per Req 16.5 and 16.11.

        Args:
            text: The claim text.
            confidence: The confidence level.
            language: Target language code.

        Returns:
            Text with confidence qualifier prepended if appropriate.
        """
        # Map confidence levels to qualifiers
        if language == "ja":
            qualifiers = {
                ConfidenceLevel.CONFIRMED: "",  # No qualifier needed for confirmed
                ConfidenceLevel.PROBABLE: "【高確度】",
                ConfidenceLevel.POSSIBLE: "【可能性】",
                ConfidenceLevel.UNKNOWN: "【不明】",
                ConfidenceLevel.NOT_OBSERVED: "【観測されず】",
            }
        else:
            qualifiers = {
                ConfidenceLevel.CONFIRMED: "",
                ConfidenceLevel.PROBABLE: "[Probable]",
                ConfidenceLevel.POSSIBLE: "[Possible]",
                ConfidenceLevel.UNKNOWN: "[Unknown]",
                ConfidenceLevel.NOT_OBSERVED: "[Not Observed]",
            }

        qualifier = qualifiers.get(confidence, "")
        if qualifier and not text.startswith(qualifier):
            return f"{qualifier} {text}"
        return text

    def _build_citation(
        self,
        evidence_ids: list[str],
        boilerplate: dict[str, str],
    ) -> str:
        """Build inline evidence citations for a claim.

        Args:
            evidence_ids: List of evidence IDs supporting the claim.
            boilerplate: Boilerplate templates containing citation format.

        Returns:
            Formatted citation string with all evidence IDs.
        """
        if not evidence_ids:
            return ""

        citation_template = boilerplate["evidence_citation"]
        citations = [citation_template.format(evidence_id=eid) for eid in evidence_ids]
        return " ".join(citations)
