"""Claim Review Service for the Analysis Layer.

Generates Markdown claim review documents with YAML decision blocks for
human review. Parses review decisions from edited documents and applies
them to the claims store.

Validates Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7
"""

from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, field_validator

from ir_agent.governance.review_options import CLAIM_OPTIONS, option_comment
from ir_agent.models.analysis import Claim


class ClaimDecisionStatus(str, Enum):
    """Allowed decision values for claim review.

    Requirement 12.3: approved
    Requirement 12.4: rejected
    Requirement 12.5: edited
    Additional: downgraded, needs_more_context
    """

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EDITED = "edited"
    DOWNGRADED = "downgraded"
    NEEDS_MORE_CONTEXT = "needs_more_context"


class ClaimDecision(BaseModel):
    """Pydantic model for a YAML decision block in the claim review document.

    YAML keys and enum values are always in English regardless of
    the review_language used for document headings.
    """

    item_id: str
    item_type: str = "claim"
    decision: ClaimDecisionStatus = ClaimDecisionStatus.PENDING
    decision_reason: str = ""
    analyst_id: str = ""
    edited_claim_text: str = ""
    downgraded_confidence: str = ""

    @field_validator("decision", mode="before")
    @classmethod
    def normalize_decision(cls, v: str) -> str:
        """Accept decision values case-insensitively."""
        if isinstance(v, str):
            return v.strip().lower()
        return v


# Section headings by language for claim review documents
_CLAIM_REVIEW_HEADINGS: dict[str, dict[str, str]] = {
    "ja": {
        "title": "Claim レビュー",
        "report_section": "レポートセクション",
        "claim_text": "Claim テキスト",
        "category": "カテゴリ",
        "confidence": "信頼度",
        "confidence_basis": "信頼度根拠",
        "supporting_evidence": "支持証拠",
        "counter_evidence": "反証",
        "limitations": "制約・不足情報",
        "missing_evidence": "不足証拠",
        "recommended_expressions": "推奨表現",
        "prohibited_expressions": "禁止表現",
        "attack_mappings": "ATT&CK マッピング",
        "group_basis": "グループ化の根拠",
        "related_correlations": "関連ヒント・エンティティリンク",
        "decision": "判定",
    },
    "en": {
        "title": "Claim Review",
        "report_section": "Report Section",
        "claim_text": "Claim Text",
        "category": "Category",
        "confidence": "Confidence",
        "confidence_basis": "Confidence Basis",
        "supporting_evidence": "Supporting Evidence",
        "counter_evidence": "Counter Evidence",
        "limitations": "Limitations",
        "missing_evidence": "Missing Evidence",
        "recommended_expressions": "Recommended Expressions",
        "prohibited_expressions": "Prohibited Expressions",
        "attack_mappings": "ATT&CK Mappings",
        "group_basis": "Grouping Basis",
        "related_correlations": "Related Hints / Entity Links",
        "decision": "Decision",
    },
}


def _get_claim_headings(review_language: str) -> dict[str, str]:
    """Get section headings for the specified language, defaulting to Japanese."""
    return _CLAIM_REVIEW_HEADINGS.get(review_language, _CLAIM_REVIEW_HEADINGS["ja"])


class ClaimReviewService:
    """Generates, parses, and applies claim review decisions.

    Follows the same pattern as ReviewDocumentGenerator in the Evidence Layer.
    The generated document presents each claim with section headings in the
    review_language, while YAML decision block keys and enum values remain
    in English for machine-parseable consistency.

    Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7
    """

    def __init__(self, claims_path: Path | None = None) -> None:
        """Initialize the ClaimReviewService.

        Args:
            claims_path: Optional path to the claims JSONL file. Used by
                apply_claim_decisions and get_approved_claims to read/write claims.
        """
        self._claims_path = claims_path

    def generate_claim_review_doc(
        self,
        claims: list[Claim],
        output_path: Path,
        review_language: str = "ja",
    ) -> None:
        """Generate a Markdown review document for claims with YAML decision blocks.

        Requirement 12.1: Generate a Claim_Review_Document in Markdown format
        using the review_language specified in the Case_Manifest.

        Requirement 12.2: Include for each Claim all required fields with
        headings rendered in review_language. YAML decision block keys and
        enum values remain in English.

        Args:
            claims: List of Claim objects to include in the review document.
            output_path: Path where the Markdown file will be written.
            review_language: Language for section headings (default "ja").
        """
        headings = _get_claim_headings(review_language)
        lines: list[str] = []

        # Document title
        lines.append(f"# {headings['title']}")
        lines.append("")

        for claim in claims:
            lines.extend(self._render_claim(claim, headings, review_language))
            lines.append("")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")

    def parse_claim_review_doc(self, review_path: Path) -> list[ClaimDecision]:
        """Parse YAML decision blocks from a claim review document.

        Extracts only the YAML code blocks, ignoring all prose content.
        This parsing is language-agnostic since YAML keys and values
        are always in English.

        Args:
            review_path: Path to the Markdown claim review document.

        Returns:
            List of validated ClaimDecision objects.

        Raises:
            FileNotFoundError: If review_path does not exist.
            ValueError: If a YAML block fails Pydantic validation.
        """
        content = review_path.read_text(encoding="utf-8")
        return self._extract_decisions(content)

    def apply_claim_decisions(
        self, decisions: list[ClaimDecision], claims_path: Path
    ) -> None:
        """Apply review decisions to the claims JSONL file.

        Updates the review_status of each claim based on the analyst's decision.

        Requirement 12.3: Mark approved claims as approved.
        Requirement 12.4: Mark rejected claims as rejected.
        Requirement 12.5: For edited claims, preserve original and store edited version.

        Args:
            decisions: List of ClaimDecision objects from parse_claim_review_doc.
            claims_path: Path to the claims JSONL file to update.
        """
        # Build a lookup of decisions by item_id
        decision_map: dict[str, ClaimDecision] = {
            d.item_id: d for d in decisions
        }

        # Read existing claims
        claims = self._read_claims_from_jsonl(claims_path)

        # Apply decisions
        updated_claims: list[Claim] = []
        for claim in claims:
            decision = decision_map.get(claim.claim_id)
            if decision is not None:
                claim = self._apply_single_decision(claim, decision)
            updated_claims.append(claim)

        # Write back updated claims
        self._write_claims_to_jsonl(updated_claims, claims_path)

    def get_approved_claims(self) -> list[Claim]:
        """Return only claims with review_status == 'approved'.

        Requirement 12.6: Only approved claims are used in report generation.
        Requirement 12.7: Pending, rejected, or superseded claims are excluded.

        Returns:
            List of approved Claim objects.

        Raises:
            ValueError: If claims_path was not provided during initialization.
        """
        if self._claims_path is None:
            raise ValueError(
                "claims_path must be provided to ClaimReviewService "
                "to use get_approved_claims()"
            )

        claims = self._read_claims_from_jsonl(self._claims_path)
        return [
            c for c in claims
            if c.review_status == "approved"
        ]

    # --- Private helper methods ---

    def _render_claim(
        self,
        claim: Claim,
        headings: dict[str, str],
        review_language: str = "ja",
    ) -> list[str]:
        """Render a single claim section for the review document."""
        lines: list[str] = []

        # Claim header
        lines.append(f"## {claim.claim_id}")
        lines.append("")

        # Report section
        lines.append(f"### {headings['report_section']}")
        lines.append("")
        lines.append(claim.report_section)
        lines.append("")

        # Claim text
        lines.append(f"### {headings['claim_text']}")
        lines.append("")
        lines.append(claim.claim_text)
        lines.append("")

        # Category
        lines.append(f"### {headings['category']}")
        lines.append("")
        lines.append(f"- claim_category: `{claim.claim_category.value}`")
        lines.append("")

        # Confidence
        lines.append(f"### {headings['confidence']}")
        lines.append("")
        lines.append(f"- confidence_level: `{claim.confidence_level.value}`")
        lines.append("")

        # Confidence basis
        lines.append(f"### {headings['confidence_basis']}")
        lines.append("")
        lines.append(claim.confidence_basis)
        lines.append("")

        # Supporting evidence
        lines.append(f"### {headings['supporting_evidence']}")
        lines.append("")
        if claim.supporting_evidence:
            for eid in claim.supporting_evidence:
                lines.append(f"- `{eid}`")
        else:
            if review_language == "ja":
                lines.append("（なし）")
            else:
                lines.append("(None)")
        lines.append("")

        # Counter evidence
        lines.append(f"### {headings['counter_evidence']}")
        lines.append("")
        if claim.counter_evidence:
            for eid in claim.counter_evidence:
                lines.append(f"- `{eid}`")
        else:
            if review_language == "ja":
                lines.append("（なし）")
            else:
                lines.append("(None)")
        lines.append("")

        # Limitations
        lines.append(f"### {headings['limitations']}")
        lines.append("")
        if claim.limitations:
            for limitation in claim.limitations:
                lines.append(f"- {limitation}")
        else:
            if review_language == "ja":
                lines.append("（なし）")
            else:
                lines.append("(None)")
        lines.append("")

        # Missing evidence
        lines.append(f"### {headings['missing_evidence']}")
        lines.append("")
        if claim.missing_evidence:
            for missing in claim.missing_evidence:
                lines.append(f"- {missing}")
        else:
            if review_language == "ja":
                lines.append("（なし）")
            else:
                lines.append("(None)")
        lines.append("")

        # Recommended expressions
        lines.append(f"### {headings['recommended_expressions']}")
        lines.append("")
        if claim.recommended_expressions:
            for expr in claim.recommended_expressions:
                lines.append(f"- {expr}")
        else:
            if review_language == "ja":
                lines.append("（なし）")
            else:
                lines.append("(None)")
        lines.append("")

        # Prohibited expressions
        lines.append(f"### {headings['prohibited_expressions']}")
        lines.append("")
        if claim.prohibited_expressions:
            for expr in claim.prohibited_expressions:
                lines.append(f"- {expr}")
        else:
            if review_language == "ja":
                lines.append("（なし）")
            else:
                lines.append("(None)")
        lines.append("")

        # ATT&CK Mappings
        lines.append(f"### {headings['attack_mappings']}")
        lines.append("")
        if claim.attack_mappings:
            for mapping in claim.attack_mappings:
                lines.append(
                    f"- {mapping.tactic} / {mapping.technique_id} "
                    f"({mapping.technique_name}) - {mapping.confidence.value}"
                )
        else:
            if review_language == "ja":
                lines.append("（なし）")
            else:
                lines.append("(None)")
        lines.append("")

        # Grouping provenance (upstream-analysis flow): shown so the
        # reviewer can judge why multiple evidence items were combined.
        if claim.group_basis or claim.analysis_group_id:
            lines.append(f"### {headings['group_basis']}")
            lines.append("")
            if claim.analysis_group_id:
                lines.append(f"- analysis_group_id: `{claim.analysis_group_id}`")
            if claim.group_basis:
                lines.append(f"- {claim.group_basis}")
            lines.append("")

        if claim.related_hint_ids or claim.related_entity_link_ids:
            lines.append(f"### {headings['related_correlations']}")
            lines.append("")
            for link_id in claim.related_entity_link_ids:
                lines.append(f"- entity_link: `{link_id}`")
            for hint_id in claim.related_hint_ids:
                lines.append(f"- hint: `{hint_id}`")
            lines.append("")

        # Decision section with YAML block
        lines.append(f"### {headings['decision']}")
        lines.append("")

        guidance = "# " + option_comment(CLAIM_OPTIONS, review_language)

        lines.append("```yaml")
        lines.append(f"item_id: {claim.claim_id}")
        lines.append("item_type: claim")
        lines.append(f"decision: pending  {guidance}")
        lines.append('decision_reason: ""')
        lines.append('analyst_id: ""')
        lines.append('edited_claim_text: ""  # decision が edited の場合に記入')
        lines.append('downgraded_confidence: ""  # decision が downgraded の場合に記入')
        lines.append("```")
        lines.append("")
        lines.append("---")

        return lines

    def _extract_decisions(self, content: str) -> list[ClaimDecision]:
        """Extract and validate YAML decision blocks from Markdown content."""
        # Match all fenced YAML code blocks
        yaml_pattern = re.compile(
            r"```yaml\s*\n(.*?)\n\s*```", re.DOTALL
        )
        matches = yaml_pattern.findall(content)

        decisions: list[ClaimDecision] = []
        for yaml_text in matches:
            parsed = yaml.safe_load(yaml_text)
            if parsed is None:
                continue
            if not isinstance(parsed, dict):
                continue
            # Only process blocks that look like decision blocks
            if "item_id" not in parsed or "decision" not in parsed:
                continue
            decision = ClaimDecision.model_validate(parsed)
            decisions.append(decision)

        return decisions

    def _apply_single_decision(
        self, claim: Claim, decision: ClaimDecision
    ) -> Claim:
        """Apply a single decision to a claim.

        Args:
            claim: The claim to update.
            decision: The analyst's decision for this claim.

        Returns:
            Updated Claim object.
        """
        status = decision.decision.value

        # Update review_status
        claim.review_status = status

        if status == ClaimDecisionStatus.EDITED.value:
            # Requirement 12.5: Preserve original, store edited version
            if decision.edited_claim_text:
                claim.original_claim_text = claim.claim_text
                claim.approved_claim_text = decision.edited_claim_text
                # Mark as approved after edit
                claim.review_status = "edited"

        elif status == ClaimDecisionStatus.DOWNGRADED.value:
            # Downgrade confidence level
            if decision.downgraded_confidence:
                from ir_agent.models.enums import ConfidenceLevel
                try:
                    new_confidence = ConfidenceLevel(decision.downgraded_confidence)
                    claim.confidence_level = new_confidence
                    claim.review_status = "downgraded"
                except ValueError:
                    # Invalid confidence level, keep current
                    pass

        elif status == ClaimDecisionStatus.APPROVED.value:
            # Requirement 12.3: Mark as approved
            claim.review_status = "approved"

        elif status == ClaimDecisionStatus.REJECTED.value:
            # Requirement 12.4: Mark as rejected
            claim.review_status = "rejected"

        elif status == ClaimDecisionStatus.NEEDS_MORE_CONTEXT.value:
            claim.review_status = "needs_more_context"

        return claim

    def _read_claims_from_jsonl(self, claims_path: Path) -> list[Claim]:
        """Read claims from a JSONL file.

        Args:
            claims_path: Path to the claims JSONL file.

        Returns:
            List of Claim objects.
        """
        if not claims_path.exists():
            return []

        claims: list[Claim] = []
        with open(claims_path, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                data = json.loads(stripped)
                claim = Claim.model_validate(data)
                claims.append(claim)

        return claims

    def _write_claims_to_jsonl(
        self, claims: list[Claim], claims_path: Path
    ) -> None:
        """Write claims to a JSONL file (overwriting for decision application).

        Note: This is an intentional overwrite to apply decisions, unlike
        the append-only Evidence Ledger. Claims are updated in-place during
        the review process.

        Args:
            claims: List of Claim objects to write.
            claims_path: Path to the claims JSONL file.
        """
        claims_path.parent.mkdir(parents=True, exist_ok=True)
        with open(claims_path, "w", encoding="utf-8") as f:
            for claim in claims:
                f.write(claim.model_dump_json() + "\n")
