"""Review Document Generator for the Evidence Layer.

Generates Markdown review documents with YAML decision blocks for
human review of evidence candidates. Parses review decisions from
edited documents.

Validates Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, field_validator

from ir_agent.governance.review_options import EVIDENCE_OPTIONS, option_comment
from ir_agent.models.evidence import EvidenceCandidate


class ReviewDecisionStatus(str, Enum):
    """Allowed decision values for evidence candidate review."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EDITED = "edited"
    NEEDS_MORE_CONTEXT = "needs_more_context"


class ReviewDecision(BaseModel):
    """Pydantic model for a YAML decision block in the review document.

    YAML keys and enum values are always in English regardless of
    the review_language used for document headings.
    """

    item_id: str
    item_type: str = "evidence_candidate"
    decision: ReviewDecisionStatus = ReviewDecisionStatus.PENDING
    decision_reason: str = ""
    analyst_id: str = ""

    @field_validator("decision", mode="before")
    @classmethod
    def normalize_decision(cls, v: str) -> str:
        """Accept decision values case-insensitively."""
        if isinstance(v, str):
            return v.strip().lower()
        return v


# Section headings by language
_SECTION_HEADINGS: dict[str, dict[str, str]] = {
    "ja": {
        "summary": "概要",
        "observed_fact": "観測事実",
        "interpretation": "解釈",
        "confidence": "信頼度",
        "limitations": "制約・不足情報",
        "recommended_expressions": "推奨表現",
        "prohibited_expressions": "禁止表現",
        "source": "出典",
        "decision": "判定",
    },
    "en": {
        "summary": "Summary",
        "observed_fact": "Observed Fact",
        "interpretation": "Interpretation",
        "confidence": "Confidence",
        "limitations": "Constraints / Limitations",
        "recommended_expressions": "Recommended Expressions",
        "prohibited_expressions": "Prohibited Expressions",
        "source": "Source",
        "decision": "Decision",
    },
}


def _get_headings(review_language: str) -> dict[str, str]:
    """Get section headings for the specified language, defaulting to Japanese."""
    return _SECTION_HEADINGS.get(review_language, _SECTION_HEADINGS["ja"])


class ReviewDocumentGenerator:
    """Generates and parses Markdown review documents with YAML decision blocks.

    The generated document presents each evidence candidate with section
    headings in the review_language, while YAML decision block keys and
    enum values remain in English for machine-parseable consistency.
    """

    def generate_review_doc(
        self,
        candidates: list[EvidenceCandidate],
        output_path: Path,
        review_language: str = "ja",
    ) -> None:
        """Generate a Markdown review document for evidence candidates.

        Args:
            candidates: List of EvidenceCandidate objects to include.
            output_path: Path where the Markdown file will be written.
            review_language: Language for section headings (default "ja").
        """
        headings = _get_headings(review_language)
        lines: list[str] = []

        # Document title
        if review_language == "ja":
            lines.append("# エビデンス候補レビュー\n")
        else:
            lines.append("# Evidence Candidate Review\n")
        lines.append("")

        for candidate in candidates:
            lines.extend(self._render_candidate(candidate, headings, review_language))
            lines.append("")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")

    def _render_candidate(
        self,
        candidate: EvidenceCandidate,
        headings: dict[str, str],
        review_language: str = "ja",
    ) -> list[str]:
        """Render a single candidate section."""
        lines: list[str] = []

        # Candidate header
        lines.append(f"## {candidate.candidate_id}")
        lines.append("")

        # Summary section
        lines.append(f"### {headings['summary']}")
        lines.append("")
        lines.append(f"- candidate_id: `{candidate.candidate_id}`")
        source_file_ids = [ref.source_file_id for ref in candidate.source_refs]
        lines.append(f"- source_refs: {', '.join(source_file_ids)}")
        lines.append("")

        # Observed Fact section
        lines.append(f"### {headings['observed_fact']}")
        lines.append("")
        lines.append(candidate.observed_fact)
        lines.append("")

        # Interpretation section
        lines.append(f"### {headings['interpretation']}")
        lines.append("")
        lines.append(candidate.interpretation)
        lines.append("")

        # Confidence section
        lines.append(f"### {headings['confidence']}")
        lines.append("")
        lines.append(
            f"- observed_fact_confidence: {candidate.observed_fact_confidence.value}"
        )
        lines.append(
            f"- interpretation_confidence: {candidate.interpretation_confidence.value}"
        )
        lines.append("")

        # Limitations section
        lines.append(f"### {headings['limitations']}")
        lines.append("")
        if review_language == "ja":
            lines.append("（既知の制約・不足情報をここに記載）")
        else:
            lines.append("(Known constraints and limitations listed here)")
        lines.append("")

        # Recommended Expressions section
        lines.append(f"### {headings['recommended_expressions']}")
        lines.append("")
        if review_language == "ja":
            lines.append("（レポート作成時の推奨表現）")
        else:
            lines.append("(Recommended expressions for report writing)")
        lines.append("")

        # Prohibited Expressions section
        lines.append(f"### {headings['prohibited_expressions']}")
        lines.append("")
        if review_language == "ja":
            lines.append("（レポート作成時の禁止表現）")
        else:
            lines.append("(Prohibited expressions for report writing)")
        lines.append("")

        # Source section
        lines.append(f"### {headings['source']}")
        lines.append("")
        for ref in candidate.source_refs:
            lines.append(f"- source_file_id: `{ref.source_file_id}`")
            lines.append(f"  - source_lines: {ref.source_lines[0]}-{ref.source_lines[1]}")
            lines.append(f"  - excerpt: `{ref.excerpt[:200]}`")
        lines.append("")

        # Decision section with YAML block
        lines.append(f"### {headings['decision']}")
        lines.append("")
        lines.append("```yaml")
        lines.append(f"item_id: {candidate.candidate_id}")
        lines.append("item_type: evidence_candidate")
        lines.append(
            f"decision: pending  # {option_comment(EVIDENCE_OPTIONS, review_language)}"
        )
        lines.append('decision_reason: ""')
        lines.append('analyst_id: ""')
        lines.append("```")
        lines.append("")
        lines.append("---")

        return lines

    def parse_review_doc(self, review_path: Path) -> list[ReviewDecision]:
        """Parse YAML decision blocks from a review document.

        Extracts only the YAML code blocks, ignoring all prose content.
        This parsing is language-agnostic since YAML keys and values
        are always in English.

        Args:
            review_path: Path to the Markdown review document.

        Returns:
            List of validated ReviewDecision objects.

        Raises:
            FileNotFoundError: If review_path does not exist.
            ValueError: If a YAML block fails Pydantic validation.
        """
        content = review_path.read_text(encoding="utf-8")
        return self._extract_decisions(content)

    def _extract_decisions(self, content: str) -> list[ReviewDecision]:
        """Extract and validate YAML decision blocks from Markdown content."""
        # Match all fenced YAML code blocks
        yaml_pattern = re.compile(
            r"```yaml\s*\n(.*?)\n\s*```", re.DOTALL
        )
        matches = yaml_pattern.findall(content)

        decisions: list[ReviewDecision] = []
        for yaml_text in matches:
            parsed = yaml.safe_load(yaml_text)
            if parsed is None:
                continue
            if not isinstance(parsed, dict):
                continue
            # Only process blocks that look like decision blocks
            if "item_id" not in parsed or "decision" not in parsed:
                continue
            decision = ReviewDecision.model_validate(parsed)
            decisions.append(decision)

        return decisions
