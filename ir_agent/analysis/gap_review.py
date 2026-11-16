"""Gap Review Service for the Analysis Layer.

Generates Markdown gap review documents with YAML disposition blocks
for human review of identified gaps. Parses disposition decisions from
edited documents and applies them to the gaps store.

Validates Requirements: 13.5, 13.6, 13.7, 13.8
"""

from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, field_validator

from ir_agent.governance.review_options import GAP_OPTIONS, option_comment
from ir_agent.models.analysis import Gap


class GapDisposition(str, Enum):
    """Allowed disposition values for gap review.

    These values remain in English in the YAML decision blocks,
    regardless of the review_language used for document headings.
    """

    ACCEPTED_AS_LIMITATION = "accepted_as_limitation"
    MITIGATED_BY_CLAIM_DOWNGRADE = "mitigated_by_claim_downgrade"
    ADDRESSED_BY_ADDITIONAL_EVIDENCE = "addressed_by_additional_evidence"
    OUT_OF_SCOPE_WITH_ANALYST_APPROVAL = "out_of_scope_with_analyst_approval"
    DEFERRED_WITH_REASON = "deferred_with_reason"
    NEEDS_MORE_CONTEXT = "needs_more_context"


class GapDispositionDecision(BaseModel):
    """Pydantic model for a YAML disposition block in the gap review document.

    YAML keys and enum values are always in English regardless of
    the review_language used for document headings.
    """

    item_id: str
    item_type: str = "gap"
    disposition: str | None = None
    disposition_reason: str = ""
    analyst_id: str = ""

    @field_validator("disposition", mode="before")
    @classmethod
    def normalize_disposition(cls, v: str | None) -> str | None:
        """Accept disposition values case-insensitively."""
        if isinstance(v, str):
            stripped = v.strip().lower()
            if stripped == "" or stripped == "null" or stripped == "none":
                return None
            return stripped
        return v


# Section headings by language for gap review documents
_GAP_REVIEW_HEADINGS: dict[str, dict[str, str]] = {
    "ja": {
        "description": "説明",
        "related_claim": "関連Claim",
        "recommended_action": "推奨対応",
        "impact": "影響",
        "disposition": "判定",
    },
    "en": {
        "description": "Description",
        "related_claim": "Related Claim",
        "recommended_action": "Recommended Action",
        "impact": "Impact",
        "disposition": "Disposition",
    },
}


def _get_gap_headings(review_language: str) -> dict[str, str]:
    """Get gap review section headings for the specified language, defaulting to Japanese."""
    return _GAP_REVIEW_HEADINGS.get(review_language, _GAP_REVIEW_HEADINGS["ja"])


class GapReviewService:
    """Generates and parses Markdown gap review documents with YAML disposition blocks.

    The generated document presents each gap with section headings in the
    review_language, while YAML disposition block keys and enum values
    remain in English for machine-parseable consistency.
    """

    def generate_gap_review_doc(
        self,
        gaps: list[Gap],
        output_path: Path,
        review_language: str = "ja",
    ) -> None:
        """Generate a Markdown gap review document for identified gaps.

        Args:
            gaps: List of Gap objects to include in the review document.
            output_path: Path where the Markdown file will be written.
            review_language: Language for section headings (default "ja").
        """
        headings = _get_gap_headings(review_language)
        lines: list[str] = []

        # Document title
        if review_language == "ja":
            lines.append("# ギャップレビュー\n")
        else:
            lines.append("# Gap Review\n")
        lines.append("")

        for gap in gaps:
            lines.extend(self._render_gap(gap, headings, review_language))
            lines.append("")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")

    def _render_gap(
        self,
        gap: Gap,
        headings: dict[str, str],
        review_language: str = "ja",
    ) -> list[str]:
        """Render a single gap section."""
        lines: list[str] = []

        # Gap header
        lines.append(f"## {gap.gap_id}")
        lines.append("")

        # Metadata
        lines.append(f"- gap_id: `{gap.gap_id}`")
        lines.append(f"- gap_type: {gap.gap_type}")
        lines.append(f"- severity: {gap.severity}")
        lines.append("")

        # Description section
        lines.append(f"### {headings['description']}")
        lines.append("")
        lines.append(gap.description)
        lines.append("")

        # Related Claim section
        lines.append(f"### {headings['related_claim']}")
        lines.append("")
        lines.append(f"- claim_id: `{gap.related_claim_id}`")
        if gap.related_claim_id == "CASE-SCOPE":
            lines.append(
                "- ケース全体の不足事項です(特定の分析結果に紐づきません。"
                "詳細: `ir-agent source-coverage`)。"
            )
        lines.append("")

        # Recommended Action section
        lines.append(f"### {headings['recommended_action']}")
        lines.append("")
        lines.append(gap.recommended_action)
        lines.append("")

        # Impact section
        lines.append(f"### {headings['impact']}")
        lines.append("")
        # Derived from the gap itself rather than left as a fill-in placeholder:
        # a placeholder nobody fills is approved as-is and says nothing.
        lines.append(_impact_text(gap, review_language))
        lines.append("")

        # Disposition section with YAML block
        lines.append(f"### {headings['disposition']}")
        lines.append("")
        disposition_options = option_comment(GAP_OPTIONS, review_language)
        lines.append("```yaml")
        lines.append(f"item_id: {gap.gap_id}")
        lines.append("item_type: gap")
        lines.append(f"disposition: null  # {disposition_options}")
        lines.append('disposition_reason: ""')
        lines.append('analyst_id: ""')
        lines.append("```")
        lines.append("")
        lines.append("---")

        return lines

    def parse_gap_review_doc(self, review_path: Path) -> list[GapDispositionDecision]:
        """Parse YAML disposition blocks from a gap review document.

        Extracts only the YAML code blocks, ignoring all prose content.
        This parsing is language-agnostic since YAML keys and values
        are always in English.

        Args:
            review_path: Path to the Markdown gap review document.

        Returns:
            List of validated GapDispositionDecision objects.

        Raises:
            FileNotFoundError: If review_path does not exist.
            ValueError: If a YAML block fails Pydantic validation.
        """
        content = review_path.read_text(encoding="utf-8")
        return self._extract_dispositions(content)

    def _extract_dispositions(self, content: str) -> list[GapDispositionDecision]:
        """Extract and validate YAML disposition blocks from Markdown content."""
        # Match all fenced YAML code blocks
        yaml_pattern = re.compile(
            r"```yaml\s*\n(.*?)\n\s*```", re.DOTALL
        )
        matches = yaml_pattern.findall(content)

        dispositions: list[GapDispositionDecision] = []
        for yaml_text in matches:
            parsed = yaml.safe_load(yaml_text)
            if parsed is None:
                continue
            if not isinstance(parsed, dict):
                continue
            # Only process blocks that look like disposition blocks
            if "item_id" not in parsed:
                continue
            # Normalize: treat "disposition" key presence as indicator
            if "disposition" not in parsed and "item_type" not in parsed:
                continue
            decision = GapDispositionDecision.model_validate(parsed)
            dispositions.append(decision)

        return dispositions

    def apply_gap_dispositions(
        self,
        dispositions: list[GapDispositionDecision],
        gaps_path: Path,
    ) -> list[Gap]:
        """Apply parsed dispositions to the gaps stored in a JSONL file.

        Reads all gaps from the JSONL file, applies matching dispositions,
        and rewrites the file with updated disposition fields.

        Args:
            dispositions: List of GapDispositionDecision objects parsed from
                the review document.
            gaps_path: Path to the gaps JSONL file.

        Returns:
            List of updated Gap objects.

        Raises:
            FileNotFoundError: If gaps_path does not exist.
        """
        # Read existing gaps
        gaps = self._read_gaps(gaps_path)

        # Build lookup by item_id
        disposition_map: dict[str, GapDispositionDecision] = {
            d.item_id: d for d in dispositions
        }

        # Apply dispositions
        updated_gaps: list[Gap] = []
        for gap in gaps:
            if gap.gap_id in disposition_map:
                decision = disposition_map[gap.gap_id]
                if decision.disposition is not None:
                    gap.disposition = decision.disposition
                    gap.disposition_reason = decision.disposition_reason
                    gap.dispositioned_by = decision.analyst_id or None
            updated_gaps.append(gap)

        # Write updated gaps back
        self._write_gaps(updated_gaps, gaps_path)

        return updated_gaps

    def _read_gaps(self, gaps_path: Path) -> list[Gap]:
        """Read gaps from a JSONL file."""
        if not gaps_path.exists():
            return []

        gaps: list[Gap] = []
        with open(gaps_path, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                data = json.loads(stripped)
                gaps.append(Gap.model_validate(data))
        return gaps

    def _write_gaps(self, gaps: list[Gap], gaps_path: Path) -> None:
        """Write gaps to a JSONL file, overwriting existing content."""
        gaps_path.parent.mkdir(parents=True, exist_ok=True)
        with open(gaps_path, "w", encoding="utf-8") as f:
            for gap in gaps:
                f.write(gap.model_dump_json() + "\n")


_IMPACT_JA = {
    "missing_evidence": "裏付けとなる記録が不足しているため、関連する分析結果は確定できず、"
                        "報告書では推定・可能性の表現に留まります。",
    "weak_evidence": "根拠の確度が低いため、関連する分析結果は可能性としての記載に留まります。",
    "single_source": "根拠が単一のソースに限られるため、独立した記録による裏付けがないことを"
                     "制約として明記する必要があります。",
    "unavailable_logs": "対象の記録が提供されていないため、該当する期間・ホストの事象は"
                        "確認も否定もできません。",
    "logs_outside_scope": "記録の期間が調査対象期間と重ならない部分があるため、該当期間の事象は"
                          "確認も否定もできません。",
    "logs_not_analyzed": "提供された記録の一部が分析結果に反映されていないため、当該記録に含まれる"
                         "事象の有無は報告書で判断できません。",
    "contradictory_evidence": "根拠の間に矛盾があるため、関連する分析結果の時刻・事象の解釈は"
                              "確定できません。",
}
_SEVERITY_JA = {"critical": "重大", "major": "中", "minor": "軽微"}


def _impact_text(gap: Gap, review_language: str) -> str:
    """Impact statement derived from the gap type and severity (no placeholder)."""
    severity = str(getattr(gap.severity, "value", gap.severity))
    gap_type = str(getattr(gap.gap_type, "value", gap.gap_type))
    if review_language != "ja":
        return (f"Severity {severity}: findings that depend on this gap "
                f"({gap_type}) cannot be stated as confirmed.")
    base = _IMPACT_JA.get(gap_type, "関連する分析結果の確度に影響します。")
    return f"影響度 {_SEVERITY_JA.get(severity, severity)}: {base}"

