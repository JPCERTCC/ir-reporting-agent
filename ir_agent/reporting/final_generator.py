"""Final Report Generator for the IR Reporting Layer.

Generates the final report from the analyst-approved draft. This generator
does NOT re-generate content — it takes the approved draft as-is, removes
the draft watermark, adds a confidentiality notice, and records the final
approval in the audit log.

Requirements: 17.1, 17.3, 17.4, 17.5
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ir_agent.reporting.localization import LocalizationEngine

if TYPE_CHECKING:
    from ir_agent.governance.audit import AuditLogger

logger = logging.getLogger(__name__)


class FinalReportBlockedError(Exception):
    """The final text failed the final-report check; nothing was written."""

    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


class FinalReportGenerator:
    """Produces the final report from an approved draft.

    The finalize process:
    1. Reads the approved draft report verbatim.
    2. Removes the draft watermark line.
    3. Adds a confidentiality notice at the top.
    4. Records the final approval decision in the audit log.
    5. Writes final_report.md to the reports/ directory.

    Design invariants:
    - Does NOT re-generate or modify the content of the approved draft
      (Requirement 17.3).
    - Requires explicit analyst approval before producing the final report
      (Requirement 17.4).
    - Final report includes: investigation overview, executive summary,
      TTP-based findings, per-system findings, remediation recommendations,
      and appendices (Requirement 17.5).
    """

    def __init__(
        self,
        localization: LocalizationEngine | None = None,
        report_language: str = "ja",
        report_timezone: str = "UTC",
    ):
        """Initialize the FinalReportGenerator.

        Args:
            localization: Optional LocalizationEngine instance. A default
                instance is created if not provided.
            report_language: Language code for boilerplate text (default "ja").
            report_timezone: IANA timezone for the finalize date stamp.
        """
        self._localization = localization or LocalizationEngine()
        self._report_language = report_language
        self._report_timezone = report_timezone

    def finalize_report(
        self,
        approved_draft_path: Path,
        audit_logger: AuditLogger,
        analyst_id: str,
        check: Callable[[str], list[str]] | None = None,
    ) -> Path:
        """Generate final_report.md from the approved draft.

        Reads the approved draft, removes the draft watermark, adds a
        confidentiality notice, and writes the final report. The final
        approval is recorded in the audit log.

        This method does NOT re-generate content. The approved draft is
        used as-is with only formatting adjustments (watermark removal,
        confidentiality notice addition).

        Args:
            approved_draft_path: Path to the approved draft report
                (e.g., ``<case_dir>/reports/draft_report.md``).
            audit_logger: AuditLogger instance for recording the final
                approval decision.
            analyst_id: ID of the analyst who approved the final report.
            check: Optional validator for the final text; when it returns
                problems nothing is written and FinalReportBlockedError is
                raised.

        Returns:
            Path to the generated final_report.md file.

        Raises:
            FileNotFoundError: If the approved draft path does not exist.
            AuditWriteError: If the audit log write fails (propagated from
                AuditLogger, halting the operation per Requirement 20.5).
        """
        if not approved_draft_path.exists():
            raise FileNotFoundError(
                f"Approved draft not found: {approved_draft_path}"
            )

        # Read the approved draft content
        draft_content = approved_draft_path.read_text(encoding="utf-8")

        # Remove draft watermark
        final_content = self._remove_draft_watermark(draft_content)

        # Add confidentiality notice
        final_content = self._add_confidentiality_notice(final_content)

        # Update the title to remove "(Draft)" / "(ドラフト)" indicator
        final_content = self._update_title_to_final(final_content)

        # Stamp the finalized version into the metadata table and change
        # history so the final report no longer self-identifies as a draft.
        # Only version metadata is touched; report content is unchanged. (UP-04)
        final_content = self._stamp_final_version(final_content, analyst_id)

        # Reviewer fill-in comments are instructions to the reviewer, not text
        # for the customer.
        final_content = self._remove_reviewer_comments(final_content)

        if check is not None:
            problems = check(final_content)
            if problems:
                raise FinalReportBlockedError(problems)

        # Determine output path (same directory as draft)
        output_path = approved_draft_path.parent / "final_report.md"

        # Write the final report
        output_path.write_text(final_content, encoding="utf-8")

        # Record the final approval in the audit log
        self._log_final_approval(audit_logger, analyst_id, output_path)

        logger.info("Final report generated at: %s", output_path)
        return output_path

    def _stamp_final_version(self, content: str, analyst_id: str = "") -> str:
        """Stamp the finalized version into the metadata table and history.

        Updates only the version fields:
        - metadata 版数 cell: ``0.1(ドラフト)`` -> ``1.0(確定)``
        - metadata 作成者 cell: drops the ``(レビュー前ドラフト)`` suffix, and
          a 承認者 row naming the approving analyst is added after it
        - change history: appends a ``1.0`` finalize row, attributed to the
          approving analyst, directly after the initial draft row

        Half-width and full-width parentheses are both handled. Report body
        text is not modified. Applies to Japanese reports only.

        Requirement UP-04.
        """
        if self._report_language != "ja":
            return content

        import re
        from datetime import datetime

        try:
            from zoneinfo import ZoneInfo

            today = datetime.now(ZoneInfo(self._report_timezone)).strftime(
                "%Y-%m-%d"
            )
        except Exception:
            today = datetime.now().strftime("%Y-%m-%d")

        # The final report is issued today: 作成日 / 報告時点 are the issue date.
        content = re.sub(
            r"(?m)^(\|\s*(?:作成日|報告時点)\s*\|\s*)\d{4}-\d{2}-\d{2}(\s*\|)",
            rf"\g<1>{today}\g<2>",
            content,
        )
        content = re.sub(
            r"(\|\s*版数\s*\|\s*)0\.1\s*[（(]ドラフト[)）](\s*\|)",
            r"\g<1>1.0（確定）\g<2>",
            content,
        )
        approver = analyst_id.strip().replace("|", "/") or "分析担当者"
        content = re.sub(
            # "IR Reporting Agent" is the pre-rename name in older drafts.
            r"(\|\s*作成者\s*\|\s*IR Reporting (?:Support )?Agent)"
            r"\s*[（(]レビュー前ドラフト[)）](\s*\|)",
            r"\g<1>\g<2>",
            content,
        )
        if not re.search(r"(?m)^\|\s*承認者\s*\|", content):
            content = re.sub(
                r"(?m)^(\|\s*作成者\s*\|[^\n]*\|)[ \t]*$",
                lambda m: m.group(1) + f"\n| 承認者 | {approver} |",
                content,
                count=1,
            )

        def _append_history_row(match: re.Match[str]) -> str:
            return (
                match.group(0)
                + f"\n| 1.0 | {today} | 分析担当者承認により確定 | {approver} |"
            )

        # ``[ \t]*`` rather than ``\s*``: ``\s`` would swallow the newline and
        # leave a blank line that splits the history table in two.
        content = re.sub(
            r"(?m)^\|\s*0\.1\s*\|[^\n]*初版ドラフト作成[^\n]*\|[ \t]*$",
            _append_history_row,
            content,
            count=1,
        )
        return content

    def _remove_reviewer_comments(self, content: str) -> str:
        """Drop ``<!-- レビュー担当者記入欄 … -->`` lines (and the blank line after)."""
        import re

        return re.sub(r"(?m)^<!--\s*レビュー担当者記入欄.*?-->[ \t]*(?:\n|\Z)(?:[ \t]*\n)?",
                      "", content, flags=re.S)

    def _remove_draft_watermark(self, content: str) -> str:
        """Remove draft watermark lines from the content.

        Removes both Japanese and English draft watermark lines that are
        inserted by the DraftGenerator.

        Args:
            content: The draft report content.

        Returns:
            Content with draft watermark lines removed.
        """
        boilerplate_ja = self._localization.get_boilerplate_templates("ja")
        boilerplate_en = self._localization.get_boilerplate_templates("en")

        watermarks = [
            boilerplate_ja["draft_watermark"],
            boilerplate_en["draft_watermark"],
        ]

        lines = content.split("\n")
        filtered_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped in watermarks:
                continue
            filtered_lines.append(line)

        # Remove leading blank lines after watermark removal
        while filtered_lines and filtered_lines[0].strip() == "":
            filtered_lines.pop(0)

        return "\n".join(filtered_lines)

    def _add_confidentiality_notice(self, content: str) -> str:
        """Add a confidentiality notice at the top of the report.

        Args:
            content: The report content (watermark already removed).

        Returns:
            Content with confidentiality notice prepended.
        """
        boilerplate = self._localization.get_boilerplate_templates(
            self._report_language
        )
        notice = boilerplate["confidentiality_notice"]

        # Format as a blockquote for visual distinction
        notice_block = f"> {notice}\n\n---\n"

        return f"{notice_block}\n{content}"

    def _update_title_to_final(self, content: str) -> str:
        """Update the report title to indicate it is the final version.

        Replaces "(Draft)" / "(ドラフト)" in the title with "(Final)" / "(最終版)".

        Args:
            content: The report content.

        Returns:
            Content with title updated to final version indicator.
        """
        content = content.replace(
            "インシデント調査報告書（ドラフト）",
            "インシデント調査報告書（最終版）",
        )
        content = content.replace(
            "Incident Investigation Report (Draft)",
            "Incident Investigation Report (Final)",
        )
        return content

    def _log_final_approval(
        self,
        audit_logger: AuditLogger,
        analyst_id: str,
        output_path: Path,
    ) -> None:
        """Record the final report approval in the audit log.

        Args:
            audit_logger: AuditLogger instance.
            analyst_id: ID of the approving analyst.
            output_path: Path to the generated final report.
        """
        from ir_agent.models.governance import ApprovalEntry

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        approval = ApprovalEntry(
            timestamp=now_utc,
            analyst_id=analyst_id,
            item_type="final_report",
            item_id=str(output_path),
            decision="approved",
            reason="Final report generated from approved draft",
        )
        audit_logger.log_approval(approval)
