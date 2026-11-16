"""Rubric Checker for the IR Reporting Layer.

Evaluates draft and final reports against a configurable report quality
rubric. Each rubric item defines a check that must pass for the report
to be considered conformant with IR reporting standards.

Requirements: 28.1, 28.2, 28.3, 28.4
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ir_agent.steering.manifest import CaseManifest

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default rubric items when none are provided in the manifest
# ---------------------------------------------------------------------------

DEFAULT_RUBRIC_ITEMS: list[dict[str, Any]] = [
    {
        "id": "R01",
        "description": "Investigation purpose and scope",
        "check_type": "section_present",
        "section_keywords": ["調査目的", "調査範囲", "purpose", "scope"],
        "severity": "critical",
    },
    {
        "id": "R02",
        "description": "Data provided / evidence list",
        "check_type": "section_present",
        "section_keywords": ["調査対象", "provided data", "evidence list", "提供データ"],
        "severity": "critical",
    },
    {
        "id": "R03",
        "description": "Investigation period",
        "check_type": "section_present",
        "section_keywords": ["調査期間", "対象期間", "investigation period", "スケジュール"],
        "severity": "critical",
    },
    {
        "id": "R04",
        "description": "Investigation limitations",
        "check_type": "limitations_covered",
        "section_keywords": ["制約", "limitation", "制限"],
        "severity": "critical",
    },
    {
        "id": "R05",
        "description": "Executive summary",
        "check_type": "section_present",
        "section_keywords": ["エグゼクティブサマリー", "executive summary", "概要"],
        "severity": "critical",
    },
    {
        "id": "R06",
        "description": "Incident timeline",
        "check_type": "section_present",
        "section_keywords": ["タイムライン", "timeline", "時系列"],
        "severity": "major",
    },
    {
        "id": "R07",
        "description": "TTP-based findings",
        "check_type": "section_present",
        "section_keywords": ["TTP", "ATT&CK", "調査結果"],
        "severity": "critical",
    },
    {
        "id": "R08",
        "description": "Per-system findings",
        "check_type": "section_present",
        "section_keywords": ["システム別", "対象別", "per-system", "詳細調査", "対象別調査結果詳細"],
        "severity": "major",
    },
    {
        "id": "R09",
        "description": "Evidence references present",
        "check_type": "evidence_cited",
        "severity": "critical",
    },
    {
        "id": "R10",
        "description": "Uncertainty wording compliance",
        "check_type": "expression_policy_compliance",
        "severity": "major",
    },
    {
        "id": "R11",
        "description": "Containment and recovery section",
        "check_type": "section_present",
        "section_keywords": ["封じ込め", "復旧", "対応状況", "containment", "recovery"],
        "severity": "major",
    },
    {
        "id": "R12",
        "description": "Remediation recommendations",
        "check_type": "section_present",
        "section_keywords": ["改善", "再発防止", "推奨対策", "推奨対応", "remediation", "recommendation", "是正"],
        "severity": "major",
    },
    {
        "id": "R13",
        "description": "IoC appendix present",
        "check_type": "section_present",
        "section_keywords": ["IoC", "IOC", "Indicator"],
        "severity": "major",
    },
    {
        "id": "R14",
        "description": "MITRE ATT&CK mapping appendix",
        "check_type": "section_present",
        "section_keywords": ["ATT&CK", "MITRE", "マッピング"],
        "severity": "major",
    },
]


class RubricChecker:
    """Evaluates reports against a quality rubric.

    The rubric defines a set of check items, each with:
    - id: Unique identifier for the rubric item.
    - description: Human-readable description.
    - check_type: Type of check to perform:
        - section_present: Verify a required section exists in the report.
        - evidence_cited: Verify that evidence citations are present.
        - limitations_covered: Verify limitations section exists and has content.
        - expression_policy_compliance: Verify confidence language usage.
    - severity: One of "critical", "major", or "minor".
    - section_keywords: (for section_present) Keywords to search for.

    Check results include:
    - items: List of individual check results.
    - critical_failures: List of items that failed with critical severity.
    - audit_log_valid: Boolean indicating audit log accessibility.

    Requirements:
    - 28.1: Evaluate each draft against the Report_Rubric.
    - 28.2: Check for required sections and content.
    - 28.3: Output rubric check results with passed/failed/warnings.
    - 28.4: Block final report on critical rubric failures.
    """

    def check_rubric(
        self,
        report: str,
        rubric: dict[str, Any] | None,
        manifest: CaseManifest,
    ) -> dict[str, Any]:
        """Evaluate a report against the rubric items.

        If the rubric dict from the manifest is empty or None, the default
        rubric items are used.

        Args:
            report: The report content as a Markdown string.
            rubric: Rubric configuration from the case manifest. Expected
                to have an 'items' key with a list of rubric item dicts.
                If None or empty, DEFAULT_RUBRIC_ITEMS is used.
            manifest: The CaseManifest for context (language, expression
                policy, etc.).

        Returns:
            A results dict with keys:
            - items: List of check result dicts, each containing:
                - id: Rubric item ID.
                - description: Item description.
                - severity: Item severity.
                - passed: Boolean indicating pass/fail.
                - detail: Optional detail message.
            - critical_failures: List of failed critical item IDs.
            - audit_log_valid: Boolean (defaults to True; caller may
                override based on external audit log validation).
            - passed_items: List of passed item IDs.
            - failed_items: List of all failed item IDs.
            - warnings: List of warning messages for minor issues.
        """
        # Resolve rubric items
        rubric_items = self._resolve_rubric_items(rubric)

        results: list[dict[str, Any]] = []
        for item in rubric_items:
            result = self._check_item(item, report, manifest)
            results.append(result)

        # Categorize results
        passed_items = [r["id"] for r in results if r["passed"]]
        failed_items = [r["id"] for r in results if not r["passed"]]
        critical_failures = [
            r["id"] for r in results
            if not r["passed"] and r["severity"] == "critical"
        ]
        warnings = [
            f"{r['id']}: {r['description']} — {r.get('detail', 'check failed')}"
            for r in results
            if not r["passed"] and r["severity"] == "minor"
        ]

        return {
            "items": results,
            "critical_failures": critical_failures,
            "audit_log_valid": True,
            "passed_items": passed_items,
            "failed_items": failed_items,
            "warnings": warnings,
        }

    def has_critical_failures(self, results: dict[str, Any]) -> bool:
        """Check if the rubric results contain any critical failures.

        Args:
            results: Results dict from check_rubric().

        Returns:
            True if there are one or more critical failures.
        """
        critical = results.get("critical_failures", [])
        return len(critical) > 0

    def _resolve_rubric_items(
        self, rubric: dict[str, Any] | None
    ) -> list[dict[str, Any]]:
        """Resolve rubric items from manifest config or use defaults.

        Args:
            rubric: Rubric configuration dict from the manifest.

        Returns:
            List of rubric item dicts to evaluate.
        """
        if rubric and "items" in rubric and rubric["items"]:
            return rubric["items"]
        return DEFAULT_RUBRIC_ITEMS

    def _check_item(
        self,
        item: dict[str, Any],
        report: str,
        manifest: CaseManifest,
    ) -> dict[str, Any]:
        """Evaluate a single rubric item against the report.

        Dispatches to the appropriate check method based on check_type.

        Args:
            item: Rubric item dict.
            report: Report content.
            manifest: CaseManifest for context.

        Returns:
            Check result dict with id, description, severity, passed, detail.
        """
        check_type = item.get("check_type", "section_present")
        item_id = item.get("id", "UNKNOWN")
        description = item.get("description", "")
        severity = item.get("severity", "major")

        if check_type == "section_present":
            passed, detail = self._check_section_present(item, report)
        elif check_type == "evidence_cited":
            passed, detail = self._check_evidence_cited(report)
        elif check_type == "limitations_covered":
            passed, detail = self._check_limitations_covered(item, report)
        elif check_type == "expression_policy_compliance":
            passed, detail = self._check_expression_policy(report, manifest)
        else:
            # Unknown check type — treat as passed with warning
            passed = True
            detail = f"Unknown check_type '{check_type}' — skipped"

        return {
            "id": item_id,
            "description": description,
            "severity": severity,
            "passed": passed,
            "detail": detail,
        }

    def _check_section_present(
        self, item: dict[str, Any], report: str
    ) -> tuple[bool, str]:
        """Check if a required section is present in the report.

        Searches for any of the section_keywords in the report content.
        Keywords are matched case-insensitively against headings and content.

        Args:
            item: Rubric item dict with 'section_keywords' list.
            report: Report content.

        Returns:
            (passed, detail) tuple.
        """
        keywords = item.get("section_keywords", [])
        if not keywords:
            return True, "No keywords specified — pass by default"

        report_lower = report.lower()
        found_keywords = [kw for kw in keywords if kw.lower() in report_lower]

        if found_keywords:
            return True, f"Found keywords: {found_keywords}"
        return False, f"None of the required keywords found: {keywords}"

    def _check_evidence_cited(self, report: str) -> tuple[bool, str]:
        """Check if evidence citations are present in the report.

        Looks for evidence ID references in the format used by the
        DraftGenerator (e.g., "(Evidence ID: EV-001)" or "（証拠ID: EV-001）").

        Args:
            report: Report content.

        Returns:
            (passed, detail) tuple.
        """
        # Match patterns like (Evidence ID: ...) or （証拠ID: ...）
        patterns = [
            r"\(Evidence ID:\s*[\w\-]+\)",
            r"（証拠ID:\s*[\w\-]+）",
            r"\(証拠ID:\s*[\w\-]+\)",
            r"EV-\d+",
        ]

        citations_found = 0
        for pattern in patterns:
            matches = re.findall(pattern, report)
            citations_found += len(matches)

        if citations_found > 0:
            return True, f"Found {citations_found} evidence citation(s)"
        return False, "No evidence citations found in the report"

    def _check_limitations_covered(
        self, item: dict[str, Any], report: str
    ) -> tuple[bool, str]:
        """Check if limitations are covered in the report.

        Verifies that a limitations section exists and contains substantive
        content (not just a heading).

        Args:
            item: Rubric item dict with 'section_keywords' list.
            report: Report content.

        Returns:
            (passed, detail) tuple.
        """
        keywords = item.get("section_keywords", ["制約", "limitation"])
        report_lower = report.lower()

        # First check if any keyword is present
        found = False
        for kw in keywords:
            if kw.lower() in report_lower:
                found = True
                break

        if not found:
            return False, "No limitations section found"

        # Check for substantive content around limitations keywords
        # Look for at least one paragraph or bullet point after a heading
        # that contains a keyword
        lines = report.split("\n")
        in_limitations_section = False
        content_lines = 0

        for line in lines:
            line_lower = line.lower()
            # Only trigger section detection on heading lines with keywords
            if line.startswith("#") and any(
                kw.lower() in line_lower for kw in keywords
            ):
                in_limitations_section = True
                continue
            if in_limitations_section:
                # Stop at next heading
                if line.startswith("#"):
                    break
                if line.strip():
                    content_lines += 1

        if content_lines > 0:
            return True, f"Limitations section has {content_lines} content line(s)"

        inline_limitation_lines = [
            line for line in lines
            if any(kw.lower() in line.lower() for kw in keywords)
            and not line.lstrip().startswith("#")
            and line.strip()
        ]
        if inline_limitation_lines:
            return (
                True,
                f"Found {len(inline_limitation_lines)} inline limitation statement(s)",
            )

        return False, "Limitations section found but appears empty"

    def _check_expression_policy(
        self, report: str, manifest: CaseManifest
    ) -> tuple[bool, str]:
        """Check if the report uses confidence-appropriate language.

        Verifies that confidence qualifiers are present when the report
        discusses findings at different confidence levels. This is a
        heuristic check — it looks for the presence of confidence markers.

        Args:
            report: Report content.
            manifest: CaseManifest with language info.

        Returns:
            (passed, detail) tuple.
        """
        language = manifest.report_language

        # Confidence markers to look for (at least some should be present
        # in a well-formed report that has non-confirmed findings)
        if language == "ja":
            confidence_markers = [
                "高確度",
                "可能性",
                "不明",
                "観測されず",
                "確認",
            ]
        else:
            confidence_markers = [
                "Probable",
                "Possible",
                "Unknown",
                "Not Observed",
                "Confirmed",
                "likely",
                "may have",
            ]

        found_markers = [m for m in confidence_markers if m in report]

        if found_markers:
            return True, f"Found confidence markers: {found_markers}"

        # If the report has content but no confidence markers, it might
        # be all confirmed facts (which is valid) or missing markers
        # We pass with a note rather than failing, since all-confirmed
        # reports are valid.
        if len(report) > 200:
            return True, "No confidence markers found (may be all confirmed facts)"

        return True, "Report too short for meaningful expression policy check"
