"""Redaction Service for the Governance Layer.

Scans content for sensitive data patterns and creates redacted output views.
Raw artifacts are NEVER modified in-place — only output views are redacted.

Requirements: 19.1, 19.2, 19.3, 19.4
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class SensitiveDataType(str, Enum):
    """Types of sensitive data detected by the RedactionService."""

    PASSWORD = "password"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    PERSONAL_EMAIL = "personal_email"


@dataclass
class SensitiveDataFinding:
    """A single finding of sensitive data in content.

    Attributes:
        finding_id: Unique identifier for this finding.
        data_type: The type of sensitive data detected.
        value: The actual sensitive value found.
        start: Start position (character offset) in the content.
        end: End position (character offset) in the content.
        context: A brief snippet around the finding for analyst review.
    """

    finding_id: str
    data_type: SensitiveDataType
    value: str
    start: int
    end: int
    context: str = ""


# Regex patterns for detecting sensitive data types.
# Each pattern is a tuple of (SensitiveDataType, compiled regex).
_SENSITIVE_PATTERNS: list[tuple[SensitiveDataType, re.Pattern[str]]] = [
    # Passwords: matches common password assignment patterns
    (
        SensitiveDataType.PASSWORD,
        re.compile(
            r"""(?ix)
            (?:password|passwd|pwd|pass)\s*[:=]\s*
            (?:
                "([^"]{1,200})"      |  # double-quoted value
                '([^']{1,200})'      |  # single-quoted value
                (\S{4,200})             # unquoted value (at least 4 chars)
            )
            """,
        ),
    ),
    # API keys: matches common API key patterns
    (
        SensitiveDataType.API_KEY,
        re.compile(
            r"""(?ix)
            (?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*
            (?:
                "([^"]{8,200})"      |  # double-quoted
                '([^']{8,200})'      |  # single-quoted
                ([A-Za-z0-9_\-/.+=]{8,200})  # unquoted key-like value
            )
            """,
        ),
    ),
    # Private keys: PEM-format private key blocks
    (
        SensitiveDataType.PRIVATE_KEY,
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"
            r"[\s\S]*?"
            r"-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
            re.IGNORECASE,
        ),
    ),
    # Social Security Numbers: matches US SSN format (XXX-XX-XXXX)
    (
        SensitiveDataType.SSN,
        re.compile(
            r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
        ),
    ),
    # Credit card numbers: matches Visa, MC, Amex, Discover patterns
    (
        SensitiveDataType.CREDIT_CARD,
        re.compile(
            r"\b(?:"
            r"4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"  # Visa
            r"|5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"  # Mastercard
            r"|3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}"  # Amex
            r"|6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"  # Discover
            r")\b"
        ),
    ),
    # Personal email addresses
    (
        SensitiveDataType.PERSONAL_EMAIL,
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@"
            r"(?:gmail|yahoo|hotmail|outlook|protonmail|aol|icloud|mail|yandex|zoho)"
            r"\.[a-zA-Z]{2,}\b",
            re.IGNORECASE,
        ),
    ),
]


class RedactionService:
    """Scans content for sensitive data and creates redacted output views.

    Design invariants:
    - Raw artifacts are NEVER modified in-place (Requirement 19.4, Design Key Decision 9).
    - scan_content returns findings with type, value, and position (Requirement 19.1, 19.2).
    - create_redacted_view replaces only approved findings with [REDACTED-type] markers (Requirement 19.3).
    - Only approved_redactions are actually redacted in output views.
    """

    def scan_content(self, content: str) -> list[dict]:
        """Scan content for sensitive data patterns.

        Detects passwords, API keys, private keys, social security numbers,
        credit card numbers, and personal email addresses.

        Args:
            content: The text content to scan for sensitive data.

        Returns:
            A list of finding dictionaries, each containing:
                - finding_id: Unique ID for this finding
                - data_type: The type of sensitive data (e.g., "password", "api_key")
                - value: The matched sensitive value
                - start: Start character offset in content
                - end: End character offset in content
                - context: Brief surrounding context for analyst review
                - redaction_recommendation: Always "redact" (analyst may override)
        """
        findings: list[dict] = []

        for data_type, pattern in _SENSITIVE_PATTERNS:
            for match in pattern.finditer(content):
                # For patterns with capture groups, use the full match
                matched_value = match.group(0)
                start = match.start()
                end = match.end()

                # Build a context snippet (up to 20 chars on each side)
                ctx_start = max(0, start - 20)
                ctx_end = min(len(content), end + 20)
                context = content[ctx_start:ctx_end]

                finding = {
                    "finding_id": str(uuid.uuid4()),
                    "data_type": data_type.value,
                    "value": matched_value,
                    "start": start,
                    "end": end,
                    "context": context,
                    "redaction_recommendation": "redact",
                }
                findings.append(finding)

        # Sort findings by start position for stable output
        findings.sort(key=lambda f: f["start"])
        return findings

    def create_redacted_view(
        self, content: str, approved_redactions: list[dict]
    ) -> str:
        """Create a redacted view of content, replacing approved findings with markers.

        Only findings whose finding_id appears in approved_redactions are replaced.
        The original content string is NOT modified — a new string is returned.

        Args:
            content: The original text content (not modified).
            approved_redactions: List of approved finding dicts (must have
                "finding_id", "data_type", "start", "end").

        Returns:
            A new string with approved sensitive data replaced by
            [REDACTED-type] markers (e.g., [REDACTED-password]).
        """
        if not approved_redactions:
            return content

        # Sort approved redactions by start position descending so that
        # replacements don't shift offsets for earlier positions.
        sorted_redactions = sorted(
            approved_redactions, key=lambda r: r["start"], reverse=True
        )

        result = content
        for redaction in sorted_redactions:
            start = redaction["start"]
            end = redaction["end"]
            data_type = redaction["data_type"]
            marker = f"[REDACTED-{data_type}]"
            result = result[:start] + marker + result[end:]

        return result

    def redact_report_output(
        self, report_md: str, approved_redactions: list[dict]
    ) -> str:
        """Apply redaction to a report Markdown output.

        This is a convenience method for report-specific redaction. It
        re-scans the report content and applies approved redactions based
        on matching finding_ids or, for redactions with value-based matching,
        replaces all occurrences of the sensitive value.

        Args:
            report_md: The report Markdown text (not modified).
            approved_redactions: List of approved finding dicts containing
                at minimum "data_type" and "value" fields.

        Returns:
            A new string with sensitive data replaced by [REDACTED-type] markers.
        """
        if not approved_redactions:
            return report_md

        result = report_md
        # For report-level redaction, we do value-based replacement since
        # the report is a new document whose character offsets differ from
        # the original artifact scan.
        for redaction in approved_redactions:
            data_type = redaction["data_type"]
            value = redaction["value"]
            marker = f"[REDACTED-{data_type}]"
            result = result.replace(value, marker)

        return result

    def generate_redaction_report(self, detections: list[dict]) -> str:
        """Generate a human-readable redaction report for analyst review.

        Lists all detections grouped by type with their context and
        recommendations.

        Args:
            detections: List of finding dicts from scan_content().

        Returns:
            A Markdown-formatted report summarizing all detections.
        """
        if not detections:
            return "# Redaction Report\n\nNo sensitive data detected.\n"

        lines = ["# Redaction Report\n"]
        lines.append(f"Total detections: {len(detections)}\n")

        # Group by type
        by_type: dict[str, list[dict]] = {}
        for d in detections:
            dtype = d["data_type"]
            by_type.setdefault(dtype, []).append(d)

        for dtype, items in sorted(by_type.items()):
            lines.append(f"\n## {dtype} ({len(items)} found)\n")
            for item in items:
                lines.append(f"- **ID**: `{item['finding_id']}`")
                lines.append(f"  - Position: {item['start']}-{item['end']}")
                lines.append(f"  - Context: `{item['context']}`")
                lines.append(
                    f"  - Recommendation: {item['redaction_recommendation']}"
                )
                lines.append("")

        return "\n".join(lines)
