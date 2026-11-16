"""IOC Formatter for the IR Reporting Layer.

Formats Indicators of Compromise (IOCs) into defanged markdown appendix
tables for inclusion in reports. Uses the LocalizationEngine for IOC
defanging and provides structured output compatible with the report
generation pipeline.

Requirements: 5.4, 25.4, 25.8
"""

from __future__ import annotations

import logging
from typing import Optional

from ir_agent.models.evidence import IOCRecord
from ir_agent.reporting.localization import LocalizationEngine

logger = logging.getLogger(__name__)


class IOCFormatter:
    """Formats IOC records into defanged markdown appendix tables.

    Provides methods to defang individual IOC values and to format a
    complete list of IOCs into a markdown table suitable for report
    appendices. IOC values are defanged by default (dots replaced with
    [.] for IPs/domains, hxxp for URLs, etc.) to prevent accidental
    activation.

    Uses LocalizationEngine.format_ioc_defanged() for defanging logic.
    """

    def __init__(
        self,
        localization: LocalizationEngine | None = None,
        language: str = "ja",
    ):
        """Initialize the IOCFormatter.

        Args:
            localization: Optional LocalizationEngine instance. A default
                instance is created if not provided.
            language: Language code for table headers (default "ja").
        """
        self._localization = localization or LocalizationEngine()
        self._language = language

    def defang_value(self, value: str, ioc_type: str) -> str:
        """Defang a single IOC value for safe display.

        Delegates to LocalizationEngine.format_ioc_defanged() for
        consistent defanging logic across the system.

        Args:
            value: The raw IOC value.
            ioc_type: The IOC type (ip, domain, url, email, hash_md5,
                hash_sha1, hash_sha256, file_path).

        Returns:
            The defanged IOC value string.
        """
        return self._localization.format_ioc_defanged(value, ioc_type)

    def format_ioc_appendix(
        self,
        iocs: list[IOCRecord],
        defang: bool = True,
        language: Optional[str] = None,
    ) -> str:
        """Format a list of IOC records into a markdown appendix table.

        Produces a markdown table with columns for IOC type, value (defanged
        if requested), and source reference. IOCs are grouped by type for
        readability.

        Args:
            iocs: List of IOCRecord objects to format.
            defang: If True (default), IOC values are defanged before display.
                Set to False only if the analyst explicitly requests raw values.
            language: Language code for table headers. Falls back to the
                instance default if not specified.

        Returns:
            A markdown-formatted string containing the IOC appendix table.
        """
        lang = language or self._language

        # Get table caption
        captions = self._localization.get_table_captions(lang)
        caption = captions.get("ioc_table", "IoC List")

        parts: list[str] = []
        parts.append(caption)
        parts.append("")

        # Table headers
        if lang == "ja":
            parts.append("| 種別 | 値 | 概要/役割 | 確認箇所 |")
        else:
            parts.append("| Type | Value | Summary / Role | Location |")
        parts.append("|---|---|---|---|")

        if not iocs:
            # Empty table row
            if lang == "ja":
                parts.append("| — | — | — | — |")
            else:
                parts.append("| — | — | — | — |")
            return "\n".join(parts)

        # Sort IOCs by type for organized display
        sorted_iocs = sorted(iocs, key=lambda ioc: (ioc.ioc_type, ioc.value))

        for ioc in sorted_iocs:
            display_value = (
                self.defang_value(ioc.value, ioc.ioc_type)
                if defang
                else ioc.value
            )

            # Format the type label
            type_label = self._format_type_label(ioc.ioc_type, lang)

            # Source reference
            source = f"{ioc.source_file_id}:L{ioc.source_line}"
            summary = self._summary_for_type(ioc.ioc_type, lang)

            # Escape pipe characters in values for markdown table
            display_value = display_value.replace("|", "\\|")

            parts.append(f"| {type_label} | `{display_value}` | {summary} | {source} |")

        return "\n".join(parts)

    def _summary_for_type(self, ioc_type: str, language: str) -> str:
        """Return a short customer-facing role summary for an IoC type."""
        if language == "ja":
            summaries = {
                "ip": "通信先または接続元として確認されたIPアドレスです。",
                "domain": "通信先または参照先として確認されたドメイン名です。",
                "url": "通信先または参照先として確認されたURLです。",
                "hash": "ファイル識別子として確認されたハッシュ値です。",
                "file_path": "調査過程で確認されたファイルパスです。",
            }
            return summaries.get(ioc_type, "調査過程で確認された指標です。")
        summaries = {
            "ip": "IP address observed as a source or destination.",
            "domain": "Domain observed as a destination or reference.",
            "url": "URL observed as a destination or reference.",
            "hash": "Hash value observed as a file identifier.",
            "file_path": "File path observed during the investigation.",
        }
        return summaries.get(ioc_type, "Indicator observed during the investigation.")

    def _format_type_label(self, ioc_type: str, language: str) -> str:
        """Get a human-readable label for an IOC type.

        Args:
            ioc_type: The IOC type identifier.
            language: Language code for the label.

        Returns:
            Human-readable IOC type label.
        """
        labels_ja: dict[str, str] = {
            "ip": "IPアドレス",
            "domain": "ドメイン",
            "hash_md5": "MD5ハッシュ",
            "hash_sha1": "SHA-1ハッシュ",
            "hash_sha256": "SHA-256ハッシュ",
            "file_path": "ファイルパス",
            "url": "URL",
            "email": "メールアドレス",
        }

        labels_en: dict[str, str] = {
            "ip": "IP Address",
            "domain": "Domain",
            "hash_md5": "MD5 Hash",
            "hash_sha1": "SHA-1 Hash",
            "hash_sha256": "SHA-256 Hash",
            "file_path": "File Path",
            "url": "URL",
            "email": "Email",
        }

        if language == "ja":
            return labels_ja.get(ioc_type, ioc_type)
        return labels_en.get(ioc_type, ioc_type)
