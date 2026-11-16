"""Localization engine for the Reporting Layer.

Provides structural text elements (section headers, table captions, boilerplate,
error messages) in the target language, plus timezone-aware timestamp formatting
and IOC defanging for display output.

This engine is limited to structural elements only — it does NOT translate
evidentiary conclusions or claim text.
"""

from datetime import datetime
from typing import Optional

import pytz


# ---------------------------------------------------------------------------
# Language data: report section headers
# ---------------------------------------------------------------------------

_REPORT_SECTION_HEADERS: dict[str, dict[str, str]] = {
    "ja": {
        "investigation_overview": "調査概要",
        "executive_summary": "エグゼクティブサマリー",
        "ttp_based_findings": "TTPベースの調査結果",
        "per_system_findings": "システム別詳細調査結果",
        "remediation_recommendations": "改善・再発防止策",
        "appendix_ioc_list": "付録：IoC一覧",
        "appendix_attack_mapping": "付録：MITRE ATT&CKマッピング",
        "document_handling": "文書取扱い・機密区分",
        "change_history": "変更履歴",
        "investigation_background": "調査背景",
        "investigation_purpose_scope": "調査目的・範囲",
        "investigation_schedule": "調査スケジュール・調査対象期間",
        "investigated_systems": "調査対象システム・提供データ",
        "investigation_methods": "調査手法・使用ツール",
        "hearing_summary": "ヒアリング概要",
        "investigation_response_policy": "調査・対応方針",
        "incident_overview_diagram": "インシデント概要図",
        "incident_timeline": "インシデントタイムライン",
        "recommended_response_summary": "推奨対応まとめ",
        "containment_recovery": "封じ込め・復旧状況",
        "remediation_recurrence_prevention": "是正・再発防止策",
        "related_files_attachments": "関連ファイル・添付資料",
        "limitations": "調査の制約事項",
        "data_coverage_limitations": "データカバレッジの制約",
    },
    "en": {
        "investigation_overview": "Investigation Overview",
        "executive_summary": "Executive Summary",
        "ttp_based_findings": "TTP-Based Findings",
        "per_system_findings": "Per-System Detailed Findings",
        "remediation_recommendations": "Remediation Recommendations",
        "appendix_ioc_list": "Appendix: IoC List",
        "appendix_attack_mapping": "Appendix: MITRE ATT&CK Mapping",
        "document_handling": "Document Handling and Confidentiality",
        "change_history": "Change History",
        "investigation_background": "Investigation Background",
        "investigation_purpose_scope": "Investigation Purpose and Scope",
        "investigation_schedule": "Investigation Schedule and Period",
        "investigated_systems": "Investigated Systems and Provided Data",
        "investigation_methods": "Investigation Methods and Tools",
        "hearing_summary": "Hearing Summary",
        "investigation_response_policy": "Investigation and Response Policy",
        "incident_overview_diagram": "Incident Overview Diagram",
        "incident_timeline": "Incident Timeline",
        "recommended_response_summary": "Recommended Response Summary",
        "containment_recovery": "Containment and Recovery Status",
        "remediation_recurrence_prevention": "Remediation and Recurrence Prevention",
        "related_files_attachments": "Related Files and Attachments",
        "limitations": "Investigation Limitations",
        "data_coverage_limitations": "Data Coverage Limitations",
    },
}

# ---------------------------------------------------------------------------
# Language data: review document section headers
# ---------------------------------------------------------------------------

_REVIEW_SECTION_HEADERS: dict[str, dict[str, str]] = {
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
        # Gap review document headers
        "description": "説明",
        "related_claim": "関連Claim",
        "recommended_action": "推奨対応",
        "impact": "影響",
        "disposition": "判定",
    },
    "en": {
        "summary": "Summary",
        "observed_fact": "Observed Fact",
        "interpretation": "Interpretation",
        "confidence": "Confidence",
        "limitations": "Limitations",
        "recommended_expressions": "Recommended Expressions",
        "prohibited_expressions": "Prohibited Expressions",
        "source": "Source",
        "decision": "Decision",
        # Gap review document headers
        "description": "Description",
        "related_claim": "Related Claim",
        "recommended_action": "Recommended Action",
        "impact": "Impact",
        "disposition": "Disposition",
    },
}

# ---------------------------------------------------------------------------
# Language data: table captions
# ---------------------------------------------------------------------------

_TABLE_CAPTIONS: dict[str, dict[str, str]] = {
    "ja": {
        "ioc_table": "表：Indicator of Compromise (IoC) 一覧",
        "attack_mapping_table": "表：MITRE ATT&CKマッピング",
        "timeline_table": "表：インシデントタイムライン",
        "evidence_table": "表：証拠一覧",
        "data_coverage_table": "表：データカバレッジ",
        "investigation_tasks_table": "表：追加調査タスク",
        "systems_table": "表：調査対象システム一覧",
        "quality_metrics_table": "表：品質メトリクス",
    },
    "en": {
        "ioc_table": "Table: Indicators of Compromise (IoC)",
        "attack_mapping_table": "Table: MITRE ATT&CK Mapping",
        "timeline_table": "Table: Incident Timeline",
        "evidence_table": "Table: Evidence List",
        "data_coverage_table": "Table: Data Coverage",
        "investigation_tasks_table": "Table: Investigation Tasks",
        "systems_table": "Table: Investigated Systems",
        "quality_metrics_table": "Table: Quality Metrics",
    },
}

# ---------------------------------------------------------------------------
# Language data: boilerplate templates
# ---------------------------------------------------------------------------

_BOILERPLATE_TEMPLATES: dict[str, dict[str, str]] = {
    "ja": {
        "confidentiality_notice": (
            "本報告書は機密情報を含みます。"
            "許可なく第三者への開示、複製、配布を禁止します。"
        ),
        "evidence_citation": "（証拠ID: {evidence_id}）",
        "confidence_note": "信頼度: {confidence_level}",
        "limitation_prefix": "【制約事項】",
        "not_observed_disclaimer": (
            "上記の「観測されず」判定は、対象期間において"
            "利用可能なデータを分析した結果に基づくものであり、"
            "当該事象が発生しなかったことを保証するものではありません。"
        ),
        "data_unavailable_note": "当該データは{reason}のため利用不可。",
        "draft_watermark": "【ドラフト — 最終版ではありません】",
        "approval_required": "本セクションはアナリストによる承認が必要です。",
        "no_evidence_found": "関連する証拠は特定されませんでした。",
        "report_generated_at": "レポート生成日時: {timestamp}",
    },
    "en": {
        "confidentiality_notice": (
            "This report contains confidential information. "
            "Unauthorized disclosure, reproduction, or distribution is prohibited."
        ),
        "evidence_citation": "(Evidence ID: {evidence_id})",
        "confidence_note": "Confidence: {confidence_level}",
        "limitation_prefix": "[Limitation]",
        "not_observed_disclaimer": (
            "The 'not observed' determination above is based on analysis of "
            "available data during the target period and does not guarantee "
            "that the event did not occur."
        ),
        "data_unavailable_note": "Data unavailable due to {reason}.",
        "draft_watermark": "[DRAFT — Not a final version]",
        "approval_required": "This section requires analyst approval.",
        "no_evidence_found": "No related evidence was identified.",
        "report_generated_at": "Report generated at: {timestamp}",
    },
}

# ---------------------------------------------------------------------------
# Language data: error messages
# ---------------------------------------------------------------------------

_ERROR_MESSAGES: dict[str, dict[str, str]] = {
    "ja": {
        "workflow_blocked": "ワークフロー前提条件が未完了です",
        "missing_evidence": "証拠IDが見つかりません",
        "invalid_manifest": "ケースマニフェストが無効です",
        "approval_required": "アナリストの承認が必要です",
        "audit_write_failed": "監査ログへの書き込みに失敗しました — 操作を中止します",
        "llm_call_failed": "LLM呼び出しが失敗しました",
        "file_not_found": "ファイルが見つかりません: {path}",
        "parse_error": "パースエラー: {detail}",
        "validation_error": "バリデーションエラー: {detail}",
        "claim_without_evidence": "証拠なしのClaimは生成できません",
        "unresolved_critical_gaps": "未解決の重大ギャップがあります",
        "rubric_check_failed": "ルーブリックチェックに失敗しました",
        "redaction_detected": "機密情報が検出されました",
        "injection_detected": "プロンプトインジェクションの疑いが検出されました",
        "unsupported_language": "サポートされていない言語です: {language}",
        "timezone_invalid": "無効なタイムゾーンです: {timezone}",
    },
    "en": {
        "workflow_blocked": "Workflow prerequisites not completed",
        "missing_evidence": "Evidence ID not found",
        "invalid_manifest": "Invalid case manifest",
        "approval_required": "Analyst approval required",
        "audit_write_failed": "Failed to write audit log — operation aborted",
        "llm_call_failed": "LLM call failed",
        "file_not_found": "File not found: {path}",
        "parse_error": "Parse error: {detail}",
        "validation_error": "Validation error: {detail}",
        "claim_without_evidence": "Cannot generate a claim without evidence",
        "unresolved_critical_gaps": "Unresolved critical gaps remain",
        "rubric_check_failed": "Rubric check failed",
        "redaction_detected": "Sensitive information detected",
        "injection_detected": "Suspected prompt injection detected",
        "unsupported_language": "Unsupported language: {language}",
        "timezone_invalid": "Invalid timezone: {timezone}",
    },
}


class LocalizationEngine:
    """Provides structural text in the target language and formatting utilities.

    This engine handles:
    - Report section headers
    - Review document section headers
    - Table captions
    - Boilerplate templates
    - Timestamp formatting for display (timezone conversion)
    - IOC defanging for display output
    - CLI and review error messages

    It does NOT translate evidentiary conclusions or claim text.
    """

    def __init__(self, default_language: str = "ja", default_timezone: str = "Asia/Tokyo"):
        """Initialize the localization engine.

        Args:
            default_language: Default language code (e.g., "ja", "en").
            default_timezone: Default display timezone (e.g., "Asia/Tokyo").
        """
        self._default_language = default_language
        self._default_timezone = default_timezone

    @property
    def default_language(self) -> str:
        """Return the default language."""
        return self._default_language

    @property
    def default_timezone(self) -> str:
        """Return the default timezone."""
        return self._default_timezone

    def _resolve_language(self, language: Optional[str] = None) -> str:
        """Resolve language to use, falling back to default."""
        return language if language is not None else self._default_language

    def get_section_headers(self, language: Optional[str] = None) -> dict[str, str]:
        """Return report section headers in the specified language.

        Args:
            language: Language code. Falls back to default_language if None.

        Returns:
            Dict mapping section keys to localized header strings.

        Raises:
            ValueError: If the language is not supported.
        """
        lang = self._resolve_language(language)
        if lang not in _REPORT_SECTION_HEADERS:
            raise ValueError(
                _ERROR_MESSAGES.get(self._default_language, _ERROR_MESSAGES["en"])[
                    "unsupported_language"
                ].format(language=lang)
            )
        return dict(_REPORT_SECTION_HEADERS[lang])

    def get_review_section_headers(self, language: Optional[str] = None) -> dict[str, str]:
        """Return review document section headers in the specified language.

        For Japanese, returns headers like: 概要, 観測事実, 解釈, 信頼度,
        制約・不足情報, 推奨表現, 禁止表現, 出典, 判定.

        For gap review documents: 説明, 関連Claim, 推奨対応, 影響, 判定.

        Args:
            language: Language code. Falls back to default_language if None.

        Returns:
            Dict mapping section keys to localized header strings.

        Raises:
            ValueError: If the language is not supported.
        """
        lang = self._resolve_language(language)
        if lang not in _REVIEW_SECTION_HEADERS:
            raise ValueError(
                _ERROR_MESSAGES.get(self._default_language, _ERROR_MESSAGES["en"])[
                    "unsupported_language"
                ].format(language=lang)
            )
        return dict(_REVIEW_SECTION_HEADERS[lang])

    def get_table_captions(self, language: Optional[str] = None) -> dict[str, str]:
        """Return table captions in the specified language.

        Args:
            language: Language code. Falls back to default_language if None.

        Returns:
            Dict mapping table keys to localized caption strings.

        Raises:
            ValueError: If the language is not supported.
        """
        lang = self._resolve_language(language)
        if lang not in _TABLE_CAPTIONS:
            raise ValueError(
                _ERROR_MESSAGES.get(self._default_language, _ERROR_MESSAGES["en"])[
                    "unsupported_language"
                ].format(language=lang)
            )
        return dict(_TABLE_CAPTIONS[lang])

    def get_boilerplate_templates(self, language: Optional[str] = None) -> dict[str, str]:
        """Return boilerplate templates in the specified language.

        Templates may contain placeholders like {evidence_id}, {confidence_level},
        {reason}, {timestamp}, {path} that should be formatted by the caller.

        Args:
            language: Language code. Falls back to default_language if None.

        Returns:
            Dict mapping template keys to localized template strings.

        Raises:
            ValueError: If the language is not supported.
        """
        lang = self._resolve_language(language)
        if lang not in _BOILERPLATE_TEMPLATES:
            raise ValueError(
                _ERROR_MESSAGES.get(self._default_language, _ERROR_MESSAGES["en"])[
                    "unsupported_language"
                ].format(language=lang)
            )
        return dict(_BOILERPLATE_TEMPLATES[lang])

    def get_error_messages(self, language: Optional[str] = None) -> dict[str, str]:
        """Return CLI and review error messages in the specified language.

        Messages may contain placeholders like {path}, {detail}, {language},
        {timezone} that should be formatted by the caller.

        Args:
            language: Language code. Falls back to default_language if None.

        Returns:
            Dict mapping error keys to localized message strings.

        Raises:
            ValueError: If the language is not supported.
        """
        lang = self._resolve_language(language)
        if lang not in _ERROR_MESSAGES:
            raise ValueError(
                _ERROR_MESSAGES.get(self._default_language, _ERROR_MESSAGES["en"])[
                    "unsupported_language"
                ].format(language=lang)
            )
        return dict(_ERROR_MESSAGES[lang])

    def format_timestamp_for_display(
        self, utc_time: str, timezone: Optional[str] = None
    ) -> str:
        """Convert a UTC timestamp to the display timezone for report output.

        Accepts ISO 8601 format (e.g., '2024-01-15T10:30:00Z' or
        '2024-01-15T10:30:00+00:00') and returns a human-readable string
        in the target timezone.

        Args:
            utc_time: UTC timestamp in ISO 8601 format.
            timezone: Target timezone (e.g., "Asia/Tokyo"). Falls back to
                default_timezone if None.

        Returns:
            Formatted timestamp string in the target timezone,
            e.g., "2024-01-15 19:30:00 JST".

        Raises:
            ValueError: If the timezone is invalid or the timestamp cannot be parsed.
        """
        tz_name = timezone if timezone is not None else self._default_timezone

        try:
            target_tz = pytz.timezone(tz_name)
        except pytz.exceptions.UnknownTimeZoneError:
            raise ValueError(
                _ERROR_MESSAGES.get(self._default_language, _ERROR_MESSAGES["en"])[
                    "timezone_invalid"
                ].format(timezone=tz_name)
            )

        # Parse the UTC timestamp
        utc_str = utc_time.strip()
        # Handle 'Z' suffix
        if utc_str.endswith("Z"):
            utc_str = utc_str[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(utc_str)
        except ValueError:
            raise ValueError(
                _ERROR_MESSAGES.get(self._default_language, _ERROR_MESSAGES["en"])[
                    "parse_error"
                ].format(detail=f"Cannot parse timestamp: {utc_time}")
            )

        # If the datetime is naive (no timezone info), assume UTC
        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)

        # Convert to target timezone
        local_dt = dt.astimezone(target_tz)

        # Format with timezone abbreviation
        return local_dt.strftime("%Y-%m-%d %H:%M:%S %Z")

    def format_ioc_defanged(self, value: str, ioc_type: str) -> str:
        """Defang an IOC value for safe display in reports.

        Replaces dots with [.] for domains and IPs. For URLs, also replaces
        http/https with hxxp/hxxps. Other IOC types are returned unchanged.

        Args:
            value: The raw IOC value.
            ioc_type: The IOC type (e.g., "ip", "domain", "url", "hash_md5",
                "hash_sha1", "hash_sha256", "file_path", "email").

        Returns:
            Defanged IOC value string.
        """
        if ioc_type in ("ip", "domain"):
            return value.replace(".", "[.]")
        elif ioc_type == "url":
            # Replace http/https with hxxp/hxxps
            defanged = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
            # Defang dots in the host portion (up to first / after ://)
            protocol_end = defanged.find("://")
            if protocol_end == -1:
                # No protocol — defang all dots
                return defanged.replace(".", "[.]")
            protocol_end += 3
            rest = defanged[protocol_end:]
            path_start = rest.find("/")
            if path_start == -1:
                # No path — defang all dots in host
                host = rest.replace(".", "[.]")
                return defanged[:protocol_end] + host
            else:
                host = rest[:path_start].replace(".", "[.]")
                path = rest[path_start:]
                return defanged[:protocol_end] + host + path
        elif ioc_type == "email":
            # Defang dots and @ in email addresses
            return value.replace(".", "[.]").replace("@", "[@]")
        # For hashes, file paths, etc. — return unchanged
        return value
