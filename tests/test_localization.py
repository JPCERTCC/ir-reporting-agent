"""Tests for the LocalizationEngine in the Reporting Layer."""

import pytest

from ir_agent.reporting.localization import LocalizationEngine


@pytest.fixture
def engine():
    """Create a LocalizationEngine with default settings (ja, Asia/Tokyo)."""
    return LocalizationEngine()


@pytest.fixture
def engine_en():
    """Create a LocalizationEngine with English defaults."""
    return LocalizationEngine(default_language="en", default_timezone="UTC")


class TestGetSectionHeaders:
    """Tests for get_section_headers()."""

    def test_returns_japanese_headers_by_default(self, engine):
        headers = engine.get_section_headers()
        assert headers["investigation_overview"] == "調査概要"
        assert headers["executive_summary"] == "エグゼクティブサマリー"
        assert headers["ttp_based_findings"] == "TTPベースの調査結果"
        assert headers["per_system_findings"] == "システム別詳細調査結果"
        assert headers["remediation_recommendations"] == "改善・再発防止策"

    def test_returns_japanese_headers_explicitly(self, engine):
        headers = engine.get_section_headers("ja")
        assert headers["appendix_ioc_list"] == "付録：IoC一覧"
        assert headers["appendix_attack_mapping"] == "付録：MITRE ATT&CKマッピング"

    def test_returns_english_headers(self, engine):
        headers = engine.get_section_headers("en")
        assert headers["investigation_overview"] == "Investigation Overview"
        assert headers["executive_summary"] == "Executive Summary"

    def test_raises_for_unsupported_language(self, engine):
        with pytest.raises(ValueError, match="サポートされていない言語です"):
            engine.get_section_headers("fr")

    def test_contains_all_required_report_sections(self, engine):
        headers = engine.get_section_headers("ja")
        required_keys = [
            "investigation_overview",
            "executive_summary",
            "ttp_based_findings",
            "per_system_findings",
            "remediation_recommendations",
            "appendix_ioc_list",
            "appendix_attack_mapping",
        ]
        for key in required_keys:
            assert key in headers

    def test_returns_copy_not_reference(self, engine):
        headers1 = engine.get_section_headers("ja")
        headers2 = engine.get_section_headers("ja")
        headers1["investigation_overview"] = "modified"
        assert headers2["investigation_overview"] == "調査概要"


class TestGetReviewSectionHeaders:
    """Tests for get_review_section_headers()."""

    def test_returns_japanese_evidence_review_headers(self, engine):
        headers = engine.get_review_section_headers("ja")
        assert headers["summary"] == "概要"
        assert headers["observed_fact"] == "観測事実"
        assert headers["interpretation"] == "解釈"
        assert headers["confidence"] == "信頼度"
        assert headers["limitations"] == "制約・不足情報"
        assert headers["recommended_expressions"] == "推奨表現"
        assert headers["prohibited_expressions"] == "禁止表現"
        assert headers["source"] == "出典"
        assert headers["decision"] == "判定"

    def test_returns_japanese_gap_review_headers(self, engine):
        headers = engine.get_review_section_headers("ja")
        assert headers["description"] == "説明"
        assert headers["related_claim"] == "関連Claim"
        assert headers["recommended_action"] == "推奨対応"
        assert headers["impact"] == "影響"

    def test_returns_english_review_headers(self, engine):
        headers = engine.get_review_section_headers("en")
        assert headers["summary"] == "Summary"
        assert headers["observed_fact"] == "Observed Fact"

    def test_raises_for_unsupported_language(self, engine):
        with pytest.raises(ValueError):
            engine.get_review_section_headers("de")


class TestGetTableCaptions:
    """Tests for get_table_captions()."""

    def test_returns_japanese_table_captions(self, engine):
        captions = engine.get_table_captions("ja")
        assert "ioc_table" in captions
        assert "attack_mapping_table" in captions
        assert "timeline_table" in captions
        assert captions["ioc_table"] == "表：Indicator of Compromise (IoC) 一覧"

    def test_returns_english_table_captions(self, engine):
        captions = engine.get_table_captions("en")
        assert captions["ioc_table"] == "Table: Indicators of Compromise (IoC)"

    def test_raises_for_unsupported_language(self, engine):
        with pytest.raises(ValueError):
            engine.get_table_captions("zh")


class TestGetBoilerplateTemplates:
    """Tests for get_boilerplate_templates()."""

    def test_returns_japanese_templates(self, engine):
        templates = engine.get_boilerplate_templates("ja")
        assert "confidentiality_notice" in templates
        assert "evidence_citation" in templates
        assert "{evidence_id}" in templates["evidence_citation"]

    def test_returns_english_templates(self, engine):
        templates = engine.get_boilerplate_templates("en")
        assert "confidentiality_notice" in templates
        assert "Evidence ID" in templates["evidence_citation"]

    def test_templates_contain_placeholders(self, engine):
        templates = engine.get_boilerplate_templates("ja")
        assert "{evidence_id}" in templates["evidence_citation"]
        assert "{confidence_level}" in templates["confidence_note"]
        assert "{reason}" in templates["data_unavailable_note"]
        assert "{timestamp}" in templates["report_generated_at"]

    def test_raises_for_unsupported_language(self, engine):
        with pytest.raises(ValueError):
            engine.get_boilerplate_templates("ko")


class TestGetErrorMessages:
    """Tests for get_error_messages()."""

    def test_returns_japanese_error_messages(self, engine):
        messages = engine.get_error_messages("ja")
        assert messages["workflow_blocked"] == "ワークフロー前提条件が未完了です"
        assert messages["missing_evidence"] == "証拠IDが見つかりません"

    def test_returns_english_error_messages(self, engine):
        messages = engine.get_error_messages("en")
        assert messages["workflow_blocked"] == "Workflow prerequisites not completed"

    def test_error_messages_contain_placeholders(self, engine):
        messages = engine.get_error_messages("ja")
        assert "{path}" in messages["file_not_found"]
        assert "{detail}" in messages["parse_error"]
        assert "{language}" in messages["unsupported_language"]
        assert "{timezone}" in messages["timezone_invalid"]

    def test_raises_for_unsupported_language(self, engine):
        with pytest.raises(ValueError):
            engine.get_error_messages("pt")


class TestFormatTimestampForDisplay:
    """Tests for format_timestamp_for_display()."""

    def test_converts_utc_z_suffix_to_jst(self, engine):
        result = engine.format_timestamp_for_display("2024-01-15T10:30:00Z", "Asia/Tokyo")
        assert result == "2024-01-15 19:30:00 JST"

    def test_converts_utc_offset_to_jst(self, engine):
        result = engine.format_timestamp_for_display("2024-01-15T10:30:00+00:00", "Asia/Tokyo")
        assert result == "2024-01-15 19:30:00 JST"

    def test_uses_default_timezone_when_none(self, engine):
        # Default timezone is Asia/Tokyo
        result = engine.format_timestamp_for_display("2024-06-01T00:00:00Z")
        assert "JST" in result or "09:00:00" in result

    def test_converts_to_us_eastern(self, engine):
        result = engine.format_timestamp_for_display(
            "2024-07-15T12:00:00Z", "US/Eastern"
        )
        assert "EDT" in result
        assert "08:00:00" in result

    def test_naive_datetime_treated_as_utc(self, engine):
        # Naive datetime (no timezone info) should be treated as UTC
        result = engine.format_timestamp_for_display("2024-01-15T10:30:00", "Asia/Tokyo")
        assert result == "2024-01-15 19:30:00 JST"

    def test_raises_for_invalid_timezone(self, engine):
        with pytest.raises(ValueError, match="無効なタイムゾーンです"):
            engine.format_timestamp_for_display("2024-01-15T10:30:00Z", "Invalid/Zone")

    def test_raises_for_invalid_timestamp(self, engine):
        with pytest.raises(ValueError, match="パースエラー"):
            engine.format_timestamp_for_display("not-a-timestamp", "Asia/Tokyo")

    def test_handles_non_utc_input(self, engine):
        # Input with +05:30 offset (IST)
        result = engine.format_timestamp_for_display(
            "2024-01-15T16:00:00+05:30", "Asia/Tokyo"
        )
        # 16:00 IST = 10:30 UTC = 19:30 JST
        assert result == "2024-01-15 19:30:00 JST"


class TestFormatIocDefanged:
    """Tests for format_ioc_defanged()."""

    def test_defangs_ipv4_address(self, engine):
        result = engine.format_ioc_defanged("192.168.1.1", "ip")
        assert result == "192[.]168[.]1[.]1"

    def test_defangs_domain(self, engine):
        result = engine.format_ioc_defanged("evil.example.com", "domain")
        assert result == "evil[.]example[.]com"

    def test_defangs_url_http(self, engine):
        result = engine.format_ioc_defanged("http://evil.example.com/payload", "url")
        assert result == "hxxp://evil[.]example[.]com/payload"

    def test_defangs_url_https(self, engine):
        result = engine.format_ioc_defanged("https://c2.bad.org/beacon", "url")
        assert result == "hxxps://c2[.]bad[.]org/beacon"

    def test_defangs_url_no_path(self, engine):
        result = engine.format_ioc_defanged("https://malware.evil.com", "url")
        assert result == "hxxps://malware[.]evil[.]com"

    def test_defangs_email(self, engine):
        result = engine.format_ioc_defanged("attacker@evil.com", "email")
        assert result == "attacker[@]evil[.]com"

    def test_hash_unchanged(self, engine):
        sha256 = "a" * 64
        assert engine.format_ioc_defanged(sha256, "hash_sha256") == sha256

    def test_file_path_unchanged(self, engine):
        path = "C:\\Windows\\System32\\cmd.exe"
        assert engine.format_ioc_defanged(path, "file_path") == path


class TestDefaultLanguageFallback:
    """Test that methods fall back to default language when None is passed."""

    def test_section_headers_default(self, engine):
        headers_default = engine.get_section_headers()
        headers_ja = engine.get_section_headers("ja")
        assert headers_default == headers_ja

    def test_review_headers_default(self, engine):
        headers_default = engine.get_review_section_headers()
        headers_ja = engine.get_review_section_headers("ja")
        assert headers_default == headers_ja

    def test_table_captions_default(self, engine):
        captions_default = engine.get_table_captions()
        captions_ja = engine.get_table_captions("ja")
        assert captions_default == captions_ja

    def test_boilerplate_default(self, engine):
        templates_default = engine.get_boilerplate_templates()
        templates_ja = engine.get_boilerplate_templates("ja")
        assert templates_default == templates_ja

    def test_error_messages_default(self, engine):
        messages_default = engine.get_error_messages()
        messages_ja = engine.get_error_messages("ja")
        assert messages_default == messages_ja

    def test_english_engine_defaults_to_english(self, engine_en):
        headers = engine_en.get_section_headers()
        assert headers["investigation_overview"] == "Investigation Overview"
