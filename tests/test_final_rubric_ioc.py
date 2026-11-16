"""Unit tests for FinalReportGenerator, RubricChecker, and IOCFormatter.

Tests task 15.4 implementation:
- FinalReportGenerator: finalize_report from approved draft
- RubricChecker: check_rubric and has_critical_failures
- IOCFormatter: defang_value and format_ioc_appendix

Requirements: 17.1, 17.3, 17.4, 17.5, 25.4, 25.5, 28.1, 28.2, 28.3, 28.4
"""

from pathlib import Path

import pytest

from ir_agent.governance.audit import AuditLogger
from ir_agent.models.base import TimeRange
from ir_agent.models.evidence import IOCRecord
from ir_agent.reporting.final_generator import FinalReportGenerator
from ir_agent.reporting.ioc_formatter import IOCFormatter
from ir_agent.reporting.rubric_checker import DEFAULT_RUBRIC_ITEMS, RubricChecker
from ir_agent.steering.manifest import (
    CaseManifest,
    ConfidenceExpressionPolicy,
    ExpressionPolicy,
    ExpressionRule,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_manifest() -> CaseManifest:
    """Create a sample CaseManifest for testing."""
    policy = ExpressionPolicy(
        confirmed=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["確認しました"],
                prohibited_expressions=[],
            )
        ),
        probable=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["高確度"],
                prohibited_expressions=[],
            )
        ),
        possible=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["可能性があります"],
                prohibited_expressions=[],
            )
        ),
        unknown=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["不明"],
                prohibited_expressions=[],
            )
        ),
        not_observed=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["観測されず"],
                prohibited_expressions=[],
            )
        ),
    )
    return CaseManifest(
        case_id="TEST-001",
        case_name="テストケース",
        scope="テスト範囲",
        hosts=["host01"],
        time_range=TimeRange(start="2024-01-01T00:00:00Z", end="2024-01-31T23:59:59Z"),
        expression_policy=policy,
    )


@pytest.fixture
def sample_draft_content() -> str:
    """Create a sample draft report content."""
    return (
        "【ドラフト — 最終版ではありません】\n"
        "\n"
        "# テストケース — インシデント調査報告書（ドラフト）\n"
        "\n"
        "レポート生成日時: 2024-01-20 10:00:00 JST\n"
        "\n"
        "## 調査概要\n"
        "\n"
        "調査の概要テキスト。\n"
        "\n"
        "## エグゼクティブサマリー\n"
        "\n"
        "サマリーテキスト。 （証拠ID: EV-001）\n"
        "\n"
        "## 制約事項\n"
        "\n"
        "【制約事項】 一部のログが利用不可。\n"
    )


@pytest.fixture
def audit_logger(tmp_path: Path) -> AuditLogger:
    """Create an AuditLogger for testing."""
    return AuditLogger(case_dir=tmp_path)


# ---------------------------------------------------------------------------
# FinalReportGenerator Tests
# ---------------------------------------------------------------------------


class TestFinalReportGenerator:
    """Tests for FinalReportGenerator.finalize_report()."""

    def test_finalize_removes_draft_watermark(
        self, tmp_path: Path, sample_draft_content: str, audit_logger: AuditLogger
    ):
        """Final report does not contain the draft watermark."""
        draft_path = tmp_path / "reports" / "draft_report.md"
        draft_path.parent.mkdir(parents=True, exist_ok=True)
        draft_path.write_text(sample_draft_content, encoding="utf-8")

        generator = FinalReportGenerator()
        output = generator.finalize_report(draft_path, audit_logger, "analyst01")

        final_content = output.read_text(encoding="utf-8")
        assert "【ドラフト — 最終版ではありません】" not in final_content
        assert "[DRAFT — Not a final version]" not in final_content

    def test_finalize_adds_confidentiality_notice(
        self, tmp_path: Path, sample_draft_content: str, audit_logger: AuditLogger
    ):
        """Final report contains confidentiality notice."""
        draft_path = tmp_path / "reports" / "draft_report.md"
        draft_path.parent.mkdir(parents=True, exist_ok=True)
        draft_path.write_text(sample_draft_content, encoding="utf-8")

        generator = FinalReportGenerator()
        output = generator.finalize_report(draft_path, audit_logger, "analyst01")

        final_content = output.read_text(encoding="utf-8")
        assert "機密情報" in final_content

    def test_finalize_updates_title_to_final(
        self, tmp_path: Path, sample_draft_content: str, audit_logger: AuditLogger
    ):
        """Final report title says 最終版 instead of ドラフト."""
        draft_path = tmp_path / "reports" / "draft_report.md"
        draft_path.parent.mkdir(parents=True, exist_ok=True)
        draft_path.write_text(sample_draft_content, encoding="utf-8")

        generator = FinalReportGenerator()
        output = generator.finalize_report(draft_path, audit_logger, "analyst01")

        final_content = output.read_text(encoding="utf-8")
        assert "（最終版）" in final_content
        assert "（ドラフト）" not in final_content

    def test_finalize_records_approval_in_audit_log(
        self, tmp_path: Path, sample_draft_content: str, audit_logger: AuditLogger
    ):
        """Finalization records approval in the audit log."""
        draft_path = tmp_path / "reports" / "draft_report.md"
        draft_path.parent.mkdir(parents=True, exist_ok=True)
        draft_path.write_text(sample_draft_content, encoding="utf-8")

        generator = FinalReportGenerator()
        generator.finalize_report(draft_path, audit_logger, "analyst01")

        # Check that audit log has an entry
        audit_path = tmp_path / "logs" / "audit.jsonl"
        assert audit_path.exists()
        content = audit_path.read_text(encoding="utf-8")
        assert "final_report" in content
        assert "analyst01" in content

    def test_finalize_produces_final_report_md(
        self, tmp_path: Path, sample_draft_content: str, audit_logger: AuditLogger
    ):
        """Finalization outputs final_report.md in the same directory."""
        draft_path = tmp_path / "reports" / "draft_report.md"
        draft_path.parent.mkdir(parents=True, exist_ok=True)
        draft_path.write_text(sample_draft_content, encoding="utf-8")

        generator = FinalReportGenerator()
        output = generator.finalize_report(draft_path, audit_logger, "analyst01")

        assert output.name == "final_report.md"
        assert output.parent == draft_path.parent
        assert output.exists()

    def test_finalize_preserves_draft_content(
        self, tmp_path: Path, sample_draft_content: str, audit_logger: AuditLogger
    ):
        """Final report preserves the substantive content from the draft."""
        draft_path = tmp_path / "reports" / "draft_report.md"
        draft_path.parent.mkdir(parents=True, exist_ok=True)
        draft_path.write_text(sample_draft_content, encoding="utf-8")

        generator = FinalReportGenerator()
        output = generator.finalize_report(draft_path, audit_logger, "analyst01")

        final_content = output.read_text(encoding="utf-8")
        # Key content from the draft should remain
        assert "調査の概要テキスト" in final_content
        assert "サマリーテキスト" in final_content
        assert "EV-001" in final_content

    def test_finalize_raises_on_missing_draft(
        self, tmp_path: Path, audit_logger: AuditLogger
    ):
        """Raises FileNotFoundError when draft path does not exist."""
        draft_path = tmp_path / "reports" / "nonexistent.md"

        generator = FinalReportGenerator()
        with pytest.raises(FileNotFoundError):
            generator.finalize_report(draft_path, audit_logger, "analyst01")

    def test_finalize_english_draft(
        self, tmp_path: Path, audit_logger: AuditLogger
    ):
        """Finalization works for English drafts."""
        draft_content = (
            "[DRAFT — Not a final version]\n"
            "\n"
            "# Test Case — Incident Investigation Report (Draft)\n"
            "\n"
            "## Executive Summary\n"
            "\n"
            "Summary text. (Evidence ID: EV-001)\n"
        )
        draft_path = tmp_path / "reports" / "draft_report.md"
        draft_path.parent.mkdir(parents=True, exist_ok=True)
        draft_path.write_text(draft_content, encoding="utf-8")

        generator = FinalReportGenerator(report_language="en")
        output = generator.finalize_report(draft_path, audit_logger, "analyst01")

        final_content = output.read_text(encoding="utf-8")
        assert "[DRAFT — Not a final version]" not in final_content
        assert "Incident Investigation Report (Final)" in final_content
        assert "confidential" in final_content.lower()


# ---------------------------------------------------------------------------
# RubricChecker Tests
# ---------------------------------------------------------------------------


class TestRubricChecker:
    """Tests for RubricChecker.check_rubric() and has_critical_failures()."""

    def test_all_sections_present_passes(self, sample_manifest: CaseManifest):
        """Report with all required sections passes rubric."""
        report = (
            "# Report\n"
            "## 調査目的・範囲\nPurpose.\n"
            "## 調査対象・提供データ\nData.\n"
            "## 調査期間\n2024-01.\n"
            "## 制約事項\nSome limitation content.\n"
            "## エグゼクティブサマリー\nSummary.\n"
            "## タイムライン\nTimeline.\n"
            "## TTP調査結果\nFindings.\n"
            "## システム別詳細\nPer-system.\n"
            "(Evidence ID: EV-001)\n"
            "【可能性】 something\n"
            "## 封じ込め・復旧\nContainment.\n"
            "## 改善・再発防止策\nRemediation.\n"
            "## IoC一覧\nIOC table.\n"
            "## ATT&CKマッピング\nMapping.\n"
        )

        checker = RubricChecker()
        results = checker.check_rubric(report, None, sample_manifest)

        assert not checker.has_critical_failures(results)
        assert len(results["critical_failures"]) == 0

    def test_missing_critical_section_fails(self, sample_manifest: CaseManifest):
        """Report missing a critical section has critical failures."""
        # Report missing investigation purpose/scope
        report = (
            "# Report\n"
            "## エグゼクティブサマリー\nSummary.\n"
            "(Evidence ID: EV-001)\n"
            "## 制約事項\nLimitation.\n"
            "## 調査期間\n2024.\n"
            "## 調査対象\nData.\n"
            "## TTP調査結果\nFindings.\n"
        )

        checker = RubricChecker()
        results = checker.check_rubric(report, None, sample_manifest)

        # Should have at least one critical failure (missing purpose/scope keywords)
        assert len(results["failed_items"]) > 0

    def test_no_evidence_citations_fails(self, sample_manifest: CaseManifest):
        """Report without evidence citations triggers rubric failure."""
        report = (
            "# Report\n"
            "## 調査目的・範囲\nPurpose.\n"
            "## 調査対象\nData.\n"
            "## 調査期間\n2024.\n"
            "## 制約事項\nLimitation content here.\n"
            "## エグゼクティブサマリー\nSummary.\n"
            "## TTP調査結果\nFindings without citations.\n"
        )

        checker = RubricChecker()
        results = checker.check_rubric(report, None, sample_manifest)

        # R09 (evidence citations) should fail
        failed_ids = results["failed_items"]
        assert "R09" in failed_ids

    def test_has_critical_failures_true(self, sample_manifest: CaseManifest):
        """has_critical_failures returns True when critical items fail."""
        results = {"critical_failures": ["R01", "R05"]}
        checker = RubricChecker()
        assert checker.has_critical_failures(results) is True

    def test_has_critical_failures_false(self, sample_manifest: CaseManifest):
        """has_critical_failures returns False when no critical failures."""
        results = {"critical_failures": []}
        checker = RubricChecker()
        assert checker.has_critical_failures(results) is False

    def test_custom_rubric_items(self, sample_manifest: CaseManifest):
        """Custom rubric items from manifest are used when provided."""
        custom_rubric = {
            "items": [
                {
                    "id": "CUSTOM-01",
                    "description": "Custom check",
                    "check_type": "section_present",
                    "section_keywords": ["unicorn"],
                    "severity": "critical",
                }
            ]
        }
        report = "# Report\nNo special content here.\n"

        checker = RubricChecker()
        results = checker.check_rubric(report, custom_rubric, sample_manifest)

        assert "CUSTOM-01" in results["critical_failures"]

    def test_default_rubric_items_count(self):
        """Default rubric has the expected number of items."""
        assert len(DEFAULT_RUBRIC_ITEMS) == 14

    def test_audit_log_valid_defaults_true(self, sample_manifest: CaseManifest):
        """Results include audit_log_valid defaulting to True."""
        checker = RubricChecker()
        results = checker.check_rubric("# Empty report", None, sample_manifest)
        assert results["audit_log_valid"] is True


# ---------------------------------------------------------------------------
# IOCFormatter Tests
# ---------------------------------------------------------------------------


class TestIOCFormatter:
    """Tests for IOCFormatter.defang_value() and format_ioc_appendix()."""

    def test_defang_ip(self):
        """IP addresses are defanged with [.] notation."""
        formatter = IOCFormatter()
        assert formatter.defang_value("192.168.1.1", "ip") == "192[.]168[.]1[.]1"

    def test_defang_domain(self):
        """Domain names are defanged with [.] notation."""
        formatter = IOCFormatter()
        assert formatter.defang_value("evil.example.com", "domain") == "evil[.]example[.]com"

    def test_defang_url(self):
        """URLs are defanged with hxxp and [.] in host."""
        formatter = IOCFormatter()
        result = formatter.defang_value("https://evil.com/path", "url")
        assert "hxxps" in result
        assert "[.]" in result
        assert "/path" in result

    def test_defang_email(self):
        """Email addresses are defanged with [.] and [@]."""
        formatter = IOCFormatter()
        result = formatter.defang_value("bad@evil.com", "email")
        assert "[@]" in result
        assert "[.]" in result

    def test_defang_hash_unchanged(self):
        """Hash values are not defanged."""
        formatter = IOCFormatter()
        hash_val = "d41d8cd98f00b204e9800998ecf8427e"
        assert formatter.defang_value(hash_val, "hash_md5") == hash_val

    def test_defang_file_path_unchanged(self):
        """File paths are not defanged."""
        formatter = IOCFormatter()
        path = "C:\\Windows\\System32\\cmd.exe"
        assert formatter.defang_value(path, "file_path") == path

    def test_format_ioc_appendix_japanese(self):
        """IOC appendix table is formatted in Japanese."""
        formatter = IOCFormatter(language="ja")
        iocs = [
            IOCRecord(ioc_id="ioc-1", ioc_type="ip", value="10.0.0.1", source_file_id="f1", source_line=5),
            IOCRecord(ioc_id="ioc-2", ioc_type="domain", value="bad.org", source_file_id="f2", source_line=12),
        ]

        table = formatter.format_ioc_appendix(iocs)
        assert "種別" in table
        assert "値" in table
        assert "概要/役割" in table
        assert "確認箇所" in table
        assert "10[.]0[.]0[.]1" in table
        assert "bad[.]org" in table

    def test_format_ioc_appendix_english(self):
        """IOC appendix table is formatted in English."""
        formatter = IOCFormatter(language="en")
        iocs = [
            IOCRecord(ioc_id="ioc-1", ioc_type="ip", value="10.0.0.1", source_file_id="f1", source_line=5),
        ]

        table = formatter.format_ioc_appendix(iocs, language="en")
        assert "Type" in table
        assert "Value" in table
        assert "Summary / Role" in table
        assert "Location" in table
        assert "10[.]0[.]0[.]1" in table

    def test_format_ioc_appendix_no_defang(self):
        """IOC appendix without defanging preserves raw values."""
        formatter = IOCFormatter()
        iocs = [
            IOCRecord(ioc_id="ioc-1", ioc_type="ip", value="10.0.0.1", source_file_id="f1", source_line=5),
        ]

        table = formatter.format_ioc_appendix(iocs, defang=False)
        assert "10.0.0.1" in table
        assert "[.]" not in table

    def test_format_ioc_appendix_empty_list(self):
        """Empty IOC list produces a table with placeholder row."""
        formatter = IOCFormatter()
        table = formatter.format_ioc_appendix([])
        assert "—" in table

    def test_format_ioc_appendix_source_reference(self):
        """IOC table includes source file and line reference."""
        formatter = IOCFormatter()
        iocs = [
            IOCRecord(ioc_id="ioc-1", ioc_type="ip", value="1.2.3.4", source_file_id="file-abc", source_line=42),
        ]

        table = formatter.format_ioc_appendix(iocs)
        assert "file-abc" in table
        assert "L42" in table

    def test_format_ioc_type_labels_japanese(self):
        """IOC type labels are properly localized in Japanese."""
        formatter = IOCFormatter(language="ja")
        iocs = [
            IOCRecord(ioc_id="ioc-1", ioc_type="ip", value="1.1.1.1", source_file_id="f1", source_line=1),
            IOCRecord(ioc_id="ioc-2", ioc_type="domain", value="a.com", source_file_id="f1", source_line=2),
            IOCRecord(ioc_id="ioc-3", ioc_type="hash_sha256", value="abc123", source_file_id="f1", source_line=3),
        ]

        table = formatter.format_ioc_appendix(iocs)
        assert "IPアドレス" in table
        assert "ドメイン" in table
        assert "SHA-256ハッシュ" in table
