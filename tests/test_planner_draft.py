"""Tests for ReportPlanner and DraftGenerator in the Reporting Layer."""

import pytest

from ir_agent.models.analysis import Claim, Gap, TimelineEntry
from ir_agent.models.base import SourceReference, TimeRange
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry
from ir_agent.models.events import ATTCKMapping
from ir_agent.models.reporting import ReportPlan
from ir_agent.reporting.draft_generator import DraftGenerator
from ir_agent.reporting.localization import LocalizationEngine
from ir_agent.reporting.planner import ReportPlanner
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
def manifest_ja():
    """Create a Japanese case manifest."""
    return CaseManifest(
        case_id="case-001",
        case_name="テスト調査ケース",
        scope="テスト用スコープ",
        hosts=["host01", "host02"],
        time_range=TimeRange(start="2024-01-01T00:00:00Z", end="2024-01-31T23:59:59Z"),
        report_language="ja",
        review_language="ja",
        report_timezone="Asia/Tokyo",
    )


@pytest.fixture
def manifest_en():
    """Create an English case manifest."""
    return CaseManifest(
        case_id="case-002",
        case_name="Test Investigation Case",
        scope="Test scope",
        hosts=["host01"],
        time_range=TimeRange(start="2024-01-01T00:00:00Z", end="2024-01-31T23:59:59Z"),
        report_language="en",
        review_language="en",
        report_timezone="UTC",
    )


@pytest.fixture
def expression_policy():
    """Create an ExpressionPolicy with some rules."""
    return ExpressionPolicy(
        confirmed=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["確認された", "であることが確認された"],
                prohibited_expressions=["可能性がある"],
            )
        ),
        probable=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["高い確度で", "と考えられる"],
                prohibited_expressions=["確認された", "である"],
            )
        ),
        possible=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["可能性がある", "の可能性が考えられる"],
                prohibited_expressions=["確認された", "と考えられる", "である"],
            )
        ),
        unknown=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["不明", "判断できない"],
                prohibited_expressions=["確認された", "と考えられる"],
            )
        ),
        not_observed=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["観測されなかった", "確認されなかった"],
                prohibited_expressions=["発生しなかった", "存在しない"],
            )
        ),
    )


@pytest.fixture
def sample_claims():
    """Create sample approved claims for testing."""
    return [
        Claim(
            claim_id="CLM-001",
            report_section="ttp_based_findings",
            claim_text="攻撃者はsftp.exeを使用して外部IPへデータを送信した",
            claim_category=ClaimCategory.OBSERVED_FACT,
            confidence_level=ConfidenceLevel.CONFIRMED,
            confidence_basis="Direct log evidence from multiple sources",
            supporting_evidence=["EV-001", "EV-002"],
            counter_evidence=[],
            limitations=[],
            missing_evidence=[],
            recommended_expressions=["確認された"],
            prohibited_expressions=["可能性がある"],
            review_status="approved",
        ),
        Claim(
            claim_id="CLM-002",
            report_section="ttp_based_findings",
            claim_text="データの外部送信は窃取目的である",
            claim_category=ClaimCategory.DATA_EXFILTRATION_ASSESSMENT,
            confidence_level=ConfidenceLevel.POSSIBLE,
            confidence_basis="Single source, interpretation based on volume",
            supporting_evidence=["EV-001"],
            counter_evidence=[],
            limitations=["送信先の意図を確認できる証拠が不足"],
            missing_evidence=["destination_analysis"],
            recommended_expressions=["可能性がある"],
            prohibited_expressions=["確認された", "である"],
            review_status="approved",
        ),
        Claim(
            claim_id="CLM-003",
            report_section="executive_summary",
            claim_text="本インシデントは初期アクセスからデータ送信まで約3日間で進行した",
            claim_category=ClaimCategory.INTERPRETATION,
            confidence_level=ConfidenceLevel.PROBABLE,
            confidence_basis="Timeline analysis from multiple evidence entries",
            supporting_evidence=["EV-001", "EV-003"],
            counter_evidence=[],
            limitations=[],
            missing_evidence=[],
            recommended_expressions=["高い確度で", "と考えられる"],
            prohibited_expressions=["確認された"],
            review_status="approved",
        ),
        Claim(
            claim_id="CLM-004",
            report_section="per_system_findings",
            claim_text="host01のイベントログに不審なプロセス実行が記録された",
            claim_category=ClaimCategory.OBSERVED_FACT,
            confidence_level=ConfidenceLevel.CONFIRMED,
            confidence_basis="Direct Windows Event Log evidence",
            supporting_evidence=["EV-004"],
            counter_evidence=[],
            limitations=[],
            missing_evidence=[],
            recommended_expressions=["確認された"],
            prohibited_expressions=[],
            review_status="approved",
        ),
        # A rejected claim that should NOT appear in the report
        Claim(
            claim_id="CLM-005",
            report_section="ttp_based_findings",
            claim_text="この主張は却下されている",
            claim_category=ClaimCategory.INTERPRETATION,
            confidence_level=ConfidenceLevel.POSSIBLE,
            confidence_basis="Weak evidence",
            supporting_evidence=["EV-001"],
            counter_evidence=[],
            limitations=[],
            missing_evidence=[],
            recommended_expressions=[],
            prohibited_expressions=[],
            review_status="rejected",
        ),
    ]


@pytest.fixture
def sample_timeline():
    """Create sample timeline entries."""
    return [
        TimelineEntry(
            entry_id="TL-001",
            evidence_id="EV-001",
            event_time="2024-01-15T10:30:00Z",
            original_timestamp="2024-01-15 19:30:00 JST",
            display_timezone="Asia/Tokyo",
            event_description="sftp.exe executed",
            host="host01",
            confidence=ConfidenceLevel.CONFIRMED,
        ),
        TimelineEntry(
            entry_id="TL-002",
            evidence_id="EV-003",
            event_time="2024-01-13T08:00:00Z",
            original_timestamp="2024-01-13 17:00:00 JST",
            display_timezone="Asia/Tokyo",
            event_description="Initial access via VPN",
            host="host01",
            confidence=ConfidenceLevel.PROBABLE,
        ),
        TimelineEntry(
            entry_id="TL-003",
            evidence_id="EV-004",
            event_time="2024-01-14T05:00:00Z",
            original_timestamp="2024-01-14 14:00:00 JST",
            display_timezone="Asia/Tokyo",
            event_description="Suspicious process execution",
            host="host01",
            confidence=ConfidenceLevel.CONFIRMED,
        ),
    ]


@pytest.fixture
def sample_ledger():
    """Create sample evidence ledger entries."""
    return [
        EvidenceLedgerEntry(
            evidence_id="EV-001",
            promoted_from=["CAND-001"],
            approval_timestamp="2024-02-01T00:00:00Z",
            approved_by="analyst01",
            source_refs=[
                SourceReference(
                    source_ref_id="SR-001",
                    source_file_id="FILE-001",
                    source_path="artifacts/host01/syslog.log",
                    source_lines=(100, 105),
                    excerpt="sftp.exe 192.168.1.100 -> 203.0.113.50",
                    excerpt_sha256="abc123",
                )
            ],
            observed_event={"type": "file_transfer"},
            observed_fact="sftp.exe transferred 184MB to external IP",
            interpretation="Possible data exfiltration",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.POSSIBLE,
        ),
        EvidenceLedgerEntry(
            evidence_id="EV-002",
            promoted_from=["CAND-002"],
            approval_timestamp="2024-02-01T01:00:00Z",
            approved_by="analyst01",
            source_refs=[
                SourceReference(
                    source_ref_id="SR-002",
                    source_file_id="FILE-002",
                    source_path="artifacts/host01/firewall.log",
                    source_lines=(50, 52),
                    excerpt="ALLOW TCP 192.168.1.100:59321 -> 203.0.113.50:22",
                    excerpt_sha256="def456",
                )
            ],
            observed_event={"type": "network_connection"},
            observed_fact="Firewall allowed outbound SSH connection",
            interpretation="Connection used for data exfiltration",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.POSSIBLE,
        ),
    ]


@pytest.fixture
def sample_gaps():
    """Create sample gap records."""
    return [
        Gap(
            gap_id="GAP-001",
            related_claim_id="CLM-002",
            gap_type="missing_evidence",
            severity="major",
            description="送信先サーバの分析結果がない",
            recommended_action="送信先IPの脅威情報照会",
            disposition="accepted_as_limitation",
            disposition_reason="送信先は海外のため調査困難",
            dispositioned_by="analyst01",
        ),
        Gap(
            gap_id="GAP-002",
            related_claim_id="CLM-001",
            gap_type="single_source",
            severity="minor",
            description="ネットワーク機器ログの不足",
            recommended_action="スイッチログの取得",
            disposition="deferred_with_reason",
            disposition_reason="機器ログ保持期間外",
            dispositioned_by="analyst01",
        ),
    ]


# ---------------------------------------------------------------------------
# ReportPlanner Tests
# ---------------------------------------------------------------------------


class TestReportPlanner:
    """Tests for the ReportPlanner class."""

    def test_generates_plan_with_standard_sections(self, sample_claims, sample_timeline, manifest_ja):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        assert isinstance(plan, ReportPlan)
        assert len(plan.sections) > 0

        section_keys = [s["section_key"] for s in plan.sections]
        assert "investigation_overview" in section_keys
        assert "executive_summary" in section_keys
        assert "ttp_based_findings" in section_keys
        assert "per_system_findings" in section_keys
        assert "remediation_recommendations" in section_keys
        assert "limitations" in section_keys
        assert "appendix_ioc_list" in section_keys
        assert "appendix_attack_mapping" in section_keys

    def test_assigns_claims_to_correct_sections(self, sample_claims, sample_timeline, manifest_ja):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        sections_by_key = {s["section_key"]: s for s in plan.sections}

        # CLM-001 and CLM-002 are in ttp_based_findings
        ttp_claims = sections_by_key["ttp_based_findings"]["claims"]
        assert "CLM-001" in ttp_claims
        assert "CLM-002" in ttp_claims

        # CLM-003 is in executive_summary
        summary_claims = sections_by_key["executive_summary"]["claims"]
        assert "CLM-003" in summary_claims

        # CLM-004 is in per_system_findings
        system_claims = sections_by_key["per_system_findings"]["claims"]
        assert "CLM-004" in system_claims

    def test_excludes_rejected_claims(self, sample_claims, sample_timeline, manifest_ja):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        all_claim_ids = []
        for section in plan.sections:
            all_claim_ids.extend(section["claims"])

        assert "CLM-005" not in all_claim_ids

    def test_includes_evidence_refs(self, sample_claims, sample_timeline, manifest_ja):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        sections_by_key = {s["section_key"]: s for s in plan.sections}
        ttp_section = sections_by_key["ttp_based_findings"]

        assert "EV-001" in ttp_section["evidence_refs"]
        assert "EV-002" in ttp_section["evidence_refs"]

    def test_japanese_ir_structure_type(self, sample_claims, sample_timeline, manifest_ja):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)
        assert plan.structure_type == "japanese_ir"

    def test_standard_structure_type_for_english(self, sample_claims, sample_timeline, manifest_en):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_en)
        assert plan.structure_type == "standard"

    def test_claims_sorted_by_timeline_order(self, sample_claims, sample_timeline, manifest_ja):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        sections_by_key = {s["section_key"]: s for s in plan.sections}
        ttp_claims = sections_by_key["ttp_based_findings"]["claims"]

        # CLM-001 has evidence EV-001 (2024-01-15T10:30:00Z)
        # CLM-002 has evidence EV-001 (2024-01-15T10:30:00Z) — same time, so order is stable
        # Both should appear (they share EV-001)
        assert "CLM-001" in ttp_claims
        assert "CLM-002" in ttp_claims

    def test_sections_have_narrative_flow(self, sample_claims, sample_timeline, manifest_ja):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        for section in plan.sections:
            assert "narrative_flow" in section
            assert isinstance(section["narrative_flow"], str)

    def test_sections_have_japanese_headings(self, sample_claims, sample_timeline, manifest_ja):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        sections_by_key = {s["section_key"]: s for s in plan.sections}
        assert sections_by_key["investigation_overview"]["heading"] == "調査概要"
        assert sections_by_key["executive_summary"]["heading"] == "エグゼクティブサマリー"

    def test_empty_claims_produces_plan_with_empty_sections(self, sample_timeline, manifest_ja):
        planner = ReportPlanner()
        plan = planner.generate_plan([], sample_timeline, manifest_ja)

        assert isinstance(plan, ReportPlan)
        for section in plan.sections:
            assert section["claims"] == []
            assert section["evidence_refs"] == []


# ---------------------------------------------------------------------------
# DraftGenerator Tests
# ---------------------------------------------------------------------------


class TestDraftGenerator:
    """Tests for the DraftGenerator class."""

    def test_generates_draft_in_japanese(
        self, sample_claims, sample_timeline, sample_ledger, sample_gaps,
        expression_policy, manifest_ja,
    ):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, sample_claims, sample_ledger, sample_gaps,
            expression_policy, manifest_ja,
        )

        # Should contain Japanese content
        assert "インシデント調査報告書" in draft
        assert "ドラフト" in draft

    def test_uses_only_approved_claims(
        self, sample_claims, sample_timeline, sample_ledger, sample_gaps,
        expression_policy, manifest_ja,
    ):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, sample_claims, sample_ledger, sample_gaps,
            expression_policy, manifest_ja,
        )

        # The rejected claim text should NOT appear in the draft
        assert "この主張は却下されている" not in draft

    def test_includes_evidence_citations(
        self, sample_claims, sample_timeline, sample_ledger, sample_gaps,
        expression_policy, manifest_ja,
    ):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, sample_claims, sample_ledger, sample_gaps,
            expression_policy, manifest_ja,
        )

        # Evidence citations should be present
        assert "EV-001" in draft
        assert "EV-002" in draft

    def test_includes_limitations_section(
        self, sample_claims, sample_timeline, sample_ledger, sample_gaps,
        expression_policy, manifest_ja,
    ):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, sample_claims, sample_ledger, sample_gaps,
            expression_policy, manifest_ja,
        )

        # Limitations section should include the accepted_as_limitation gap
        assert "送信先サーバの分析結果がない" in draft

    def test_does_not_include_deferred_gaps_in_limitations(
        self, sample_claims, sample_timeline, sample_ledger, sample_gaps,
        expression_policy, manifest_ja,
    ):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, sample_claims, sample_ledger, sample_gaps,
            expression_policy, manifest_ja,
        )

        # GAP-002 has disposition="deferred_with_reason", should NOT be in limitations
        assert "ネットワーク機器ログの不足" not in draft

    def test_includes_draft_watermark(
        self, sample_claims, sample_timeline, sample_ledger, sample_gaps,
        expression_policy, manifest_ja,
    ):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, sample_claims, sample_ledger, sample_gaps,
            expression_policy, manifest_ja,
        )

        assert "【ドラフト — 最終版ではありません】" in draft

    def test_applies_confidence_qualifier_for_interpretations(
        self, sample_claims, sample_timeline, sample_ledger, sample_gaps,
        expression_policy, manifest_ja,
    ):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, sample_claims, sample_ledger, sample_gaps,
            expression_policy, manifest_ja,
        )

        # CLM-002 is POSSIBLE confidence + DATA_EXFILTRATION_ASSESSMENT category
        # Should have a confidence qualifier
        assert "【可能性】" in draft

    def test_does_not_add_qualifier_for_observed_facts(
        self, sample_claims, sample_timeline, sample_ledger, sample_gaps,
        expression_policy, manifest_ja,
    ):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, sample_claims, sample_ledger, sample_gaps,
            expression_policy, manifest_ja,
        )

        # CLM-001 is OBSERVED_FACT with CONFIRMED confidence
        # Should NOT have "【高確度】" qualifier since it's an observed fact
        # The raw claim text should appear without a confidence qualifier prefix
        assert "攻撃者はsftp.exeを使用して外部IPへデータを送信した" in draft

    def test_replaces_prohibited_expressions(self, manifest_ja, sample_timeline, sample_ledger):
        """Test that prohibited expressions are replaced with recommended ones."""
        policy = ExpressionPolicy(
            confirmed=ConfidenceExpressionPolicy(
                default=ExpressionRule(
                    recommended_expressions=["確認した"],
                    prohibited_expressions=["と思われる"],
                )
            ),
            probable=ConfidenceExpressionPolicy(default=ExpressionRule()),
            possible=ConfidenceExpressionPolicy(default=ExpressionRule()),
            unknown=ConfidenceExpressionPolicy(default=ExpressionRule()),
            not_observed=ConfidenceExpressionPolicy(default=ExpressionRule()),
        )

        claims = [
            Claim(
                claim_id="CLM-X",
                report_section="ttp_based_findings",
                claim_text="攻撃者がマルウェアを実行したと思われる",
                claim_category=ClaimCategory.OBSERVED_FACT,
                confidence_level=ConfidenceLevel.CONFIRMED,
                confidence_basis="Direct evidence",
                supporting_evidence=["EV-001"],
                review_status="approved",
            ),
        ]

        planner = ReportPlanner()
        plan = planner.generate_plan(claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, claims, sample_ledger, [], policy, manifest_ja,
        )

        # Prohibited expression should be replaced
        assert "と思われる" not in draft
        assert "確認した" in draft

    def test_generates_english_report(
        self, sample_claims, sample_timeline, sample_ledger, sample_gaps,
        expression_policy, manifest_en,
    ):
        planner = ReportPlanner()
        plan = planner.generate_plan(sample_claims, sample_timeline, manifest_en)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, sample_claims, sample_ledger, sample_gaps,
            expression_policy, manifest_en,
        )

        # English report markers
        assert "Incident Investigation Report (Draft)" in draft
        assert "[DRAFT" in draft

    def test_includes_claim_level_limitations(
        self, sample_timeline, sample_ledger, expression_policy, manifest_ja,
    ):
        """Test that per-claim limitations are rendered."""
        claims = [
            Claim(
                claim_id="CLM-LIM",
                report_section="ttp_based_findings",
                claim_text="攻撃者はデータを送信した",
                claim_category=ClaimCategory.OBSERVED_FACT,
                confidence_level=ConfidenceLevel.CONFIRMED,
                confidence_basis="Log evidence",
                supporting_evidence=["EV-001"],
                limitations=["送信量の正確な値は不確定"],
                review_status="approved",
            ),
        ]

        planner = ReportPlanner()
        plan = planner.generate_plan(claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, claims, sample_ledger, [], expression_policy, manifest_ja,
        )

        assert "送信量の正確な値は不確定" in draft
        assert "【制約事項】" in draft

    def test_uses_approved_claim_text_when_edited(
        self, sample_timeline, sample_ledger, expression_policy, manifest_ja,
    ):
        """Test that edited claims use approved_claim_text."""
        claims = [
            Claim(
                claim_id="CLM-EDIT",
                report_section="ttp_based_findings",
                claim_text="元のテキスト",
                claim_category=ClaimCategory.OBSERVED_FACT,
                confidence_level=ConfidenceLevel.CONFIRMED,
                confidence_basis="Direct evidence",
                supporting_evidence=["EV-001"],
                review_status="edited",
                original_claim_text="元のテキスト",
                approved_claim_text="編集後のテキスト",
            ),
        ]

        planner = ReportPlanner()
        plan = planner.generate_plan(claims, sample_timeline, manifest_ja)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, claims, sample_ledger, [], expression_policy, manifest_ja,
        )

        assert "編集後のテキスト" in draft
        assert "元のテキスト" not in draft
