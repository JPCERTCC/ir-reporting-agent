"""Consolidated integration tests for the Reporting Layer.

Tests specific interactions and requirements for:
- DraftGenerator: excludes rejected/pending claims; generates Japanese directly
- FinalReportGenerator: produces from approved draft only (no re-generation)
- RubricChecker: identifies critical failures correctly
- ReportGenerationGuard: blocks correctly on each condition

Requirements: 16.2, 16.8, 17.3, 28.4
"""

import pytest

from ir_agent.models.analysis import Claim, Gap
from ir_agent.models.base import SourceReference, TimeRange
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel, WorkflowPhase
from ir_agent.models.evidence import EvidenceLedgerEntry
from ir_agent.models.reporting import ReportPlan
from ir_agent.reporting.draft_generator import DraftGenerator
from ir_agent.reporting.final_generator import FinalReportGenerator
from ir_agent.reporting.guard import ReportGenerationGuard
from ir_agent.reporting.planner import ReportPlanner
from ir_agent.reporting.rubric_checker import RubricChecker
from ir_agent.steering.manifest import (
    CaseManifest,
    ConfidenceExpressionPolicy,
    ExpressionPolicy,
    ExpressionRule,
)
from ir_agent.workflow.state import WorkflowState

# ---------------------------------------------------------------------------
# Shared Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ja_manifest():
    """Japanese case manifest for testing."""
    return CaseManifest(
        case_id="CASE-INT-001",
        case_name="統合テストケース",
        scope="テスト範囲",
        hosts=["srv01", "srv02"],
        time_range=TimeRange(start="2024-03-01T00:00:00Z", end="2024-03-15T23:59:59Z"),
        report_language="ja",
        review_language="ja",
        report_timezone="Asia/Tokyo",
    )


@pytest.fixture
def expression_policy():
    """Expression policy with Japanese expressions."""
    return ExpressionPolicy(
        confirmed=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["確認された", "であることが判明した"],
                prohibited_expressions=["可能性がある", "と推測される"],
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
                recommended_expressions=["可能性がある", "の疑いがある"],
                prohibited_expressions=["確認された", "と考えられる", "である"],
            )
        ),
        unknown=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["不明である", "判断不能"],
                prohibited_expressions=["確認された"],
            )
        ),
        not_observed=ConfidenceExpressionPolicy(
            default=ExpressionRule(
                recommended_expressions=["観測されなかった"],
                prohibited_expressions=["存在しない", "発生しなかった"],
            )
        ),
    )


@pytest.fixture
def ledger_entries():
    """Sample evidence ledger entries."""
    return [
        EvidenceLedgerEntry(
            evidence_id="EV-100",
            promoted_from=["CAND-100"],
            approval_timestamp="2024-03-05T10:00:00Z",
            approved_by="analyst_a",
            source_refs=[
                SourceReference(
                    source_ref_id="SR-100",
                    source_file_id="FILE-A",
                    source_path="artifacts/srv01/auth.log",
                    source_lines=(200, 210),
                    excerpt="Failed login attempts from 10.0.0.5",
                    excerpt_sha256="hash100",
                )
            ],
            observed_event={"type": "authentication_failure"},
            observed_fact="srv01で10.0.0.5からの認証失敗が20回記録された",
            interpretation="ブルートフォース攻撃の可能性",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.POSSIBLE,
        ),
        EvidenceLedgerEntry(
            evidence_id="EV-101",
            promoted_from=["CAND-101"],
            approval_timestamp="2024-03-05T11:00:00Z",
            approved_by="analyst_a",
            source_refs=[
                SourceReference(
                    source_ref_id="SR-101",
                    source_file_id="FILE-B",
                    source_path="artifacts/srv01/syslog.log",
                    source_lines=(500, 505),
                    excerpt="Process cmd.exe spawned by svchost.exe",
                    excerpt_sha256="hash101",
                )
            ],
            observed_event={"type": "process_execution"},
            observed_fact="svchost.exeからcmd.exeが起動された",
            interpretation="正規プロセスによる不審な子プロセス生成",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.PROBABLE,
        ),
    ]


def _build_claim(
    claim_id: str,
    review_status: str = "approved",
    category: ClaimCategory = ClaimCategory.OBSERVED_FACT,
    confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
    claim_text: str = "テスト主張",
    supporting_evidence: list[str] | None = None,
) -> Claim:
    """Helper to construct a Claim with defaults."""
    return Claim(
        claim_id=claim_id,
        report_section="ttp_based_findings",
        claim_text=claim_text,
        claim_category=category,
        confidence_level=confidence,
        confidence_basis="Test basis",
        supporting_evidence=supporting_evidence or ["EV-100"],
        counter_evidence=[],
        limitations=[],
        missing_evidence=[],
        recommended_expressions=[],
        prohibited_expressions=[],
        review_status=review_status,
    )


def _section_between(markdown: str, start_heading: str, next_heading: str) -> str:
    start = markdown.index(start_heading)
    end = markdown.index(next_heading, start + len(start_heading))
    return markdown[start:end]


# ---------------------------------------------------------------------------
# DraftGenerator: excludes rejected/pending claims (Req 16.2)
# ---------------------------------------------------------------------------


class TestDraftGeneratorClaimFiltering:
    """DraftGenerator uses ONLY approved claims — rejected and pending excluded."""

    def test_pending_claims_excluded_from_draft(
        self, ja_manifest, expression_policy, ledger_entries
    ):
        """Pending claims must not appear in the generated draft.

        Validates: Requirements 16.2
        """
        approved_claim = _build_claim(
            "CLM-A1",
            review_status="approved",
            claim_text="承認済みの主張テキスト",
        )
        pending_claim = _build_claim(
            "CLM-P1",
            review_status="pending",
            claim_text="保留中の主張テキスト（表示禁止）",
        )

        all_claims = [approved_claim, pending_claim]

        planner = ReportPlanner()
        plan = planner.generate_plan(all_claims, [], ja_manifest)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, all_claims, ledger_entries, [], expression_policy, ja_manifest
        )

        # Approved claim text should appear
        assert "承認済みの主張テキスト" in draft
        # Pending claim text must NOT appear
        assert "保留中の主張テキスト（表示禁止）" not in draft

    def test_rejected_claims_excluded_from_draft(
        self, ja_manifest, expression_policy, ledger_entries
    ):
        """Rejected claims must not appear in the generated draft.

        Validates: Requirements 16.2
        """
        approved_claim = _build_claim(
            "CLM-A2",
            review_status="approved",
            claim_text="採用された主張",
        )
        rejected_claim = _build_claim(
            "CLM-R1",
            review_status="rejected",
            claim_text="却下された主張（表示禁止）",
        )

        all_claims = [approved_claim, rejected_claim]

        planner = ReportPlanner()
        plan = planner.generate_plan(all_claims, [], ja_manifest)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, all_claims, ledger_entries, [], expression_policy, ja_manifest
        )

        assert "採用された主張" in draft
        assert "却下された主張（表示禁止）" not in draft


class TestDraftGeneratorDirectJapanese:
    """DraftGenerator generates Japanese text directly — no English artifacts."""

    def test_no_english_section_headers_in_japanese_draft(
        self, ja_manifest, expression_policy, ledger_entries
    ):
        """Japanese draft should NOT contain English section headers.

        Validates: Requirements 16.8
        """
        claims = [
            _build_claim("CLM-J1", claim_text="テスト主張文"),
        ]

        planner = ReportPlanner()
        plan = planner.generate_plan(claims, [], ja_manifest)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, claims, ledger_entries, [], expression_policy, ja_manifest
        )

        # Should NOT contain English section headers
        english_headers = [
            "## Executive Summary",
            "## Findings",
            "## Recommendations",
            "## Limitations",
            "## Investigation Overview",
        ]
        for header in english_headers:
            assert header not in draft, f"English header '{header}' found in Japanese draft"

    def test_japanese_draft_uses_japanese_headers(
        self, ja_manifest, expression_policy, ledger_entries
    ):
        """Japanese draft uses localized section headings.

        Validates: Requirements 16.8
        """
        claims = [
            _build_claim("CLM-J2", claim_text="調査結果テスト"),
        ]

        planner = ReportPlanner()
        plan = planner.generate_plan(claims, [], ja_manifest)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, claims, ledger_entries, [], expression_policy, ja_manifest
        )

        # Should contain Japanese section headers
        assert "## 調査概要" in draft or "調査概要" in draft
        assert "エグゼクティブサマリー" in draft

    def test_japanese_draft_watermark_is_japanese(
        self, ja_manifest, expression_policy, ledger_entries
    ):
        """Draft watermark is in Japanese for ja reports — not English.

        Validates: Requirements 16.8
        """
        claims = [_build_claim("CLM-J3", claim_text="テスト")]

        planner = ReportPlanner()
        plan = planner.generate_plan(claims, [], ja_manifest)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, claims, ledger_entries, [], expression_policy, ja_manifest
        )

        assert "【ドラフト — 最終版ではありません】" in draft
        assert "[DRAFT — Not a final version]" not in draft

    def test_japanese_draft_title_is_japanese(self, ja_manifest, expression_policy, ledger_entries):
        """Report title is rendered in Japanese, not English.

        Validates: Requirements 16.8
        """
        claims = [_build_claim("CLM-J4", claim_text="テスト")]

        planner = ReportPlanner()
        plan = planner.generate_plan(claims, [], ja_manifest)

        generator = DraftGenerator()
        draft = generator.generate_draft(
            plan, claims, ledger_entries, [], expression_policy, ja_manifest
        )

        assert "インシデント調査報告書" in draft
        assert "Incident Investigation Report" not in draft


# ---------------------------------------------------------------------------
# FinalReportGenerator: produces from approved draft only (Req 17.3)
# ---------------------------------------------------------------------------


class TestFinalReportGeneratorNoRegeneration:
    """FinalReportGenerator uses draft as-is — no content re-generation."""

    def test_final_report_preserves_all_claims_from_draft(self, tmp_path):
        """Final report preserves every claim/assertion from the draft verbatim.

        Validates: Requirements 17.3
        """
        from ir_agent.governance.audit import AuditLogger

        draft_content = (
            "【ドラフト — 最終版ではありません】\n"
            "\n"
            "# 統合テストケース — インシデント調査報告書（ドラフト）\n"
            "\n"
            "## TTP調査結果\n"
            "\n"
            "攻撃者はsftp.exeを使用してデータを外部に送信した。 （証拠ID: EV-100）\n"
            "\n"
            "【可能性】 データ窃取の可能性がある。 （証拠ID: EV-101）\n"
            "\n"
            "## 制約事項\n"
            "\n"
            "【制約事項】 FWログの保存期間が切れていたため一部分析不可。\n"
        )
        draft_path = tmp_path / "reports" / "draft_report.md"
        draft_path.parent.mkdir(parents=True, exist_ok=True)
        draft_path.write_text(draft_content, encoding="utf-8")

        audit_logger = AuditLogger(case_dir=tmp_path)
        generator = FinalReportGenerator()
        output = generator.finalize_report(draft_path, audit_logger, "analyst_a")

        final_content = output.read_text(encoding="utf-8")

        # All substantive content from draft must remain unchanged
        assert "攻撃者はsftp.exeを使用してデータを外部に送信した" in final_content
        assert "データ窃取の可能性がある" in final_content
        assert "FWログの保存期間が切れていたため一部分析不可" in final_content
        assert "EV-100" in final_content
        assert "EV-101" in final_content

    def test_final_report_does_not_add_new_content(self, tmp_path):
        """Final report does not introduce claims or assertions beyond the draft.

        Validates: Requirements 17.3
        """
        from ir_agent.governance.audit import AuditLogger

        # Minimal draft with known content
        draft_content = (
            "【ドラフト — 最終版ではありません】\n"
            "\n"
            "# テスト — インシデント調査報告書（ドラフト）\n"
            "\n"
            "## 調査概要\n"
            "\n"
            "これは最小限のドラフトです。\n"
        )
        draft_path = tmp_path / "reports" / "draft_report.md"
        draft_path.parent.mkdir(parents=True, exist_ok=True)
        draft_path.write_text(draft_content, encoding="utf-8")

        audit_logger = AuditLogger(case_dir=tmp_path)
        generator = FinalReportGenerator()
        output = generator.finalize_report(draft_path, audit_logger, "analyst_b")

        final_content = output.read_text(encoding="utf-8")

        # The body content should remain as-is
        assert "これは最小限のドラフトです。" in final_content

        # Should only add confidentiality notice and remove watermark/update title.
        assert "EV-" not in final_content
        assert "CLM-" not in final_content

    def test_final_report_only_transforms_are_watermark_title_notice(self, tmp_path):
        """The only transformations applied are: watermark removal, title update, notice addition.

        Validates: Requirements 17.3
        """
        from ir_agent.governance.audit import AuditLogger

        draft_content = (
            "【ドラフト — 最終版ではありません】\n"
            "\n"
            "# ケース — インシデント調査報告書（ドラフト）\n"
            "\n"
            "## エグゼクティブサマリー\n"
            "\n"
            "本件は不正アクセスに関する調査である。\n"
        )
        draft_path = tmp_path / "reports" / "draft_report.md"
        draft_path.parent.mkdir(parents=True, exist_ok=True)
        draft_path.write_text(draft_content, encoding="utf-8")

        audit_logger = AuditLogger(case_dir=tmp_path)
        generator = FinalReportGenerator()
        output = generator.finalize_report(draft_path, audit_logger, "analyst_c")

        final_content = output.read_text(encoding="utf-8")

        # Watermark removed
        assert "【ドラフト — 最終版ではありません】" not in final_content
        # Title updated
        assert "（最終版）" in final_content
        assert "（ドラフト）" not in final_content
        # Confidentiality notice added
        assert "機密情報" in final_content
        # Original prose preserved exactly
        assert "本件は不正アクセスに関する調査である。" in final_content


# ---------------------------------------------------------------------------
# RubricChecker: has_critical_failures identification (Req 28.4)
# ---------------------------------------------------------------------------


class TestRubricCheckerCriticalFailures:
    """RubricChecker correctly identifies critical failures for blocking."""

    def test_has_critical_failures_with_empty_report(self, ja_manifest):
        """An empty report should trigger critical failures.

        Validates: Requirements 28.4
        """
        checker = RubricChecker()
        results = checker.check_rubric("", None, ja_manifest)

        assert checker.has_critical_failures(results) is True
        assert len(results["critical_failures"]) > 0

    def test_has_critical_failures_false_on_complete_report(self, ja_manifest):
        """A complete report with all required sections passes.

        Validates: Requirements 28.4
        """
        report = (
            "# レポート\n"
            "## 調査目的・範囲\n調査目的と範囲の説明。\n"
            "## 調査対象・提供データ\n提供データの説明。\n"
            "## 調査期間\n2024年3月1日～3月15日\n"
            "## 制約事項\n一部ログが利用不可であった。\n"
            "## エグゼクティブサマリー\n概要説明。\n"
            "## タイムライン\n時系列情報。\n"
            "## TTP調査結果\n攻撃手法の詳細。\n"
            "## システム別詳細\nシステム別の調査結果。\n"
            "(Evidence ID: EV-001)\n"
            "【可能性】テスト\n"
            "## 封じ込め・復旧\n封じ込め措置。\n"
            "## 改善・再発防止策\n改善提案。\n"
            "## IoC一覧\nIOC情報。\n"
            "## ATT&CKマッピング\nMITREマッピング。\n"
        )

        checker = RubricChecker()
        results = checker.check_rubric(report, None, ja_manifest)

        assert checker.has_critical_failures(results) is False

    def test_critical_failures_include_missing_evidence_citations(self, ja_manifest):
        """Missing evidence citations trigger a critical failure (R09).

        Validates: Requirements 28.4
        """
        # Report with all sections but no evidence citations
        report = (
            "## 調査目的・範囲\nTest.\n"
            "## 調査対象\nData.\n"
            "## 調査期間\n2024.\n"
            "## 制約事項\nSome limitations text here.\n"
            "## エグゼクティブサマリー\nSummary.\n"
            "## TTP調査結果\nFindings without any evidence references.\n"
        )

        checker = RubricChecker()
        results = checker.check_rubric(report, None, ja_manifest)

        assert "R09" in results["critical_failures"]
        assert checker.has_critical_failures(results) is True

    def test_inline_limitations_satisfy_r04(self, ja_manifest):
        """Inline investigation limitations satisfy R04 for fixed report structure."""
        report = (
            "# インシデント調査報告書\n"
            "## 1. 調査概要\n"
            "### 1.2 調査目的・調査範囲\n調査目的と調査範囲。\n"
            "### 1.3 調査日程・調査期間\n対象期間と調査期間。\n"
            "### 1.4 調査対象・提供データ\n調査対象と提供データ。\n"
            "## 2. エグゼクティブサマリー・調査結果概要\n概要。\n"
            "### 2.4 インシデントタイムライン\n時系列。\n"
            "## 3. 調査結果\n"
            "TTP調査結果。制約として、未取得ログがあるため断定しない。"
            "（証拠ID: EV-001）\n"
            "## 4. 対象別調査結果詳細\n詳細調査。\n"
            "## 5. 対応状況・推奨対策\n"
            "### 5.1 封じ込め・復旧\n復旧。\n"
            "### 5.2 再発防止策\n再発防止。\n"
            "## 付録A. IoC一覧\nIoC。\n"
            "## 付録B. MITRE ATT&CK対応表\nMITRE マッピング。\n"
        )

        checker = RubricChecker()
        results = checker.check_rubric(report, None, ja_manifest)

        assert "R04" not in results["critical_failures"]

    def test_critical_failures_list_contains_only_critical_severity(self, ja_manifest):
        """critical_failures list only contains items with severity='critical'.

        Validates: Requirements 28.4
        """
        # Minimal report that misses many things
        report = "# Incomplete Report\nSome text.\n"

        checker = RubricChecker()
        results = checker.check_rubric(report, None, ja_manifest)

        # Verify that all items in critical_failures have critical severity
        critical_ids = set(results["critical_failures"])
        for item_result in results["items"]:
            if item_result["id"] in critical_ids:
                assert item_result["severity"] == "critical"


# ---------------------------------------------------------------------------
# ReportGenerationGuard: blocks correctly on each condition
# ---------------------------------------------------------------------------


class TestReportGenerationGuardConditions:
    """ReportGenerationGuard blocks at each phase with correct reasons."""

    # --- Plan phase conditions ---

    def test_plan_blocks_on_only_pending_claims(self):
        """Plan phase blocks when claims exist but none are approved.

        Validates: Requirements 16.2
        """
        guard = ReportGenerationGuard()
        claims = [
            _build_claim("CLM-X1", review_status="pending"),
            _build_claim("CLM-X2", review_status="pending"),
        ]
        state = WorkflowState(case_id="CASE-X", completed_phases=[])

        reasons = guard.validate_before_plan(claims, [], state)

        assert len(reasons) == 1
        assert "CLM-X1" in reasons[0]
        assert "CLM-X2" in reasons[0]

    def test_plan_passes_when_all_claims_approved_or_rejected(self):
        """Plan phase passes with a mix of approved and rejected claims.

        Validates: Requirements 16.2
        """
        guard = ReportGenerationGuard()
        claims = [
            _build_claim("CLM-Y1", review_status="approved"),
            _build_claim("CLM-Y2", review_status="rejected"),
            _build_claim("CLM-Y3", review_status="approved"),
        ]
        state = WorkflowState(case_id="CASE-Y", completed_phases=[])

        reasons = guard.validate_before_plan(claims, [], state)

        assert reasons == []

    def test_plan_blocks_on_critical_gap_without_disposition(self):
        """Plan blocks on critical gap that has no disposition.

        Validates: Requirements 16.2
        """
        guard = ReportGenerationGuard()
        claims = [_build_claim("CLM-Z1", review_status="approved")]
        gaps = [
            Gap(
                gap_id="GAP-CRIT",
                related_claim_id="CLM-Z1",
                gap_type="missing_evidence",
                severity="critical",
                description="重要ログの欠損",
                recommended_action="追加収集",
                disposition=None,
            )
        ]
        state = WorkflowState(case_id="CASE-Z", completed_phases=[])

        reasons = guard.validate_before_plan(claims, gaps, state)

        assert len(reasons) == 1
        assert "GAP-CRIT" in reasons[0]

    # --- Draft phase conditions ---

    def test_draft_blocks_on_nonzero_unsupported_rate(self):
        """Draft phase blocks when unsupported_claim_rate > 0.

        Validates: Requirements 16.2
        """
        guard = ReportGenerationGuard()
        plan = ReportPlan(
            sections=[
                {"heading": "Test", "claims": ["CLM-1"], "evidence_refs": [], "narrative_flow": ""}
            ],
            structure_type="standard",
        )
        claims = [_build_claim("CLM-1", review_status="approved")]
        metrics = {"unsupported_claim_rate": 0.1}

        reasons = guard.validate_before_draft(plan, claims, [], metrics)

        assert len(reasons) >= 1
        assert any("unsupported" in r.lower() or "Unsupported" in r for r in reasons)

    def test_draft_passes_with_zero_rate_and_approved_claims(self):
        """Draft phase passes when rate=0 and all claims approved.

        Validates: Requirements 16.2
        """
        guard = ReportGenerationGuard()
        plan = ReportPlan(
            sections=[
                {
                    "heading": "Test",
                    "claims": ["CLM-1"],
                    "evidence_refs": ["EV-1"],
                    "narrative_flow": "",
                }
            ],
            structure_type="standard",
        )
        claims = [_build_claim("CLM-1", review_status="approved")]
        metrics = {"unsupported_claim_rate": 0.0}

        reasons = guard.validate_before_draft(plan, claims, [], metrics)

        assert reasons == []

    # --- Final phase conditions ---

    def test_final_blocks_on_each_condition_independently(self):
        """Each blocking condition in validate_before_final works independently.

        Validates: Requirements 16.2, 17.3, 28.4
        """
        guard = ReportGenerationGuard()
        base_state = WorkflowState(
            case_id="CASE-F",
            completed_phases=[WorkflowPhase.DRAFT_REPORT_APPROVED],
        )
        passing_rubric = {"critical_failures": [], "audit_log_valid": True}

        # Condition 1: Critical rubric failure only
        reasons = guard.validate_before_final(
            "# Draft",
            {"critical_failures": ["R01"], "audit_log_valid": True},
            [],
            base_state,
        )
        assert len(reasons) == 1
        assert "rubric" in reasons[0].lower()

        # Condition 2: Undispositioned critical gap only
        undispositioned_gap = Gap(
            gap_id="GAP-F1",
            related_claim_id="CLM-F1",
            gap_type="missing_evidence",
            severity="critical",
            description="Critical gap",
            recommended_action="Fix it",
            disposition=None,
        )
        reasons = guard.validate_before_final(
            "# Draft", passing_rubric, [undispositioned_gap], base_state
        )
        assert len(reasons) == 1
        assert "GAP-F1" in reasons[0]

        # Condition 3: Audit log failure only
        reasons = guard.validate_before_final(
            "# Draft",
            {"critical_failures": [], "audit_log_valid": False},
            [],
            base_state,
        )
        assert len(reasons) == 1
        assert "audit" in reasons[0].lower()

        # Condition 4: Missing approval only
        no_approval_state = WorkflowState(
            case_id="CASE-F",
            completed_phases=[WorkflowPhase.DRAFT_REPORT_GENERATED],
        )
        reasons = guard.validate_before_final("# Draft", passing_rubric, [], no_approval_state)
        assert len(reasons) == 1
        assert "approval" in reasons[0].lower()

    def test_final_all_conditions_fail_simultaneously(self):
        """When all conditions fail at once, all 4 reasons are reported.

        Validates: Requirements 16.2, 17.3, 28.4
        """
        guard = ReportGenerationGuard()
        state = WorkflowState(case_id="CASE-ALL", completed_phases=[])
        rubric = {"critical_failures": ["R05"], "audit_log_valid": False}
        gaps = [
            Gap(
                gap_id="GAP-ALL",
                related_claim_id="CLM-1",
                gap_type="missing_evidence",
                severity="critical",
                description="All fail test",
                recommended_action="N/A",
                disposition=None,
            )
        ]

        reasons = guard.validate_before_final("# Draft", rubric, gaps, state)

        assert len(reasons) == 4
        # Verify each type of reason is present
        reason_text = " ".join(reasons).lower()
        assert "rubric" in reason_text
        assert "gap" in reason_text.lower() or "GAP-ALL" in " ".join(reasons)
        assert "audit" in reason_text
        assert "approval" in reason_text

    def test_final_dispositioned_critical_gaps_do_not_block(self):
        """Critical gaps with any valid disposition do not block final.

        Validates: Requirements 16.2
        """
        guard = ReportGenerationGuard()
        state = WorkflowState(
            case_id="CASE-DISP",
            completed_phases=[WorkflowPhase.DRAFT_REPORT_APPROVED],
        )
        rubric = {"critical_failures": [], "audit_log_valid": True}

        dispositions = [
            "accepted_as_limitation",
            "mitigated_by_claim_downgrade",
            "addressed_by_additional_evidence",
            "out_of_scope_with_analyst_approval",
            "deferred_with_reason",
        ]

        for disp in dispositions:
            gap = Gap(
                gap_id=f"GAP-{disp[:5]}",
                related_claim_id="CLM-1",
                gap_type="missing_evidence",
                severity="critical",
                description=f"Gap with disposition {disp}",
                recommended_action="N/A",
                disposition=disp,
            )
            reasons = guard.validate_before_final("# Draft", rubric, [gap], state)
            assert reasons == [], f"Disposition '{disp}' unexpectedly blocked"
