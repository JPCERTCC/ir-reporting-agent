"""Regression tests for the specification_update.md changes (UP-01..UP-09)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from ir_agent.analysis.coverage import (
    DataCoverageService,
    infer_data_source_type,
)
from ir_agent.analysis.gap_checker import GapChecker
from ir_agent.extraction.ioc_extractor import IOCExtractor, refang
from ir_agent.models.analysis import Claim, DataCoverageEntry
from ir_agent.models.base import TimeRange
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry, SourceReference
from ir_agent.reporting.final_generator import FinalReportGenerator


def _ledger_entry(host: str, path: str, ic=ConfidenceLevel.PROBABLE):
    return EvidenceLedgerEntry(
        evidence_id="ev-x",
        promoted_from=["c1"],
        approval_timestamp="2026-01-01T00:00:00+00:00",
        approved_by="tester",
        source_refs=[
            SourceReference(
                source_ref_id="sr1",
                source_file_id="f1",
                source_path=path,
                source_lines=[1, 1],
                excerpt="x",
                excerpt_sha256="0" * 64,
            )
        ],
        observed_event={"host": host},
        observed_fact="fact",
        interpretation="interp",
        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
        interpretation_confidence=ic,
    )


# --- UP-08: defang-aware IoC extraction ---

def test_refang_normalizes_defanged_ip():
    assert refang("45[.]77[.]183[.]161") == "45.77.183.161"
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"


def test_extractor_finds_defanged_ip():
    ex = IOCExtractor()
    iocs = ex.extract_iocs('sftp upload@45[.]77[.]183[.]161', "f1")
    ips = {i.value for i in iocs if i.ioc_type == "ip"}
    assert "45.77.183.161" in ips


def test_extractor_skips_path_segment_as_domain():
    ex = IOCExtractor()
    iocs = ex.extract_iocs(r"C:\Windows\Microsoft.NET\Framework64", "f1")
    domains = {i.value for i in iocs if i.ioc_type == "domain"}
    assert "Microsoft.NET" not in domains


# --- UP-02: coverage inference + evidence derivation ---

def test_infer_data_source_type_is_stable():
    assert infer_data_source_type("AD01/AD01_Security_x.evtx.txt") == "windows_event_log"
    assert infer_data_source_type("Firewall/fw_session.log.txt") == "firewall_log"
    assert infer_data_source_type("VPN/vpn-tokyo-01_ssl-vpn.log.txt") == "network_flow"
    assert infer_data_source_type("weird/unknown.bin") == "host_artifact"


def test_derive_from_evidence_marks_available():
    tmp = Path(tempfile.mkdtemp())
    (tmp / "data").mkdir()
    svc = DataCoverageService.from_case_dir(tmp)
    tr = TimeRange(start="2025-05-10T00:00:00+09:00", end="2025-06-01T23:59:59+09:00")
    entries = [_ledger_entry("AD01", "AD01/AD01_Security_x.evtx.txt")]
    derived = svc.derive_from_evidence(entries, tr)
    assert derived
    assert all(e.availability_status == "available" for e in derived)


def test_mark_unobserved_outside_scope():
    tmp = Path(tempfile.mkdtemp())
    (tmp / "data").mkdir()
    svc = DataCoverageService.from_case_dir(tmp)
    svc._store.append(
        DataCoverageEntry(
            data_source_id="DC-AD01-dns_log",
            host_or_system="AD01",
            data_source_type="dns_log",
            availability_status="unknown",
            covered_time_range=None,
            collection_time=None,
            known_gaps=[],
            reason_for_unavailability=None,
            impact_on_findings=None,
        )
    )
    rescoped = svc.mark_unobserved_outside_scope()
    assert len(rescoped) == 1
    assert svc.get_all_entries()[0].availability_status == "outside_scope"


# --- UP-07: case-specific analytical gaps ---

def _claim(text, limitations=None):
    return Claim(
        claim_id="CLM-1",
        report_section="3.6",
        claim_text=text,
        claim_category=ClaimCategory.OBSERVED_FACT,
        confidence_level=ConfidenceLevel.POSSIBLE,
        confidence_basis="b",
        supporting_evidence=["ev-x"],
        limitations=limitations or [],
    )


def test_constraint_gap_types_detected():
    checker = GapChecker()
    claim = _claim(
        "collect.rar の本体は取得できていない。送信内容は暗号化されており確認できない。"
    )
    gaps = checker.check_gaps([claim], [])
    types = {g.gap_type for g in gaps}
    assert "artifact_body_missing" in types
    assert "content_not_recoverable" in types


def test_point_in_time_gap_detected():
    checker = GapChecker()
    claim = _claim("待受の開始時刻はこの記録からは特定できません。")
    gaps = checker.check_gaps([claim], [])
    assert any(g.gap_type == "point_in_time_only" for g in gaps)


# --- UP-04: final report version stamping ---

_DRAFT = """【ドラフト — 最終版ではありません】

# インシデント調査報告書

## 報告書メタデータ

| 項目 | 内容 |
|---|---|
| 版数 | 0.1(ドラフト) |
| 作成者 | IR Reporting Support Agent(レビュー前ドラフト) |

## 変更履歴

| 版数 | 日付 | 変更内容 | 作成者 |
|---|---|---|---|
| 0.1 | 2026-07-16 | 初版ドラフト作成 | IR Reporting Support Agent |
"""


class _NullAudit:
    def ensure_writable(self):
        pass

    def log_operation(self, *a, **k):
        pass

    def log_approval(self, *a, **k):
        pass


def test_finalize_stamps_version(monkeypatch):
    tmp = Path(tempfile.mkdtemp())
    (tmp / "reports").mkdir()
    draft = tmp / "reports" / "draft_report.md"
    draft.write_text(_DRAFT, encoding="utf-8")
    gen = FinalReportGenerator(report_language="ja")
    out = gen.finalize_report(draft, _NullAudit(), analyst_id="tester")
    text = out.read_text(encoding="utf-8")
    assert "0.1(ドラフト)" not in text
    assert "レビュー前ドラフト" not in text
    assert "1.0（確定）" in text
    assert "分析担当者承認により確定" in text
    # the approving analyst is named, and the 1.0 row directly follows 0.1
    # (no blank line splitting the history table)
    assert "| 承認者 | tester |" in text
    assert "| IR Reporting Support Agent |\n| 1.0 | " in text
    assert text.rstrip().endswith("| 分析担当者承認により確定 | tester |")


def test_finalize_strips_draft_marker_for_legacy_author_name():
    # Drafts generated before the rename still carry the old tool name.
    tmp = Path(tempfile.mkdtemp())
    (tmp / "reports").mkdir()
    draft = tmp / "reports" / "draft_report.md"
    draft.write_text(_DRAFT.replace("IR Reporting Support Agent", "IR Reporting Agent"),
                     encoding="utf-8")
    gen = FinalReportGenerator(report_language="ja")
    out = gen.finalize_report(draft, _NullAudit(), analyst_id="tester")
    text = out.read_text(encoding="utf-8")
    assert "レビュー前ドラフト" not in text
    assert "| 作成者 | IR Reporting Agent |" in text
