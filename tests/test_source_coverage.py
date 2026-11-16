"""Tests for source coverage (inventory → chunks → candidates → ledger)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from click.testing import CliRunner

from ir_agent.analysis.gap_review import GapReviewService
from ir_agent.analysis.source_coverage import (
    CASE_SCOPE_CLAIM_ID,
    IN_LEDGER,
    NOT_APPROVED,
    NOT_CHUNKED,
    NOT_EXTRACTED,
    NOT_PROVIDED,
    build_source_coverage,
    load_source_coverage,
    source_coverage_gap_specs,
    summary_line,
)
from ir_agent.cli.main import cli
from ir_agent.models.analysis import Gap

REPO = Path(__file__).resolve().parents[1]
SKILLS = REPO / ".claude" / "skills"


def _import_module(path: Path):
    # Skill scripts import sibling helpers (e.g. review_io) by bare name.
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def _make_case(tmp_path: Path, hosts: list[str] | None = None) -> Path:
    """Four files, one per status: a=in_ledger, b=not_approved,
    c=not_extracted, d=not_chunked."""
    case = tmp_path / "case"
    data = case / "data"
    (data / "chunks").mkdir(parents=True)
    inventory = [
        {"file_id": "F-a", "path": "artifacts/a.log", "host": "VPN01", "line_count": 10},
        {"file_id": "F-b", "path": "artifacts/b.log", "metadata": {"system": "DC01"},
         "line_count": 5},
        {"file_id": "F-c", "path": "artifacts/c.log", "host": "FS01", "line_count": 3},
        {"file_id": "F-d", "path": "artifacts/d.log", "host": "FS01", "line_count": 1},
    ]
    (data / "file_inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
    for fid, path in (("F-a", "artifacts/a.log"), ("F-b", "artifacts/b.log"),
                      ("F-c", "artifacts/c.log")):
        (data / "chunks" / f"{fid}-0.json").write_text(json.dumps({
            "chunk_id": f"{fid}-0", "source_file_id": fid, "source_path": path,
            "start_line": 1, "end_line": 3, "content": "x",
        }), encoding="utf-8")
    _write_jsonl(data / "evidence_candidates.jsonl", [
        {"candidate_id": "C-1", "source_refs": [{"source_file_id": "F-a"}]},
        {"candidate_id": "C-2", "source_refs": [{"source_file_id": "F-b"}]},
    ])
    _write_jsonl(data / "evidence_ledger.jsonl", [
        {"evidence_id": "E-1", "source_refs": [
            {"source_file_id": "F-a", "source_lines": [2, 4]}]},
        # Withdrawn entry must not count for F-b.
        {"evidence_id": "E-2", "source_refs": [{"source_file_id": "F-b"}]},
        {"evidence_id": "E-2", "withdrawn": True},
    ])
    if hosts is not None:
        (case / "manifest.yaml").write_text(
            "hosts:\n" + "".join(f"  - {h}\n" for h in hosts), encoding="utf-8"
        )
    return case


class TestBuildSourceCoverage:
    def test_classifies_each_status(self, tmp_path: Path) -> None:
        report = build_source_coverage(_make_case(tmp_path))
        status = {f["file_id"]: f["status"] for f in report["files"]}
        assert status == {"F-a": IN_LEDGER, "F-b": NOT_APPROVED,
                          "F-c": NOT_EXTRACTED, "F-d": NOT_CHUNKED}
        a = next(f for f in report["files"] if f["file_id"] == "F-a")
        assert a["evidence_ids"] == ["E-1"]
        assert a["cited_line_count"] == 3
        b = next(f for f in report["files"] if f["file_id"] == "F-b")
        assert b["host"] == "DC01"
        assert b["candidate_count"] == 1
        assert report["summary"][IN_LEDGER] == 1
        assert report["summary"][NOT_PROVIDED] == 0

    def test_missing_hosts_case_insensitive(self, tmp_path: Path) -> None:
        case = _make_case(tmp_path, hosts=["vpn01", "dc01", "WEB01"])
        report = load_source_coverage(case)
        assert [h["host"] for h in report["missing_hosts"]] == ["WEB01"]
        assert report["summary"][NOT_PROVIDED] == 1

    def test_empty_case(self, tmp_path: Path) -> None:
        report = build_source_coverage(tmp_path)
        assert report["files"] == []
        assert source_coverage_gap_specs(report) == []

    def test_summary_line(self, tmp_path: Path) -> None:
        line = summary_line(build_source_coverage(_make_case(tmp_path), ["WEB01"]))
        assert line == ("1/4 files in ledger; not approved 1, not extracted 1, "
                        "not chunked 1, hosts not provided 1")


class TestGapSpecs:
    def test_one_spec_per_category(self, tmp_path: Path) -> None:
        report = build_source_coverage(_make_case(tmp_path), ["WEB01"])
        specs = source_coverage_gap_specs(report)
        assert [(s["gap_type"], s["severity"]) for s in specs] == [
            ("unavailable_logs", "major"),
            ("logs_not_analyzed", "major"),
            ("logs_not_analyzed", "major"),
            ("logs_not_analyzed", "minor"),
        ]
        assert all(s["related_claim_id"] == CASE_SCOPE_CLAIM_ID for s in specs)
        assert "WEB01" in specs[0]["description"]
        assert "未抽出 1 件: artifacts/c.log" in specs[2]["description"]
        for spec in specs:
            Gap(gap_id="GAP-x", **spec)  # valid Gap model

    def test_long_lists_truncated(self) -> None:
        files = [{"path": f"f{i}.log", "status": NOT_EXTRACTED} for i in range(13)]
        (spec,) = source_coverage_gap_specs({"files": files, "missing_hosts": []})
        assert "f9.log" in spec["description"]
        assert "f10.log" not in spec["description"]
        assert "ほか 3 件" in spec["description"]


class TestCli:
    def test_source_coverage_command(self, tmp_path: Path) -> None:
        case = _make_case(tmp_path, hosts=["WEB01"])
        result = CliRunner().invoke(cli, ["--case-dir", str(case), "source-coverage"])
        assert result.exit_code == 0, result.output
        assert "1/4 files in ledger" in result.output
        assert "[未抽出] artifacts/c.log" in result.output
        assert "[未提供] host=WEB01" in result.output
        assert "artifacts/a.log" not in result.output
        written = json.loads((case / "data" / "source_coverage.json").read_text())
        assert len(written["files"]) == 4

    def test_source_coverage_requires_ingest(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(cli, ["--case-dir", str(tmp_path), "source-coverage"])
        assert result.exit_code == 1


class TestGapReviewNote:
    def test_case_scope_gap_has_note(self, tmp_path: Path) -> None:
        gaps = [
            Gap(gap_id="GAP-1", related_claim_id=CASE_SCOPE_CLAIM_ID,
                gap_type="logs_not_analyzed", severity="major",
                description="d", recommended_action="r"),
            Gap(gap_id="GAP-2", related_claim_id="CLM-001",
                gap_type="missing_evidence", severity="minor",
                description="d", recommended_action="r"),
        ]
        out = tmp_path / "gap_review.md"
        GapReviewService().generate_gap_review_doc(gaps, out, review_language="ja")
        assert out.read_text(encoding="utf-8").count("ケース全体の不足事項です") == 1


class TestSkillHelpers:
    def test_finalize_uncovered_sources(self, tmp_path: Path) -> None:
        mod = _import_module(
            SKILLS / "ir-extract-evidence" / "scripts" / "finalize_candidates.py")
        case = _make_case(tmp_path)
        assert mod.uncovered_sources(
            case / "data" / "chunks", case / "data" / "evidence_candidates.jsonl"
        ) == ["artifacts/c.log"]

    def test_build_case_material_source_coverage(self, tmp_path: Path) -> None:
        mod = _import_module(
            SKILLS / "ir-draft-report" / "scripts" / "build_case_material.py")
        cov = mod.source_coverage(_make_case(tmp_path, hosts=["WEB01"]))
        assert {f["path"] for f in cov["unused_files"]} == {
            "artifacts/b.log", "artifacts/c.log", "artifacts/d.log"}
        assert cov["missing_hosts"] == ["WEB01"]
        assert mod.source_coverage(tmp_path / "empty") is None

    def test_quality_summary_source_trace(self, tmp_path: Path) -> None:
        mod = _import_module(
            SKILLS / "ir-review-quality" / "scripts" / "write_quality_summary.py")
        case = _make_case(tmp_path)
        (case / "reports").mkdir()
        (case / "reports" / "case_material.json").write_text(
            json.dumps({"alias_map": {"EV-001": "E-1"}}), encoding="utf-8")

        cited = "\n".join(mod.source_trace_lines(case, "所見(証拠ID: EV-001)。c.log 参照"))
        assert "台帳に証拠があるのに" not in cited
        assert "artifacts/c.log" not in cited
        assert "[未承認] artifacts/b.log" in cited

        uncited = "\n".join(mod.source_trace_lines(case, "本文"))
        assert "台帳に証拠があるのに本文で引用されていないファイル: artifacts/a.log" in uncited

    def test_check_review_run_flags_adhoc_scripts(self, tmp_path: Path) -> None:
        mod = _import_module(
            SKILLS / "ir-review-report" / "scripts" / "check_review_run.py")
        (tmp_path / ".git").mkdir()
        run_id = "20260101-000000_test"
        run_dir = tmp_path / "case" / "reviews" / "report" / run_id
        run_dir.mkdir(parents=True)
        (tmp_path / "eval.py").write_text(f"RUN = '{run_id}'\n", encoding="utf-8")
        (tmp_path / "case" / "fix.py").write_text(f"# {run_id}\n", encoding="utf-8")
        (tmp_path / "other.py").write_text("print(1)\n", encoding="utf-8")
        scratch = tmp_path / "case" / "reviews" / "_scratch"
        scratch.mkdir()
        (scratch / "old.py").write_text(f"# {run_id}\n", encoding="utf-8")

        hits = mod._scripts_targeting_run(run_dir)
        assert sorted(str(h) for h in hits) == ["case/fix.py", "eval.py"]

    def test_check_review_run_no_git_root(self, tmp_path: Path) -> None:
        mod = _import_module(
            SKILLS / "ir-review-report" / "scripts" / "check_review_run.py")
        run_dir = tmp_path / "reviews" / "r" / "run"
        run_dir.mkdir(parents=True)
        assert mod._scripts_targeting_run(run_dir) == []
