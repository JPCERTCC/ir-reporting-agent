"""Unit tests for review-evidence and promote-evidence CLI commands.

Tests the evidence review workflow: generating review documents and
promoting approved candidates to the evidence ledger.

Requirements: 7.1, 7.3, 7.4, 7.5, 7.6, 8.1
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from ir_agent.cli.main import cli
from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceCandidate


@pytest.fixture
def runner():
    """Create a Click test runner."""
    return CliRunner()


@pytest.fixture
def case_dir(tmp_path):
    """Provide a temporary case directory path."""
    return tmp_path / "test_case"


@pytest.fixture
def initialized_case(runner, case_dir):
    """Create a fully initialized case with subdirectories and manifest."""
    runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
    return case_dir


def _make_candidate(candidate_id: str, observed_fact: str = "Test fact") -> EvidenceCandidate:
    """Create a sample EvidenceCandidate for testing."""
    return EvidenceCandidate(
        candidate_id=candidate_id,
        source_refs=[
            SourceReference(
                source_ref_id=f"ref-{candidate_id}",
                source_file_id="file-001",
                source_path="artifacts/test.log",
                source_lines=(1, 10),
                excerpt="Sample log excerpt for testing",
                excerpt_sha256="abc123",
            )
        ],
        observed_event={"type": "test_event", "host": "host01"},
        observed_fact=observed_fact,
        interpretation="Test interpretation of the event",
        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
        interpretation_confidence=ConfidenceLevel.PROBABLE,
        attack_mapping_candidates=[],
    )


def _write_candidates(case_dir: Path, candidates: list[EvidenceCandidate]) -> None:
    """Write evidence candidates to the expected JSONL file."""
    candidates_path = case_dir / "data" / "evidence_candidates.jsonl"
    candidates_path.parent.mkdir(parents=True, exist_ok=True)
    with open(candidates_path, "w", encoding="utf-8") as f:
        for c in candidates:
            f.write(c.model_dump_json() + "\n")


def _set_workflow_phase(case_dir: Path, phase: str, completed: list[str]) -> None:
    """Set the workflow state to a specific phase with completed phases."""
    state = {
        "case_id": case_dir.name,
        "current_phase": phase,
        "completed_phases": completed,
        "blocked_reasons": [],
        "last_updated_at": "2024-01-01T00:00:00+00:00",
        "last_updated_by": None,
    }
    state_path = case_dir / "workflow_state.json"
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


class TestReviewEvidenceCommand:
    """Tests for the 'review-evidence' CLI command."""

    def test_review_evidence_generates_review_doc(self, runner, initialized_case):
        """review-evidence should generate a review Markdown file."""
        # Use distinct observed_facts and different source files to prevent deduplication
        cand1 = _make_candidate("cand-001", "User admin logged in from 192.168.1.1")
        cand2 = _make_candidate("cand-002", "File transfer detected to external server")
        # Ensure different source files to prevent merge
        cand2.source_refs[0].source_file_id = "file-002"
        _write_candidates(initialized_case, [cand1, cand2])

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-evidence"]
        )
        assert result.exit_code == 0

        review_path = initialized_case / "reviews" / "evidence_review_001.md"
        assert review_path.is_file()
        content = review_path.read_text(encoding="utf-8")
        assert "cand-001" in content
        assert "cand-002" in content

    def test_review_evidence_uses_japanese_headings(self, runner, initialized_case):
        """review-evidence should render headings in Japanese by default."""
        candidates = [_make_candidate("cand-001")]
        _write_candidates(initialized_case, candidates)

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-evidence"]
        )
        assert result.exit_code == 0

        review_path = initialized_case / "reviews" / "evidence_review_001.md"
        content = review_path.read_text(encoding="utf-8")
        # Japanese headings
        assert "観測事実" in content
        assert "解釈" in content
        assert "信頼度" in content
        assert "判定" in content
        # YAML decision block keys remain in English
        assert "item_id:" in content
        assert "decision:" in content

    def test_review_evidence_fails_without_candidates(self, runner, initialized_case):
        """review-evidence should fail if no candidates file exists."""
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-evidence"]
        )
        assert result.exit_code == 1
        assert "No evidence candidates found" in result.output

    def test_review_evidence_fails_with_empty_candidates(self, runner, initialized_case):
        """review-evidence should fail if candidates file is empty."""
        candidates_path = initialized_case / "data" / "evidence_candidates.jsonl"
        candidates_path.write_text("", encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-evidence"]
        )
        assert result.exit_code == 1
        assert "empty" in result.output

    def test_review_evidence_increments_review_number(self, runner, initialized_case):
        """review-evidence should create sequentially numbered review files."""
        candidates = [_make_candidate("cand-001")]
        _write_candidates(initialized_case, candidates)

        # First invocation
        runner.invoke(cli, ["--case-dir", str(initialized_case), "review-evidence"])
        assert (initialized_case / "reviews" / "evidence_review_001.md").is_file()

        # Second invocation
        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-evidence"]
        )
        assert result.exit_code == 0
        assert (initialized_case / "reviews" / "evidence_review_002.md").is_file()

    def test_review_evidence_logs_operation(self, runner, initialized_case):
        """review-evidence should log an audit entry."""
        candidates = [_make_candidate("cand-001")]
        _write_candidates(initialized_case, candidates)

        runner.invoke(cli, ["--case-dir", str(initialized_case), "review-evidence"])

        audit_path = initialized_case / "logs" / "audit.jsonl"
        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        # Find the review-evidence entry
        review_entries = [
            json.loads(l) for l in lines
            if "review-evidence" in l
        ]
        assert len(review_entries) >= 1
        assert review_entries[0]["operation_type"] == "review-evidence"
        assert review_entries[0]["status"] == "success"

    def test_review_evidence_marks_evidence_candidates_generated(
        self, runner, initialized_case
    ):
        """review-evidence should mark EVIDENCE_CANDIDATES_GENERATED if not already."""
        candidates = [_make_candidate("cand-001")]
        _write_candidates(initialized_case, candidates)

        runner.invoke(cli, ["--case-dir", str(initialized_case), "review-evidence"])

        state_path = initialized_case / "workflow_state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert "evidence_candidates_generated" in state["completed_phases"]

    def test_review_evidence_runs_deduplication(self, runner, initialized_case):
        """review-evidence should detect and merge duplicates."""
        # Create two candidates with very similar observed_facts and overlapping sources
        cand1 = EvidenceCandidate(
            candidate_id="cand-dup-1",
            source_refs=[
                SourceReference(
                    source_ref_id="ref-dup-1",
                    source_file_id="file-001",
                    source_path="artifacts/test.log",
                    source_lines=(1, 10),
                    excerpt="User admin logged in from 192.168.1.100 at 2024-01-01 10:00:00",
                    excerpt_sha256="abc",
                )
            ],
            observed_event={"type": "login"},
            observed_fact="User admin logged in from 192.168.1.100 at 2024-01-01 10:00:00",
            interpretation="Possible unauthorized access",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.POSSIBLE,
            attack_mapping_candidates=[],
        )
        cand2 = EvidenceCandidate(
            candidate_id="cand-dup-2",
            source_refs=[
                SourceReference(
                    source_ref_id="ref-dup-2",
                    source_file_id="file-001",
                    source_path="artifacts/test.log",
                    source_lines=(2, 9),
                    excerpt="User admin logged in from 192.168.1.100 at 2024-01-01 10:00:00",
                    excerpt_sha256="def",
                )
            ],
            observed_event={"type": "login"},
            observed_fact="User admin logged in from 192.168.1.100 at 2024-01-01 10:00:00",
            interpretation="Possible unauthorized access from external IP",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.POSSIBLE,
            attack_mapping_candidates=[],
        )
        _write_candidates(initialized_case, [cand1, cand2])

        result = runner.invoke(
            cli, ["--case-dir", str(initialized_case), "review-evidence"]
        )
        assert result.exit_code == 0
        assert "duplicate" in result.output.lower() or "Merging" in result.output


class TestPromoteEvidenceCommand:
    """Tests for the 'promote-evidence' CLI command."""

    def _setup_for_promotion(self, case_dir: Path, runner) -> Path:
        """Set up a case with candidates and a review document ready for promotion."""
        # Initialize case
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        # Write candidates
        candidates = [
            _make_candidate("cand-001", "Login from external IP"),
            _make_candidate("cand-002", "File transfer detected"),
        ]
        _write_candidates(case_dir, candidates)

        # Set workflow state to EVIDENCE_CANDIDATES_GENERATED
        _set_workflow_phase(
            case_dir,
            "evidence_candidates_generated",
            ["case_initialized", "artifacts_ingested", "events_normalized", "evidence_candidates_generated"],
        )

        # Generate a review document
        runner.invoke(cli, ["--case-dir", str(case_dir), "review-evidence"])
        return case_dir / "reviews" / "evidence_review_001.md"

    def test_promote_evidence_promotes_approved_candidates(self, runner, case_dir):
        """promote-evidence should promote approved candidates to the ledger."""
        review_path = self._setup_for_promotion(case_dir, runner)

        # Edit the review doc to approve one candidate
        content = review_path.read_text(encoding="utf-8")
        content = content.replace(
            'item_id: cand-001\nitem_type: evidence_candidate\n'
            'decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留\n'
            'decision_reason: ""\n'
            'analyst_id: ""',
            'item_id: cand-001\nitem_type: evidence_candidate\n'
            'decision: approved\n'
            'decision_reason: "Confirmed by multiple sources"\n'
            'analyst_id: "analyst-01"',
        )
        content = content.replace(
            'item_id: cand-002\nitem_type: evidence_candidate\n'
            'decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留\n'
            'decision_reason: ""\n'
            'analyst_id: ""',
            'item_id: cand-002\nitem_type: evidence_candidate\n'
            'decision: rejected\n'
            'decision_reason: "Insufficient evidence"\n'
            'analyst_id: "analyst-01"',
        )
        review_path.write_text(content, encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence", "--analyst-id", "analyst-01"]
        )
        assert result.exit_code == 0
        assert "Promoted" in result.output
        assert "Rejected" in result.output

        # Verify ledger file was created
        ledger_path = case_dir / "data" / "evidence_ledger.jsonl"
        assert ledger_path.is_file()
        lines = ledger_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1  # Only one candidate promoted

        entry = json.loads(lines[0])
        assert entry["approved_by"] == "analyst-01"
        assert "cand-001" in entry["promoted_from"]

    def test_promote_evidence_marks_ledger_approved(self, runner, case_dir):
        """promote-evidence should mark EVIDENCE_LEDGER_APPROVED when all decisions made."""
        review_path = self._setup_for_promotion(case_dir, runner)

        # Approve both candidates
        content = review_path.read_text(encoding="utf-8")
        content = content.replace(
            "decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留",
            "decision: approved",
        )
        review_path.write_text(content, encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence"]
        )
        assert result.exit_code == 0
        assert "EVIDENCE_LEDGER_APPROVED" in result.output

        state = json.loads(
            (case_dir / "workflow_state.json").read_text(encoding="utf-8")
        )
        assert "evidence_ledger_approved" in state["completed_phases"]

    def test_promote_evidence_does_not_mark_approved_if_pending(self, runner, case_dir):
        """promote-evidence should not mark EVIDENCE_LEDGER_APPROVED if items are pending."""
        review_path = self._setup_for_promotion(case_dir, runner)

        # Approve only one candidate, leave the other pending
        content = review_path.read_text(encoding="utf-8")
        # Replace only the first occurrence
        content = content.replace(
            'item_id: cand-001\nitem_type: evidence_candidate\n'
            'decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留\n'
            'decision_reason: ""\n'
            'analyst_id: ""',
            'item_id: cand-001\nitem_type: evidence_candidate\n'
            'decision: approved\n'
            'decision_reason: "Confirmed"\n'
            'analyst_id: "analyst-01"',
        )
        review_path.write_text(content, encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence"]
        )
        assert result.exit_code == 0
        assert "still pending" in result.output

        state = json.loads(
            (case_dir / "workflow_state.json").read_text(encoding="utf-8")
        )
        assert "evidence_ledger_approved" not in state["completed_phases"]

    def test_promote_evidence_fails_without_prerequisite(self, runner, case_dir):
        """promote-evidence should fail if EVIDENCE_CANDIDATES_GENERATED not completed."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence"]
        )
        assert result.exit_code == 1
        assert "cannot run" in result.output.lower() or "Error" in result.output

    def test_promote_evidence_fails_without_review_doc(self, runner, case_dir):
        """promote-evidence should fail if no review document exists."""
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        _set_workflow_phase(
            case_dir,
            "evidence_candidates_generated",
            ["case_initialized", "artifacts_ingested", "events_normalized", "evidence_candidates_generated"],
        )

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence"]
        )
        assert result.exit_code == 1
        assert "No evidence review document found" in result.output

    def test_promote_evidence_logs_approvals(self, runner, case_dir):
        """promote-evidence should log approval decisions in audit log."""
        review_path = self._setup_for_promotion(case_dir, runner)

        # Approve one candidate
        content = review_path.read_text(encoding="utf-8")
        content = content.replace(
            "decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留",
            "decision: approved",
        )
        review_path.write_text(content, encoding="utf-8")

        runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence", "--analyst-id", "analyst-01"]
        )

        audit_path = case_dir / "logs" / "audit.jsonl"
        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()

        # Find approval entries
        approval_entries = [
            json.loads(l) for l in lines
            if '"item_type"' in l and '"evidence_candidate"' in l
        ]
        assert len(approval_entries) >= 2  # At least 2 candidates approved

    def test_promote_evidence_handles_edited_decision(self, runner, case_dir):
        """promote-evidence should promote candidates marked as 'edited'."""
        review_path = self._setup_for_promotion(case_dir, runner)

        # Mark both as edited (implies approval with changes)
        content = review_path.read_text(encoding="utf-8")
        content = content.replace(
            "decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留",
            "decision: edited",
        )
        review_path.write_text(content, encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence"]
        )
        assert result.exit_code == 0
        assert "Edited & promoted" in result.output

        # Verify ledger
        ledger_path = case_dir / "data" / "evidence_ledger.jsonl"
        lines = ledger_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2  # Both promoted

    def test_promote_evidence_uses_latest_review_doc(self, runner, case_dir):
        """promote-evidence should find and use the latest review document."""
        review_path = self._setup_for_promotion(case_dir, runner)

        # Create a second review document (simulate running review-evidence twice)
        review_002 = case_dir / "reviews" / "evidence_review_002.md"
        review_002.write_text(
            review_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        # Modify the second review to approve candidates
        content = review_002.read_text(encoding="utf-8")
        content = content.replace(
            "decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留",
            "decision: approved",
        )
        review_002.write_text(content, encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence"]
        )
        assert result.exit_code == 0
        # Should use evidence_review_002.md (the latest)
        assert "evidence_review_002.md" in result.output

    def test_promote_evidence_summary_output(self, runner, case_dir):
        """promote-evidence should display a clear summary of actions taken."""
        review_path = self._setup_for_promotion(case_dir, runner)

        # Approve one, reject one
        content = review_path.read_text(encoding="utf-8")
        content = content.replace(
            'item_id: cand-001\nitem_type: evidence_candidate\n'
            'decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留\n'
            'decision_reason: ""\n'
            'analyst_id: ""',
            'item_id: cand-001\nitem_type: evidence_candidate\n'
            'decision: approved\n'
            'decision_reason: "Verified"\n'
            'analyst_id: "analyst-01"',
        )
        content = content.replace(
            'item_id: cand-002\nitem_type: evidence_candidate\n'
            'decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留\n'
            'decision_reason: ""\n'
            'analyst_id: ""',
            'item_id: cand-002\nitem_type: evidence_candidate\n'
            'decision: rejected\n'
            'decision_reason: "Not relevant"\n'
            'analyst_id: "analyst-01"',
        )
        review_path.write_text(content, encoding="utf-8")

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence"]
        )
        assert result.exit_code == 0
        assert "Evidence promotion summary" in result.output
        assert "Approved:" in result.output
        assert "Rejected:" in result.output
