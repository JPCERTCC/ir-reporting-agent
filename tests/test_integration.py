"""Integration tests for the IR Agent CLI full pipeline.

Tests:
1. End-to-end pipeline: ingest -> normalize-events -> extract-candidates ->
   review-evidence -> promote-evidence -> build-coverage -> build-timeline ->
   map-attack -> build-claims -> review-claims -> check-gaps ->
   plan-report -> draft-report -> approve-draft -> finalize-report
2. Round-trip: review document generation -> analyst edits -> parser extraction
3. Expression policy: Japanese claims use correct wording per confidence/category
4. Workflow enforcement across the full pipeline

Evidence extraction is simulated by writing the candidates file an agent
(ir-extract-evidence skill) would produce, then validating it with the CLI
without external API calls.

Requirements: 21.1, 22.9, 25.2, 26.5
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from ir_agent.cli.main import cli


# --- Fixtures ---

SAMPLE_SYSLOG = (
    "Jan 15 10:30:00 host01 sshd[1234]: Accepted password for admin from 192.168.1.100 port 22\n"
    "Jan 15 10:31:15 host01 sshd[1235]: Failed password for root from 10.0.0.5 port 22\n"
    "Jan 15 10:32:45 host01 sshd[1236]: session opened for user admin by (uid=0)\n"
    "Jan 15 10:35:00 host01 sudo[1237]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash\n"
    "Jan 15 10:40:00 host01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.200 DST=192.168.1.1\n"
)

SAMPLE_MEMO = (
    "Investigation Memo\n"
    "Date: 2024-01-15\n"
    "Analyst: Taro Yamada\n"
    "\n"
    "Suspicious login activity observed on host01.\n"
    "IP 192.168.1.100 accessed admin account at 10:30 UTC.\n"
    "After gaining access, the attacker escalated privileges using sudo.\n"
    "A file transfer via sftp was observed shortly after.\n"
)


def _write_agent_candidates(case_dir: Path) -> None:
    """Simulate the ir-extract-evidence skill output for the memo artifact.

    Builds candidates whose excerpts are verbatim lines of the ingested memo
    chunk, matching what the agent skill's finalize script would write.
    """
    import hashlib
    import uuid

    chunks_dir = case_dir / "data" / "chunks"
    memo_chunk = None
    for chunk_path in sorted(chunks_dir.glob("*.json")):
        data = json.loads(chunk_path.read_text(encoding="utf-8"))
        if "Suspicious login activity" in data.get("content", ""):
            memo_chunk = data
            break
    assert memo_chunk is not None, "memo chunk not found after ingest"

    lines = memo_chunk["content"].splitlines()

    def line_no(needle: str) -> int:
        for idx, line in enumerate(lines, memo_chunk["start_line"]):
            if needle in line:
                return idx
        raise AssertionError(f"line not found: {needle}")

    def candidate(excerpt_line: str, fact: str, interpretation: str,
                  interp_conf: str, mappings: list) -> dict:
        no = line_no(excerpt_line)
        return {
            "candidate_id": str(uuid.uuid4()),
            "source_refs": [
                {
                    "source_ref_id": str(uuid.uuid4()),
                    "source_file_id": memo_chunk["source_file_id"],
                    "source_path": "memo.txt",
                    "source_lines": [no, no],
                    "excerpt": excerpt_line,
                    "excerpt_sha256": hashlib.sha256(excerpt_line.encode()).hexdigest(),
                }
            ],
            "observed_event": {"raw_summary": excerpt_line},
            "observed_fact": fact,
            "interpretation": interpretation,
            "observed_fact_confidence": "confirmed",
            "interpretation_confidence": interp_conf,
            "attack_mapping_candidates": mappings,
            "from_normalized_event_ids": [],
            "candidate_status": "candidate",
            "review_status": "pending",
        }

    candidates = [
        candidate(
            "Suspicious login activity observed on host01.",
            "IP 192.168.1.100 logged into admin account on host01 via SSH",
            "Possible unauthorized access by external attacker",
            "possible",
            [
                {
                    "tactic": "Initial Access",
                    "technique_id": "T1078",
                    "technique_name": "Valid Accounts",
                    "confidence": "probable",
                    "mapping_reason": "Login with valid credentials from external IP",
                }
            ],
        ),
        candidate(
            "After gaining access, the attacker escalated privileges using sudo.",
            "User admin used sudo to gain root privileges",
            "Likely part of a privilege escalation attack",
            "probable",
            [
                {
                    "tactic": "Privilege Escalation",
                    "technique_id": "T1548",
                    "technique_name": "Abuse Elevation Control Mechanism",
                    "confidence": "probable",
                    "mapping_reason": "sudo used for privilege escalation",
                }
            ],
        ),
    ]
    out = case_dir / "data" / "evidence_candidates.jsonl"
    out.write_text(
        "\n".join(json.dumps(c, ensure_ascii=False) for c in candidates) + "\n",
        encoding="utf-8",
    )


@pytest.fixture
def case_with_artifacts(tmp_path):
    """Create a case directory with sample artifacts ready for the pipeline."""
    case_dir = tmp_path / "integration_case"
    case_dir.mkdir()

    # Create artifacts directory with sample files
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()

    # Sample syslog
    (artifacts_dir / "auth.log").write_text(SAMPLE_SYSLOG, encoding="utf-8")

    # Sample memo (unstructured - will trigger LLM extraction)
    (artifacts_dir / "memo.txt").write_text(SAMPLE_MEMO, encoding="utf-8")

    return case_dir, artifacts_dir


# --- Helper functions ---


def _approve_all_evidence_decisions(review_doc_path: Path) -> None:
    """Edit the evidence review doc to approve all candidates."""
    content = review_doc_path.read_text(encoding="utf-8")
    content = content.replace(
        "decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留",
        "decision: approved",
    )
    content = content.replace('analyst_id: ""', 'analyst_id: "test-analyst"')
    content = content.replace(
        'decision_reason: ""', 'decision_reason: "Approved in integration test"'
    )
    review_doc_path.write_text(content, encoding="utf-8")


def _approve_all_claim_decisions(review_doc_path: Path) -> None:
    """Edit the claim review doc to approve all claims."""
    content = review_doc_path.read_text(encoding="utf-8")
    content = re.sub(
        r"decision: pending\s*#[^\n]*",
        "decision: approved",
        content,
    )
    content = content.replace('analyst_id: ""', 'analyst_id: "test-analyst"')
    content = content.replace(
        'decision_reason: ""', 'decision_reason: "Approved in integration test"'
    )
    review_doc_path.write_text(content, encoding="utf-8")


def _disposition_all_gaps(review_doc_path: Path) -> None:
    """Edit the gap review doc to disposition all gaps as accepted_as_limitation."""
    content = review_doc_path.read_text(encoding="utf-8")
    content = re.sub(
        r"disposition: null\s*#[^\n]*",
        "disposition: accepted_as_limitation",
        content,
    )
    content = content.replace('analyst_id: ""', 'analyst_id: "test-analyst"')
    content = content.replace(
        'disposition_reason: ""',
        'disposition_reason: "Accepted as limitation in integration test"',
    )
    review_doc_path.write_text(content, encoding="utf-8")


def _assert_workflow_phase(case_dir: Path, expected_phase: str) -> None:
    """Assert that the workflow state includes the expected completed phase."""
    state_path = case_dir / "workflow_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert expected_phase in state["completed_phases"], (
        f"Expected '{expected_phase}' in completed_phases, "
        f"got: {state['completed_phases']}"
    )


def _run_pipeline_through_extract(case_dir, artifacts_dir, runner):
    """Run pipeline: init -> ingest -> normalize -> extract-candidates."""
    runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
    runner.invoke(
        cli, ["--case-dir", str(case_dir), "ingest", "--artifacts-dir", str(artifacts_dir)]
    )
    runner.invoke(cli, ["--case-dir", str(case_dir), "normalize-events"])
    _write_agent_candidates(case_dir)
    runner.invoke(cli, ["--case-dir", str(case_dir), "extract-candidates"])


def _run_pipeline_through_claims(case_dir, artifacts_dir, runner):
    """Run pipeline through build-claims step."""
    _run_pipeline_through_extract(case_dir, artifacts_dir, runner)

    # Generate and approve evidence review
    runner.invoke(cli, ["--case-dir", str(case_dir), "review-evidence"])
    reviews_dir = case_dir / "reviews"
    review_files = list(reviews_dir.glob("evidence_review_*.md"))
    if review_files:
        _approve_all_evidence_decisions(review_files[0])

    runner.invoke(
        cli, ["--case-dir", str(case_dir), "promote-evidence", "--analyst-id", "test-analyst"]
    )
    runner.invoke(cli, ["--case-dir", str(case_dir), "build-coverage"])
    runner.invoke(cli, ["--case-dir", str(case_dir), "build-timeline"])
    runner.invoke(cli, ["--case-dir", str(case_dir), "map-attack"])
    runner.invoke(cli, ["--case-dir", str(case_dir), "build-claims"])


# --- Test 1: Full Pipeline End-to-End ---


class TestFullPipelineIntegration:
    """End-to-end integration test of the full IR agent pipeline."""

    def test_full_pipeline_end_to_end(self, case_with_artifacts):
        """Run the full pipeline and verify each state transition."""
        case_dir, artifacts_dir = case_with_artifacts
        runner = CliRunner()

        # Step 1: init
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        assert result.exit_code == 0, f"init failed: {result.output}"
        _assert_workflow_phase(case_dir, "case_initialized")

        # Step 2: ingest
        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "ingest", "--artifacts-dir", str(artifacts_dir)]
        )
        assert result.exit_code == 0, f"ingest failed: {result.output}"
        _assert_workflow_phase(case_dir, "artifacts_ingested")

        # Verify file inventory was created
        inventory_path = case_dir / "data" / "file_inventory.json"
        assert inventory_path.exists()
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        assert len(inventory) >= 2

        # Step 3: normalize-events
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "normalize-events"])
        assert result.exit_code == 0, f"normalize-events failed: {result.output}"
        _assert_workflow_phase(case_dir, "events_normalized")

        # Verify normalized events were created (from syslog)
        events_path = case_dir / "data" / "normalized_events.jsonl"
        assert events_path.exists()
        events_lines = events_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(events_lines) >= 1, "Expected at least 1 normalized event from syslog"

        # Step 4: extract-candidates (validate agent-generated candidates)
        _write_agent_candidates(case_dir)
        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "extract-candidates"]
        )
        assert result.exit_code == 0, f"extract-candidates failed: {result.output}"
        _assert_workflow_phase(case_dir, "evidence_candidates_generated")

        # Verify candidates were extracted
        candidates_path = case_dir / "data" / "evidence_candidates.jsonl"
        assert candidates_path.exists()
        candidates_lines = candidates_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(candidates_lines) >= 1, "Expected agent-generated evidence candidates"

        # Step 5: review-evidence (generates review doc)
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "review-evidence"])
        assert result.exit_code == 0, f"review-evidence failed: {result.output}"

        # Find generated review doc
        reviews_dir = case_dir / "reviews"
        review_files = list(reviews_dir.glob("evidence_review_*.md"))
        assert len(review_files) >= 1, "Expected evidence review document"
        review_doc_path = review_files[0]

        # Step 6: Simulate analyst editing the review doc (approve all candidates)
        _approve_all_evidence_decisions(review_doc_path)

        # Step 7: promote-evidence
        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence", "--analyst-id", "test-analyst"]
        )
        assert result.exit_code == 0, f"promote-evidence failed: {result.output}"
        _assert_workflow_phase(case_dir, "evidence_ledger_approved")

        # Verify evidence ledger
        ledger_path = case_dir / "data" / "evidence_ledger.jsonl"
        assert ledger_path.exists()
        ledger_lines = ledger_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(ledger_lines) >= 1, "Expected entries in evidence ledger"

        # Step 8: build-coverage
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "build-coverage"])
        assert result.exit_code == 0, f"build-coverage failed: {result.output}"
        _assert_workflow_phase(case_dir, "data_coverage_built")

        # Step 9: build-timeline
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "build-timeline"])
        assert result.exit_code == 0, f"build-timeline failed: {result.output}"
        _assert_workflow_phase(case_dir, "timeline_built")

        # Step 10: map-attack
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "map-attack"])
        assert result.exit_code == 0, f"map-attack failed: {result.output}"
        _assert_workflow_phase(case_dir, "attack_mapped")

        # Step 11: build-claims
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "build-claims"])
        assert result.exit_code == 0, f"build-claims failed: {result.output}"
        _assert_workflow_phase(case_dir, "claims_generated")

        # Verify claims were generated
        claims_path = case_dir / "data" / "claims.jsonl"
        assert claims_path.exists()
        claims_lines = claims_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(claims_lines) >= 1, "Expected at least 1 claim"

        # Step 12: review-claims
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "review-claims"])
        assert result.exit_code == 0, f"review-claims failed: {result.output}"

        # Simulate analyst approving all claims
        claim_review_files = list(reviews_dir.glob("claim_review_*.md"))
        assert len(claim_review_files) >= 1
        _approve_all_claim_decisions(claim_review_files[0])

        # Step 13: apply-claim-review
        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "apply-claim-review", "--analyst-id", "test-analyst"]
        )
        assert result.exit_code == 0, f"apply-claim-review failed: {result.output}"
        _assert_workflow_phase(case_dir, "claims_reviewed")

        # Step 14: check-gaps
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "check-gaps"])
        assert result.exit_code == 0, f"check-gaps failed: {result.output}"
        _assert_workflow_phase(case_dir, "gaps_checked")

        # Step 15: review-gaps and apply-gap-disposition
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "review-gaps"])
        if result.exit_code == 0:
            gap_review_files = list(reviews_dir.glob("gap_review_*.md"))
            if gap_review_files:
                _disposition_all_gaps(gap_review_files[0])

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "apply-gap-disposition", "--analyst-id", "test-analyst"]
        )
        assert result.exit_code == 0, f"apply-gap-disposition failed: {result.output}"
        _assert_workflow_phase(case_dir, "gaps_dispositioned")

        # Step 16: plan-report
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "plan-report"])
        assert result.exit_code == 0, f"plan-report failed: {result.output}"

        # Verify report plan was created
        plan_path = case_dir / "reviews" / "report_plan.md"
        assert plan_path.exists(), "report_plan.md not created"

        # Step 17: approve-report-plan
        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "approve-report-plan", "--analyst-id", "test-analyst"]
        )
        assert result.exit_code == 0, f"approve-report-plan failed: {result.output}"
        _assert_workflow_phase(case_dir, "report_plan_approved")

        # Step 18: draft-report
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "draft-report"])
        assert result.exit_code == 0, f"draft-report failed: {result.output}"
        _assert_workflow_phase(case_dir, "draft_report_generated")

        # Verify draft report was created
        draft_path = case_dir / "reports" / "draft_report.md"
        assert draft_path.exists(), "draft_report.md not created"
        draft_content = draft_path.read_text(encoding="utf-8")
        assert len(draft_content) > 0, "Draft report is empty"

        # The human fills the reviewer sections (approve-draft refuses empty ones);
        # the check record stands in for re-running check-draft on that text.
        from ir_agent.reporting.draft_lint import REVIEW_COMMENT_SECTIONS
        from ir_agent.reporting.draft_record import draft_sha256, write_check_record

        filled = draft_content
        for heading in REVIEW_COMMENT_SECTIONS:
            filled = re.sub(rf"(?m)^{re.escape(heading)}[ \t]*$",
                            heading + "\n\nレビュー担当者が記入した内容です。", filled, count=1)
        draft_path.write_text(filled, encoding="utf-8")
        write_check_record(case_dir / "reports", draft_sha256(draft_path), "check-draft", [])

        # Step 19: approve-draft (requires a quality review of this exact draft)

        (case_dir / "reviews" / "quality_review_001.md").write_text(
            f"- 対象ドラフト SHA-256: {draft_sha256(draft_path)}\n", encoding="utf-8")
        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "approve-draft", "--analyst-id", "test-analyst"]
        )
        assert result.exit_code == 0, f"approve-draft failed: {result.output}"
        _assert_workflow_phase(case_dir, "draft_report_approved")

        # Step 20: finalize-report
        # The rubric check may produce critical failures for minimal test data
        # (missing required sections like investigation scope, evidence list, etc.)
        # Override rubric_check.json to pass the guard
        rubric_check_path = case_dir / "reports" / "rubric_check.json"
        rubric_override = {
            "items": [],
            "critical_failures": [],
            "audit_log_valid": True,
            "passed_items": [],
            "failed_items": [],
            "warnings": [],
        }
        rubric_check_path.write_text(
            json.dumps(rubric_override, ensure_ascii=False), encoding="utf-8"
        )

        result = runner.invoke(
            cli, ["--case-dir", str(case_dir), "finalize-report", "--analyst-id", "test-analyst"]
        )
        assert result.exit_code == 0, f"finalize-report failed: {result.output}"
        _assert_workflow_phase(case_dir, "final_report_generated")

        # Verify final report was created
        final_path = case_dir / "reports" / "final_report.md"
        assert final_path.exists(), "final_report.md not created"
        final_content = final_path.read_text(encoding="utf-8")
        assert len(final_content) > 0, "Final report is empty"

        # Verify audit log has entries for all operations
        audit_path = case_dir / "logs" / "audit.jsonl"
        assert audit_path.exists()
        audit_lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(audit_lines) >= 5, "Expected multiple audit log entries"


# --- Test 2: Round-Trip Review Document ---


class TestRoundTripReview:
    """Test round-trip: generate review doc -> analyst edits -> parse decisions."""

    def test_evidence_review_roundtrip(self, case_with_artifacts):
        """Generate evidence review doc, simulate edits, verify parsing."""
        case_dir, artifacts_dir = case_with_artifacts
        runner = CliRunner()

        # Set up pipeline through extract-candidates
        _run_pipeline_through_extract(case_dir, artifacts_dir, runner)

        # Generate review document
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "review-evidence"])
        assert result.exit_code == 0

        # Find the review doc
        reviews_dir = case_dir / "reviews"
        review_files = list(reviews_dir.glob("evidence_review_*.md"))
        assert len(review_files) >= 1
        review_doc_path = review_files[0]

        # Read original content
        original_content = review_doc_path.read_text(encoding="utf-8")

        # Verify it has YAML blocks
        yaml_blocks = re.findall(r"```yaml\s*\n(.*?)\n\s*```", original_content, re.DOTALL)
        assert len(yaml_blocks) >= 1, "No YAML blocks found in review document"

        # Find all item_ids from the YAML blocks
        import yaml as yaml_lib

        items = []
        for block in yaml_blocks:
            parsed = yaml_lib.safe_load(block)
            if parsed and "item_id" in parsed:
                items.append(parsed["item_id"])

        # Simulate analyst: approve first candidate, reject second if available
        content = original_content
        if len(items) >= 2:
            # Replace first to approved
            content = content.replace(
                f"item_id: {items[0]}\nitem_type: evidence_candidate\n"
                "decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留\n"
                'decision_reason: ""\n'
                'analyst_id: ""',
                f"item_id: {items[0]}\nitem_type: evidence_candidate\n"
                "decision: approved\n"
                'decision_reason: "Valid evidence of SSH login"\n'
                'analyst_id: "analyst-taro"',
            )
            # Replace second to rejected
            content = content.replace(
                f"item_id: {items[1]}\nitem_type: evidence_candidate\n"
                "decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留\n"
                'decision_reason: ""\n'
                'analyst_id: ""',
                f"item_id: {items[1]}\nitem_type: evidence_candidate\n"
                "decision: rejected\n"
                'decision_reason: "Insufficient evidence"\n'
                'analyst_id: "analyst-taro"',
            )
        elif len(items) == 1:
            content = content.replace(
                "decision: pending  # approved: 承認 | rejected: 却下 | needs_more_context: 保留",
                "decision: approved",
            )
            content = content.replace('analyst_id: ""', 'analyst_id: "analyst-taro"')

        review_doc_path.write_text(content, encoding="utf-8")

        # Parse the edited doc
        from ir_agent.evidence.review_generator import ReviewDocumentGenerator

        generator = ReviewDocumentGenerator()
        decisions = generator.parse_review_doc(review_doc_path)

        # Verify decisions were extracted correctly
        assert len(decisions) >= 1, "Expected at least 1 decision from parsed doc"

        if len(items) >= 2:
            decision_map = {d.item_id: d for d in decisions}
            assert items[0] in decision_map
            assert decision_map[items[0]].decision.value == "approved"
            assert decision_map[items[0]].analyst_id == "analyst-taro"
            assert decision_map[items[0]].decision_reason == "Valid evidence of SSH login"

            assert items[1] in decision_map
            assert decision_map[items[1]].decision.value == "rejected"
            assert decision_map[items[1]].analyst_id == "analyst-taro"
            assert decision_map[items[1]].decision_reason == "Insufficient evidence"
        else:
            assert decisions[0].decision.value == "approved"

    def test_claim_review_roundtrip(self, case_with_artifacts):
        """Generate claim review doc, simulate mixed edits, verify parsing."""
        case_dir, artifacts_dir = case_with_artifacts
        runner = CliRunner()

        # Run pipeline through build-claims
        _run_pipeline_through_claims(case_dir, artifacts_dir, runner)

        # Generate claim review document
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "review-claims"])
        assert result.exit_code == 0

        # Find the review doc
        reviews_dir = case_dir / "reviews"
        claim_review_files = list(reviews_dir.glob("claim_review_*.md"))
        assert len(claim_review_files) >= 1
        review_doc_path = claim_review_files[0]

        content = review_doc_path.read_text(encoding="utf-8")

        # Approve all claims
        content = re.sub(
            r"decision: pending\s*#[^\n]*",
            "decision: approved",
            content,
        )
        content = content.replace('analyst_id: ""', 'analyst_id: "analyst-taro"')
        review_doc_path.write_text(content, encoding="utf-8")

        # Parse the edited claim review doc
        from ir_agent.analysis.claim_review import ClaimReviewService

        service = ClaimReviewService()
        decisions = service.parse_claim_review_doc(review_doc_path)

        # Verify decisions extracted correctly
        assert len(decisions) >= 1, "Expected at least 1 claim decision"
        for decision in decisions:
            assert decision.decision.value == "approved"
            assert decision.analyst_id == "analyst-taro"


# --- Test 3: Expression Policy (Japanese) ---


class TestExpressionPolicy:
    """Test Japanese expression policy wording per confidence and category."""

    def test_japanese_expression_policy_in_draft(self, case_with_artifacts):
        """Verify Japanese draft report uses correct wording per confidence level."""
        case_dir, artifacts_dir = case_with_artifacts
        runner = CliRunner()

        # Set up the case with init
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        # Write a manifest with Japanese expression policy
        manifest_content = _create_manifest_with_expression_policy()
        (case_dir / "manifest.yaml").write_text(manifest_content, encoding="utf-8")

        # Run pipeline through draft-report
        runner.invoke(
            cli, ["--case-dir", str(case_dir), "ingest", "--artifacts-dir", str(artifacts_dir)]
        )
        runner.invoke(cli, ["--case-dir", str(case_dir), "normalize-events"])

        _write_agent_candidates(case_dir)
        runner.invoke(cli, ["--case-dir", str(case_dir), "extract-candidates"])

        # Generate and approve evidence
        runner.invoke(cli, ["--case-dir", str(case_dir), "review-evidence"])
        reviews_dir = case_dir / "reviews"
        review_files = list(reviews_dir.glob("evidence_review_*.md"))
        if review_files:
            _approve_all_evidence_decisions(review_files[0])

        runner.invoke(
            cli, ["--case-dir", str(case_dir), "promote-evidence", "--analyst-id", "test-analyst"]
        )
        runner.invoke(cli, ["--case-dir", str(case_dir), "build-coverage"])
        runner.invoke(cli, ["--case-dir", str(case_dir), "build-timeline"])
        runner.invoke(cli, ["--case-dir", str(case_dir), "map-attack"])
        runner.invoke(cli, ["--case-dir", str(case_dir), "build-claims"])

        # Approve claims
        runner.invoke(cli, ["--case-dir", str(case_dir), "review-claims"])
        claim_review_files = list(reviews_dir.glob("claim_review_*.md"))
        if claim_review_files:
            _approve_all_claim_decisions(claim_review_files[0])

        runner.invoke(
            cli, ["--case-dir", str(case_dir), "apply-claim-review", "--analyst-id", "test-analyst"]
        )

        # Check gaps and disposition
        runner.invoke(cli, ["--case-dir", str(case_dir), "check-gaps"])
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "review-gaps"])
        if result.exit_code == 0:
            gap_review_files = list(reviews_dir.glob("gap_review_*.md"))
            if gap_review_files:
                _disposition_all_gaps(gap_review_files[0])

        runner.invoke(
            cli, ["--case-dir", str(case_dir), "apply-gap-disposition", "--analyst-id", "test-analyst"]
        )

        # Plan and approve report
        runner.invoke(cli, ["--case-dir", str(case_dir), "plan-report"])
        runner.invoke(
            cli, ["--case-dir", str(case_dir), "approve-report-plan", "--analyst-id", "test-analyst"]
        )

        # Generate draft report
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "draft-report"])
        assert result.exit_code == 0, f"draft-report failed: {result.output}"

        # Verify Japanese expression policy
        draft_path = case_dir / "reports" / "draft_report.md"
        assert draft_path.exists()
        draft_content = draft_path.read_text(encoding="utf-8")

        # The draft report should be in Japanese
        assert len(draft_content) > 0, "Draft report is empty"

        # Check that prohibited expressions from our policy are NOT present
        # We set these as prohibited for 'possible' confidence
        assert "\u65ad\u5b9a\u3059\u308b" not in draft_content, (
            "Prohibited expression found in draft report"
        )

        # Verify the report is in Japanese (contains Japanese characters)
        has_japanese = bool(re.search(r"[\u3000-\u9FFF]", draft_content))
        assert has_japanese, "Draft report should contain Japanese text"


def _create_manifest_with_expression_policy() -> str:
    """Create a manifest YAML with specific Japanese expression policy."""
    return (
        'case_id: "integration_case"\n'
        'case_name: "Integration Test Case"\n'
        'scope: "Test investigation scope"\n'
        "hosts:\n"
        '  - "host01"\n'
        '  - "host02"\n'
        "time_range:\n"
        '  start: "2024-01-01T00:00:00Z"\n'
        '  end: "2024-12-31T23:59:58Z"\n'
        'report_language: "ja"\n'
        'review_language: "ja"\n'
        'report_timezone: "Asia/Tokyo"\n'
        "rubric: {}\n"
        "expression_policy:\n"
        "  confirmed:\n"
        "    default:\n"
        "      recommended_expressions:\n"
        '        - "\u78ba\u8a8d\u3055\u308c\u305f"\n'
        '        - "\u3067\u3042\u308b\u3053\u3068\u304c\u5224\u660e\u3057\u305f"\n'
        "      prohibited_expressions:\n"
        '        - "\u53ef\u80fd\u6027\u304c\u3042\u308b"\n'
        "    by_category: {}\n"
        "  probable:\n"
        "    default:\n"
        "      recommended_expressions:\n"
        '        - "\u9ad8\u3044\u78ba\u5ea6\u3067"\n'
        '        - "\u3068\u8003\u3048\u3089\u308c\u308b"\n'
        "      prohibited_expressions:\n"
        '        - "\u78ba\u8a8d\u3055\u308c\u305f"\n'
        '        - "\u65ad\u5b9a\u3059\u308b"\n'
        "    by_category: {}\n"
        "  possible:\n"
        "    default:\n"
        "      recommended_expressions:\n"
        '        - "\u53ef\u80fd\u6027\u304c\u3042\u308b"\n'
        '        - "\u306e\u7591\u3044\u304c\u3042\u308b"\n'
        "      prohibited_expressions:\n"
        '        - "\u78ba\u8a8d\u3055\u308c\u305f"\n'
        '        - "\u65ad\u5b9a\u3059\u308b"\n'
        '        - "\u3067\u3042\u308b\u3053\u3068\u304c\u5224\u660e\u3057\u305f"\n'
        "    by_category: {}\n"
        "  unknown:\n"
        "    default:\n"
        "      recommended_expressions:\n"
        '        - "\u4e0d\u660e"\n'
        '        - "\u78ba\u8a8d\u3067\u304d\u306a\u304b\u3063\u305f"\n'
        "      prohibited_expressions:\n"
        '        - "\u78ba\u8a8d\u3055\u308c\u305f"\n'
        '        - "\u65ad\u5b9a\u3059\u308b"\n'
        "    by_category: {}\n"
        "  not_observed:\n"
        "    default:\n"
        "      recommended_expressions:\n"
        '        - "\u89b3\u6e2c\u3055\u308c\u306a\u304b\u3063\u305f"\n'
        '        - "\u691c\u51fa\u3055\u308c\u306a\u304b\u3063\u305f"\n'
        "      prohibited_expressions:\n"
        '        - "\u5b58\u5728\u3057\u306a\u3044"\n'
        '        - "\u65ad\u5b9a\u3059\u308b"\n'
        "    by_category: {}\n"
        "llm_config:\n"
        '  provider: "openai"\n'
        '  model: "gpt-4o"\n'
        "  temperature: 0.1\n"
        "  max_tokens: 4096\n"
        "  retry_max_attempts: 3\n"
        "  retry_base_delay: 1.0\n"
        "max_chunk_size: 3000\n"
        "chunk_overlap: 50\n"
    )


# --- Test 4: Workflow Enforcement ---


class TestWorkflowEnforcement:
    """Test that workflow enforcement blocks out-of-order CLI commands."""

    def test_cannot_run_normalize_without_ingest(self, tmp_path):
        """normalize-events should fail without artifacts_ingested phase."""
        case_dir = tmp_path / "enforcement_case"
        runner = CliRunner()
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "normalize-events"])
        assert result.exit_code != 0 or "Error" in result.output

    def test_cannot_run_extract_without_ingest(self, case_with_artifacts):
        """extract-candidates should fail without artifacts_ingested phase."""
        case_dir, artifacts_dir = case_with_artifacts
        runner = CliRunner()
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "extract-candidates"])
        assert result.exit_code != 0 or "Error" in result.output

    def test_cannot_run_promote_without_candidates(self, tmp_path):
        """promote-evidence should fail without evidence_candidates_generated phase."""
        case_dir = tmp_path / "enforcement_case2"
        runner = CliRunner()
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "promote-evidence"])
        assert result.exit_code != 0 or "Error" in result.output

    def test_cannot_run_build_claims_without_attack_mapped(self, case_with_artifacts):
        """build-claims should fail without attack_mapped phase."""
        case_dir, artifacts_dir = case_with_artifacts
        runner = CliRunner()
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])
        runner.invoke(
            cli, ["--case-dir", str(case_dir), "ingest", "--artifacts-dir", str(artifacts_dir)]
        )
        runner.invoke(cli, ["--case-dir", str(case_dir), "normalize-events"])

        _write_agent_candidates(case_dir)
        runner.invoke(cli, ["--case-dir", str(case_dir), "extract-candidates"])

        # Try to build-claims without doing review -> promote -> coverage -> timeline -> map-attack
        result = runner.invoke(cli, ["--case-dir", str(case_dir), "build-claims"])
        assert result.exit_code != 0 or "Error" in result.output

    def test_cannot_run_draft_report_without_plan_approved(self, tmp_path):
        """draft-report should fail without report_plan_approved phase."""
        case_dir = tmp_path / "enforcement_case3"
        runner = CliRunner()
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "draft-report"])
        assert result.exit_code != 0 or "Error" in result.output

    def test_cannot_run_finalize_without_draft_approved(self, tmp_path):
        """finalize-report should fail without draft_report_approved phase."""
        case_dir = tmp_path / "enforcement_case4"
        runner = CliRunner()
        runner.invoke(cli, ["--case-dir", str(case_dir), "init"])

        result = runner.invoke(cli, ["--case-dir", str(case_dir), "finalize-report"])
        assert result.exit_code != 0 or "Error" in result.output
