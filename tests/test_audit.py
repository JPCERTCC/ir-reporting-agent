"""Unit tests for the AuditLogger class.

Tests cover:
- log_operation appending AuditEntry to logs/audit.jsonl
- log_approval appending ApprovalEntry
- log_llm_call appending LLMCallEntry with prompt_hash, response_hash, token_count
- ensure_writable halting when audit log is not writable
- All entries coexisting in the same JSONL file
"""

import json
from pathlib import Path

import pytest

from ir_agent.governance.audit import AuditLogger, AuditWriteError
from ir_agent.models.governance import ApprovalEntry, AuditEntry, LLMCallEntry


@pytest.fixture
def case_dir(tmp_path: Path) -> Path:
    """Provide a temporary case directory."""
    return tmp_path / "case01"


@pytest.fixture
def audit_logger(case_dir: Path) -> AuditLogger:
    """Create an AuditLogger instance with a temp case directory."""
    return AuditLogger(case_dir)


def _make_audit_entry(**overrides) -> AuditEntry:
    defaults = {
        "timestamp": "2024-01-15T10:00:00Z",
        "operation_type": "ingest",
        "input_summary": "artifacts_dir=/path/to/artifacts",
        "output_summary": "processed 5 files",
        "status": "success",
    }
    defaults.update(overrides)
    return AuditEntry(**defaults)


def _make_approval_entry(**overrides) -> ApprovalEntry:
    defaults = {
        "timestamp": "2024-01-15T10:05:00Z",
        "analyst_id": "analyst-01",
        "item_type": "evidence_candidate",
        "item_id": "cand-001",
        "decision": "approved",
        "reason": "Corroborated by syslog",
    }
    defaults.update(overrides)
    return ApprovalEntry(**defaults)


def _make_llm_call_entry(**overrides) -> LLMCallEntry:
    defaults = {
        "timestamp": "2024-01-15T10:02:00Z",
        "prompt_hash": "sha256:abc123",
        "model_used": "gpt-4o",
        "token_count": 1500,
        "response_hash": "sha256:def456",
        "provider": "openai",
        "temperature": 0.1,
    }
    defaults.update(overrides)
    return LLMCallEntry(**defaults)


class TestAuditLoggerLogOperation:
    """Tests for log_operation method (Requirement 20.1)."""

    def test_creates_log_directory_and_file(self, audit_logger: AuditLogger, case_dir: Path):
        entry = _make_audit_entry()
        audit_logger.log_operation(entry)

        log_path = case_dir / "logs" / "audit.jsonl"
        assert log_path.exists()

    def test_appends_operation_entry(self, audit_logger: AuditLogger, case_dir: Path):
        entry = _make_audit_entry(operation_type="normalize-events", status="success")
        audit_logger.log_operation(entry)

        log_path = case_dir / "logs" / "audit.jsonl"
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1

        record = json.loads(lines[0])
        assert record["operation_type"] == "normalize-events"
        assert record["status"] == "success"
        assert record["timestamp"] == "2024-01-15T10:00:00Z"

    def test_multiple_operations_append_in_order(self, audit_logger: AuditLogger, case_dir: Path):
        audit_logger.log_operation(_make_audit_entry(operation_type="op1"))
        audit_logger.log_operation(_make_audit_entry(operation_type="op2"))
        audit_logger.log_operation(_make_audit_entry(operation_type="op3"))

        log_path = case_dir / "logs" / "audit.jsonl"
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3
        assert json.loads(lines[0])["operation_type"] == "op1"
        assert json.loads(lines[1])["operation_type"] == "op2"
        assert json.loads(lines[2])["operation_type"] == "op3"


class TestAuditLoggerLogApproval:
    """Tests for log_approval method (Requirement 20.2)."""

    def test_appends_approval_entry(self, audit_logger: AuditLogger, case_dir: Path):
        entry = _make_approval_entry(decision="rejected", reason="Insufficient evidence")
        audit_logger.log_approval(entry)

        log_path = case_dir / "logs" / "audit.jsonl"
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        record = json.loads(lines[0])

        assert record["analyst_id"] == "analyst-01"
        assert record["decision"] == "rejected"
        assert record["reason"] == "Insufficient evidence"
        assert record["item_type"] == "evidence_candidate"
        assert record["item_id"] == "cand-001"

    def test_approval_without_reason(self, audit_logger: AuditLogger, case_dir: Path):
        entry = _make_approval_entry(reason=None)
        audit_logger.log_approval(entry)

        log_path = case_dir / "logs" / "audit.jsonl"
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        record = json.loads(lines[0])
        assert record["reason"] is None


class TestAuditLoggerLogLLMCall:
    """Tests for log_llm_call method (Requirement 20.3)."""

    def test_appends_llm_call_entry(self, audit_logger: AuditLogger, case_dir: Path):
        entry = _make_llm_call_entry()
        audit_logger.log_llm_call(entry)

        log_path = case_dir / "logs" / "audit.jsonl"
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        record = json.loads(lines[0])

        assert record["prompt_hash"] == "sha256:abc123"
        assert record["response_hash"] == "sha256:def456"
        assert record["token_count"] == 1500
        assert record["model_used"] == "gpt-4o"
        assert record["provider"] == "openai"
        assert record["temperature"] == 0.1

    def test_llm_call_with_high_token_count(self, audit_logger: AuditLogger, case_dir: Path):
        entry = _make_llm_call_entry(token_count=128000)
        audit_logger.log_llm_call(entry)

        log_path = case_dir / "logs" / "audit.jsonl"
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        record = json.loads(lines[0])
        assert record["token_count"] == 128000


class TestAuditLoggerMixedEntries:
    """Tests for mixed entry types coexisting in audit.jsonl (Requirement 20.4)."""

    def test_all_entry_types_in_same_file(self, audit_logger: AuditLogger, case_dir: Path):
        audit_logger.log_operation(_make_audit_entry())
        audit_logger.log_approval(_make_approval_entry())
        audit_logger.log_llm_call(_make_llm_call_entry())

        log_path = case_dir / "logs" / "audit.jsonl"
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3

        # First line is an operation entry
        op = json.loads(lines[0])
        assert "operation_type" in op

        # Second line is an approval entry
        approval = json.loads(lines[1])
        assert "analyst_id" in approval

        # Third line is an LLM call entry
        llm = json.loads(lines[2])
        assert "prompt_hash" in llm


class TestAuditLoggerEnsureWritable:
    """Tests for ensure_writable method (Requirement 20.5)."""

    def test_creates_directory_if_missing(self, audit_logger: AuditLogger, case_dir: Path):
        log_dir = case_dir / "logs"
        assert not log_dir.exists()

        audit_logger.ensure_writable()
        assert log_dir.exists()

    def test_succeeds_when_directory_exists(self, audit_logger: AuditLogger, case_dir: Path):
        log_dir = case_dir / "logs"
        log_dir.mkdir(parents=True)

        # Should not raise
        audit_logger.ensure_writable()

    def test_raises_audit_write_error_on_unwritable_path(self, tmp_path: Path):
        # Use a path that cannot be created (file exists where dir expected)
        blocker = tmp_path / "case02" / "logs"
        blocker.parent.mkdir(parents=True)
        # Create a file where the "logs" directory should be
        blocker.write_text("blocker")

        audit_logger = AuditLogger(tmp_path / "case02")

        with pytest.raises(AuditWriteError):
            audit_logger.ensure_writable()


class TestAuditLoggerHaltOnWriteFailure:
    """Tests that write failures halt operations (Requirement 20.5)."""

    def test_log_operation_raises_on_write_failure(self, tmp_path: Path):
        # Create a directory where the file should be so write fails
        case_dir = tmp_path / "case03"
        log_file = case_dir / "logs" / "audit.jsonl"
        log_file.mkdir(parents=True)  # audit.jsonl is a directory, not a file

        audit_logger = AuditLogger(case_dir)
        entry = _make_audit_entry()

        with pytest.raises(AuditWriteError):
            audit_logger.log_operation(entry)

    def test_log_approval_raises_on_write_failure(self, tmp_path: Path):
        case_dir = tmp_path / "case04"
        log_file = case_dir / "logs" / "audit.jsonl"
        log_file.mkdir(parents=True)

        audit_logger = AuditLogger(case_dir)
        entry = _make_approval_entry()

        with pytest.raises(AuditWriteError):
            audit_logger.log_approval(entry)

    def test_log_llm_call_raises_on_write_failure(self, tmp_path: Path):
        case_dir = tmp_path / "case05"
        log_file = case_dir / "logs" / "audit.jsonl"
        log_file.mkdir(parents=True)

        audit_logger = AuditLogger(case_dir)
        entry = _make_llm_call_entry()

        with pytest.raises(AuditWriteError):
            audit_logger.log_llm_call(entry)
