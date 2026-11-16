"""Audit Logger for the Governance Layer.

Provides append-only audit logging to ``logs/audit.jsonl`` within the case
directory. All operations, approvals, and LLM calls are logged. If an audit
log write fails, the current operation is halted immediately.

Requirements: 20.1, 20.2, 20.3, 20.4, 20.5
"""

from __future__ import annotations

import logging
from pathlib import Path

from ir_agent.models.governance import ApprovalEntry, AuditEntry, LLMCallEntry
from ir_agent.storage.store import AppendOnlyStore

logger = logging.getLogger(__name__)


class AuditWriteError(RuntimeError):
    """Raised when the audit log cannot be written, halting the operation."""

    pass


class AuditLogger:
    """Append-only audit logger writing to ``logs/audit.jsonl``.

    Design invariants:
    - Every significant operation is logged (Requirement 20.1).
    - Every human approval decision is logged (Requirement 20.2).
    - Every LLM API call is logged with prompt_hash, response_hash,
      and token_count (Requirement 20.3).
    - Logs are stored in append-only JSONL format (Requirement 20.4).
    - If a write fails, the current operation is halted (Requirement 20.5).
    """

    AUDIT_LOG_RELATIVE_PATH = Path("logs") / "audit.jsonl"

    def __init__(self, case_dir: Path) -> None:
        """Initialize the AuditLogger for a given case directory.

        Args:
            case_dir: Path to the case working directory. The audit log will
                be written to ``<case_dir>/logs/audit.jsonl``.
        """
        self._case_dir = case_dir
        self._audit_log_path = case_dir / self.AUDIT_LOG_RELATIVE_PATH

        # We use three separate AppendOnlyStore instances because each entry
        # type has a different Pydantic model, but they all write to the same
        # physical file. To keep things simple and consistent with the design
        # (single audit.jsonl), we use a unified approach: serialize manually
        # so all entry types coexist in one file.
        self._operation_store = AppendOnlyStore(
            file_path=self._audit_log_path, model_class=AuditEntry
        )
        self._approval_store = AppendOnlyStore(
            file_path=self._audit_log_path, model_class=ApprovalEntry
        )
        self._llm_call_store = AppendOnlyStore(
            file_path=self._audit_log_path, model_class=LLMCallEntry
        )

    @property
    def audit_log_path(self) -> Path:
        """Return the path to the audit log file."""
        return self._audit_log_path

    def ensure_writable(self) -> None:
        """Verify that the audit log can be written to.

        Creates the parent directory if it does not exist, then attempts a
        probe write to confirm the file system is accessible and writable.

        Raises:
            AuditWriteError: If the audit log path is not writable, halting
                the calling operation (Requirement 20.5).
        """
        try:
            self._audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            # Probe write: open in append mode to confirm writability without
            # altering existing content.
            with open(self._audit_log_path, "a", encoding="utf-8") as f:
                f.flush()
        except OSError as exc:
            msg = (
                f"Audit log is not writable at {self._audit_log_path}: {exc}. "
                "Operation halted per Requirement 20.5."
            )
            logger.error(msg)
            raise AuditWriteError(msg) from exc

    def log_operation(self, entry: AuditEntry) -> None:
        """Log a general operation entry to the audit log.

        Records every significant operation performed by the Agent including
        timestamp, operation_type, input_summary, output_summary, and status.

        Args:
            entry: A validated AuditEntry instance.

        Raises:
            AuditWriteError: If the write fails, halting the operation.
        """
        self._safe_append(self._operation_store, entry)

    def log_approval(self, entry: ApprovalEntry) -> None:
        """Log a human approval decision to the audit log.

        Records approval decisions with timestamp, analyst_id, item_type,
        item_id, decision, and reason.

        Args:
            entry: A validated ApprovalEntry instance.

        Raises:
            AuditWriteError: If the write fails, halting the operation.
        """
        self._safe_append(self._approval_store, entry)

    def log_llm_call(self, entry: LLMCallEntry) -> None:
        """Log an LLM API call to the audit log.

        Records LLM interactions with timestamp, prompt_hash, model_used,
        token_count, response_hash, provider, and temperature.

        Args:
            entry: A validated LLMCallEntry instance.

        Raises:
            AuditWriteError: If the write fails, halting the operation.
        """
        self._safe_append(self._llm_call_store, entry)

    def _safe_append(self, store: AppendOnlyStore, entry) -> None:  # type: ignore[type-arg]
        """Append an entry to the store, converting OS errors to AuditWriteError.

        This ensures that any write failure halts the current operation
        (Requirement 20.5).

        Args:
            store: The AppendOnlyStore instance to write to.
            entry: The Pydantic model entry to append.

        Raises:
            AuditWriteError: If the underlying write fails.
        """
        try:
            store.append(entry)
        except OSError as exc:
            msg = (
                f"Failed to write audit log entry at {self._audit_log_path}: {exc}. "
                "Operation halted per Requirement 20.5."
            )
            logger.error(msg)
            raise AuditWriteError(msg) from exc
