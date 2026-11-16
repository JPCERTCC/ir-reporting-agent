"""Bind draft approval to the exact draft content that passed the checks.

``check-draft`` (or the deterministic ``draft-report``) records the SHA-256 of
the draft it validated in reports/draft_check.json; ``approve-draft`` accepts
only that content and records it in reports/draft_approval.json;
``finalize-report`` refuses a draft edited after approval. A human therefore
always approves — and finalizes — the text that was actually checked.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHECK_FILE = "draft_check.json"
APPROVAL_FILE = "draft_approval.json"


def draft_sha256(draft_path: Path) -> str:
    return hashlib.sha256(draft_path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def write_check_record(reports_dir: Path, sha256: str, checker: str,
                       failures: list[str]) -> Path:
    path = reports_dir / CHECK_FILE
    path.write_text(json.dumps({
        "sha256": sha256,
        "checker": checker,
        "passed": not failures,
        "failures": failures,
        "checked_at": _now(),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def check_problem(reports_dir: Path, sha256: str) -> str | None:
    """Why the current draft may not be approved yet, or None."""
    record = _read(reports_dir / CHECK_FILE)
    if record is None:
        return "ドラフトの検査記録がありません。'check-draft' を実行してください"
    if record.get("sha256") != sha256:
        return ("検査後にドラフトが変更されています。"
                "'check-draft' を再実行してから承認してください")
    if not record.get("passed"):
        return "最新の 'check-draft' が FAIL しています。修正して再実行してください"
    return None


def write_approval_record(reports_dir: Path, sha256: str, analyst_id: str) -> Path:
    path = reports_dir / APPROVAL_FILE
    path.write_text(json.dumps({
        "sha256": sha256, "analyst_id": analyst_id, "approved_at": _now(),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def approval_problem(reports_dir: Path, sha256: str) -> str | None:
    record = _read(reports_dir / APPROVAL_FILE)
    if record is None:
        return "ドラフトの承認記録がありません。'approve-draft' を実行してください"
    if record.get("sha256") != sha256:
        return ("承認後にドラフトが変更されています。"
                "'check-draft' と 'approve-draft' をやり直してください")
    return None


def has_quality_review(case_dir: Path, sha256: str) -> bool:
    return any(sha256 in p.read_text(encoding="utf-8", errors="replace")
               for p in (case_dir / "reviews").glob("quality_review_*.md"))


def approved_by(reports_dir: Path) -> str:
    """The analyst_id recorded by approve-draft ("" when there is no record)."""
    record = _read(reports_dir / APPROVAL_FILE) or {}
    return str(record.get("analyst_id") or "")
