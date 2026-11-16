#!/usr/bin/env python3
"""Shared atomic-write and diagnosable-read helpers for ir-review-report scripts.

Every generator script in this skill writes JSON or Markdown artifacts that a
later step depends on. If a script is killed, crashes, or the disk fills up
partway through a plain ``Path.write_text`` call, the target file is left
truncated or half-written. The next script to read it then fails with a
confusing JSON-parse error, and there is no way to tell "this was never run"
from "this run was interrupted".

``atomic_write_text`` / ``atomic_write_json`` avoid that: they write to a
temporary file in the same directory (so the rename is on the same
filesystem) and atomically replace the target only once the write is
complete. A reader therefore only ever sees the previous complete version or
the new complete version, never a partial one.

On the read side, ``load_json_safe`` / ``describe_json_problem`` exist because
a bare ``json.loads(path.read_text())`` failure — an uncaught
``JSONDecodeError``, or a downstream "must be a JSON object" message with no
detail — has repeatedly cost an Agent many turns re-reading a file it could
not see was broken (wrong top-level type, empty, or a genuine syntax error).
Every script in this skill that reads an Agent-editable JSON artifact should
use these instead of a bare ``json.loads`` so the failure names its own cause.

This module has no third-party dependencies and is imported the same way
sibling scripts already import ``parse_checklists`` — Python puts a script's
own directory on ``sys.path``, so no package installation is required.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

# review_status.py sets this for every process it starts. Scripts that only make
# sense as steps of its pipeline call require_via_review_status() so that a
# stuck Agent cannot "route around" review_status.py by running them one by
# one (which skips the stages, the skeletons, and the repair guidance).
_VIA_STATUS_ENV = "IR_REVIEW_VIA_STATUS"


def mark_via_review_status() -> None:
    """Called by review_status.py: child scripts it starts are allowed to run."""
    os.environ[_VIA_STATUS_ENV] = "1"


def require_via_review_status(script_name: str) -> None:
    """Exit unless this process was started by review_status.py."""
    if os.environ.get(_VIA_STATUS_ENV) == "1":
        return
    print(
        f"error: {script_name} は単独では実行しません。review_status.py が必要な段階で"
        "自動的に実行します。次のコマンドを実行し、その出力（NEXT STEP）の指示に従って"
        "ください:\n"
        "  python .claude/skills/ir-review-report/scripts/review_status.py "
        "--review-dir <レビューフォルダ> --mode <customer|reporter>\n"
        "進めない場合は、他のスクリプトで回避せず、状況をユーザーに報告して止まってください。",
        file=sys.stderr,
    )
    raise SystemExit(2)


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write ``text`` to ``path`` atomically, creating parent dirs as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_json(
    path: Path,
    data: Any,
    *,
    indent: int = 2,
    ensure_ascii: bool = False,
    trailing_newline: bool = True,
) -> None:
    """Serialize ``data`` as JSON and write it to ``path`` atomically."""
    text = json.dumps(data, ensure_ascii=ensure_ascii, indent=indent)
    if trailing_newline:
        text += "\n"
    atomic_write_text(path, text)


def describe_json_problem(path: Path) -> str:
    """One-line, Japanese, actionable reason a JSON file failed to load.

    Distinguishes the three cases an Agent actually needs to react to
    differently: the file is missing/unreadable (check the path), it has a
    genuine syntax error (re-run the generator script, don't hand-patch it),
    or it parses fine but is the wrong shape (e.g. a list where an object was
    expected — say so instead of a generic "must be a JSON object").
    """
    path = Path(path)
    if not path.exists():
        return "ファイルが存在しません"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"読み込めません（{exc}）"
    if not text.strip():
        return "ファイルが空です"
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return f"JSON 構文エラー: {exc.msg}（{exc.lineno}行目 {exc.colno}列目）"
    return "解析はできましたが、想定した形式（JSON object）ではありません"


def load_json_safe(path: Path) -> tuple[Any, str | None]:
    """Load JSON from ``path``, never raising.

    Returns ``(data, None)`` on success, or ``(None, reason)`` on failure
    where ``reason`` is the same text ``describe_json_problem`` would give —
    computed without re-reading the file twice in the common (successful)
    case.
    """
    path = Path(path)
    if not path.exists():
        return None, "ファイルが存在しません"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"読み込めません（{exc}）"
    if not text.strip():
        return None, "ファイルが空です"
    try:
        return json.loads(text), None
    except json.JSONDecodeError as exc:
        return None, f"JSON 構文エラー: {exc.msg}（{exc.lineno}行目 {exc.colno}列目）"
