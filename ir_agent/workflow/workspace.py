"""Where agents may put their own work files.

Agents write ad-hoc scripts and intermediate notes while running a case. Those
files must not mix with the case's records, so the rule is:

- Inside a case, only the standard layout is allowed at the top level, and
  agent work files (scripts, notes, intermediate JSON) go under ``_scratch/``.
- Scripts (``*.py`` / ``*.sh``) never live elsewhere in the case: the CLI and
  the skills' bundled scripts are the only code that writes case records.
- In the repository, agent work files go to the session scratchpad, not to the
  repository root or the skills' directories (a skill holds only SKILL.md,
  MAINTAINERS.md and its scripts/, references/, assets/, agents/ folders).

``stray_case_entries`` is a check-draft failure; ``stray_repo_files`` is a
status warning only, because the repository may legitimately be mid-edit.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

CASE_SCRATCH = "_scratch"
CASE_LAYOUT = frozenset({
    "manifest.yaml", "workflow_state.json", "README.md", "artifacts", "data", "reviews",
    "reports", "logs", CASE_SCRATCH,
})
SCRIPT_SUFFIXES = (".py", ".sh")
# What a skill directory may hold; anything else in it is an agent's leftover.
SKILL_LAYOUT_DIRS = frozenset({"scripts", "references", "assets", "agents"})
SKILL_LAYOUT_FILES = frozenset({"SKILL.md", "MAINTAINERS.md"})
_IGNORED_NAMES = frozenset({".DS_Store", "Thumbs.db", "Desktop.ini", "__pycache__"})


def stray_case_entries(case_dir: Path) -> list[str]:
    """Case-relative paths that break the case layout rule."""
    if not case_dir.is_dir():
        return []
    stray = [p.name for p in sorted(case_dir.iterdir())
             if p.name not in CASE_LAYOUT and p.name not in _IGNORED_NAMES]
    for sub in sorted(CASE_LAYOUT - {CASE_SCRATCH, "artifacts"}):
        root = case_dir / sub
        if not root.is_dir():
            continue
        stray += [str(p.relative_to(case_dir)) for p in sorted(root.rglob("*"))
                  if p.is_file() and p.suffix in SCRIPT_SUFFIXES]
    return stray


def stray_repo_files(repo_root: Path) -> list[str]:
    """Untracked, non-ignored files at the repo root or under .claude/skills/."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "--others", "--exclude-standard"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    return [rel for rel in proc.stdout.splitlines()
            if "/" not in rel or _outside_skill_layout(rel)]


def _outside_skill_layout(rel: str) -> bool:
    parts = rel.split("/")
    if parts[:2] != [".claude", "skills"] or len(parts) < 4:
        return False
    inner = parts[3:]  # path inside .claude/skills/<skill>/
    if len(inner) == 1:
        return inner[0] not in SKILL_LAYOUT_FILES
    return inner[0] not in SKILL_LAYOUT_DIRS


def case_layout_message(stray: list[str]) -> str:
    shown = "、".join(stray[:10]) + (f" ほか {len(stray) - 10} 件" if len(stray) > 10 else "")
    return (f"ケースディレクトリに規定外のファイルがあります: {shown}。"
            f"作業ファイルは <case-dir>/{CASE_SCRATCH}/ に置いてください"
            "(スクリプトはケース内の他の場所に置かない)")
