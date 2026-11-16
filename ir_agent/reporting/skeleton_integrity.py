"""Verify that the draft's skeleton is the one the skill scripts generate.

check-draft compares the draft against reports/draft_skeleton.md to make sure
the fixed (non-【要記入】) lines survive drafting. That only holds if the
skeleton itself is untouched, so this rebuilds reports/case_material.json from
the case records and re-renders the skeleton from it (dated as the skeleton's
0.1 history row), and reports any difference.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path
from types import ModuleType

SCRIPTS_DIR = (Path(__file__).resolve().parents[2]
               / ".claude" / "skills" / "ir-draft-report" / "scripts")
_FIRST_ROW = re.compile(r"(?m)^\|\s*0\.1\s*\|\s*(\d{4}-\d{2}-\d{2})\s*\|")
_REBUILD = ("reports/case_material.json と reports/draft_skeleton.md は手で編集せず、"
            "draft_report.md を退避してから build_case_material.py で作り直す")


def _load(name: str) -> ModuleType | None:
    path = SCRIPTS_DIR / f"{name}.py"
    if not path.exists():
        return None
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    spec = importlib.util.spec_from_file_location(f"_ir_draft_{name}", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _first_diff(a: str, b: str) -> str:
    for n, (x, y) in enumerate(zip(a.splitlines(), b.splitlines()), 1):
        if x != y:
            return f"{n} 行目: {y[:60]!r}"
    return "行数が異なる"


def integrity_problems(case_dir: Path) -> list[str]:
    """Why the case material or the skeleton differs from a fresh generation."""
    reports = case_dir / "reports"
    material_path = reports / "case_material.json"
    skeleton_path = reports / "draft_skeleton.md"
    if not material_path.exists() or not skeleton_path.exists():
        return []
    builder, skeleton_mod = _load("build_case_material"), _load("build_draft_skeleton")
    if builder is None or skeleton_mod is None:
        return []

    problems = []
    material = json.loads(material_path.read_text(encoding="utf-8"))
    if builder.build_material(case_dir) != material:
        problems.append("reports/case_material.json が承認済みの記録から生成し直した内容と"
                        f"一致しない(承認後に記録が変わったか、手で編集された)。{_REBUILD}")
        return problems

    skeleton = skeleton_path.read_text(encoding="utf-8")
    m = _FIRST_ROW.search(skeleton)
    if not m:
        return [f"reports/draft_skeleton.md に版数 0.1 の改訂履歴行がない。{_REBUILD}"]
    tz = skeleton_mod._zone(material.get("case", {}).get("report_timezone", "UTC"))
    day = date.fromisoformat(m.group(1))
    expected = skeleton_mod.render(material, case_dir,
                                   now=datetime(day.year, day.month, day.day, 12, tzinfo=tz))
    if expected != skeleton:
        problems.append("reports/draft_skeleton.md が CLI 生成の雛形と一致しない"
                        f"({_first_diff(expected, skeleton)})。{_REBUILD}")
    return problems
