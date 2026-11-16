"""Detect a manifest that still carries the ``ir-agent init`` template values.

The scope, hosts and time range drive coverage, gaps and the report itself, so a
template manifest silently produces fake gaps (``host01`` has no data) and a
report titled "Untitled Case". ``ingest`` and ``check-gaps`` refuse to run on
one, ``check-draft`` fails, and ``status`` tells the agent to ask the human.
"""

from __future__ import annotations

from ir_agent.steering.manifest import CaseManifest

TEMPLATE_CASE_NAME = "Untitled Case"
TEMPLATE_SCOPE = "Define investigation scope here"
TEMPLATE_HOSTS = ["host01"]
TEMPLATE_TIME_RANGE = ("2024-01-01T00:00:00Z", "2024-12-31T23:59:59Z")


def template_problems(manifest: CaseManifest) -> list[str]:
    """Fields of ``manifest`` still left at (or emptied from) the init template."""
    problems = []
    if not manifest.case_name.strip() or manifest.case_name == TEMPLATE_CASE_NAME:
        problems.append(f"case_name が未設定です({manifest.case_name!r})")
    if not manifest.scope.strip() or manifest.scope == TEMPLATE_SCOPE:
        problems.append(f"scope が未設定です({manifest.scope!r})")
    if not manifest.hosts or manifest.hosts == TEMPLATE_HOSTS:
        problems.append(f"hosts が未設定です({manifest.hosts!r})")
    if (manifest.time_range.start, manifest.time_range.end) == TEMPLATE_TIME_RANGE:
        problems.append("time_range がテンプレートの既定値(2024 年通年)のままです")
    return problems


def template_message(problems: list[str]) -> str:
    return (
        "manifest.yaml がテンプレートのままです: " + "; ".join(problems) + "。"
        "ケース名・調査範囲・対象ホスト・調査対象期間を人間に確認して manifest.yaml に"
        "記入してから再実行してください(推測で埋めない)。"
    )
