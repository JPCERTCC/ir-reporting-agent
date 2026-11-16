"""The draft-report template is the single source of the report structure.

templates/report_template_ja.md defines the headings, fixed text, reviewer
fill-in comments and table headers. The skeleton generator copies from it and
the draft lint derives its required headings from it, so changing the report
structure means editing that one Markdown file. ``<…>`` lines in the template
are slots the skeleton fills; ``4.補足`` headings are numbered after the
per-host subsections by the skeleton.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

TEMPLATE_PATH = Path(__file__).parent / "templates" / "report_template_ja.md"
SUPPLEMENT_MARK = "4.補足"
REVIEWER_NOTE = "レビュー担当者記入欄"
_HEADING = re.compile(r"(?m)^(#{1,6}) +(.+?)\s*$")


@lru_cache(maxsize=1)
def template_text() -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8")


def all_headings() -> list[str]:
    return [f"{m.group(1)} {m.group(2)}" for m in _HEADING.finditer(template_text())]


def required_headings() -> list[str]:
    """Headings every draft must contain verbatim (4.補足 ones are renumbered)."""
    return [h for h in all_headings() if SUPPLEMENT_MARK not in h]


def body(heading: str, text: str | None = None) -> str:
    """Text under ``heading`` up to the next heading of any level."""
    text = template_text() if text is None else text
    match = re.search(rf"(?m)^{re.escape(heading)}\s*$", text)
    if not match:
        return ""
    nxt = _HEADING.search(text, match.end())
    return text[match.end(): nxt.start() if nxt else len(text)].strip("\n")


def fixed_body(heading: str) -> str:
    """The section's fixed text with ``<…>`` slot lines and table rows removed."""
    lines = [ln for ln in body(heading).splitlines()
             if not (ln.startswith("<") and ln.endswith(">") and not ln.startswith("<!--"))
             and not ln.startswith("|")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip("\n")


def table_header(heading: str) -> str:
    """The first two table lines (header + separator) under ``heading``."""
    rows = [ln for ln in body(heading).splitlines() if ln.startswith("|")]
    return "\n".join(rows[:2])


def reviewer_sections() -> list[str]:
    """Sections the human reviewer fills in; the draft leaves only the comment."""
    return [h for h in required_headings() if REVIEWER_NOTE in body(h)]


def attack_sections() -> list[tuple[str, str]]:
    """(``3.1``, ``初期侵入``) … from the chapter-3 headings."""
    out = []
    for h in required_headings():
        m = re.match(r"### (3\.\d+) (.+)$", h)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


# Chapter-3 section each ATT&CK tactic is reported under. Execution, Discovery
# and Collection support whichever stage they occur in, so they have no home
# section of their own.
TACTIC_SECTIONS = {
    "Initial Access": "3.1",
    "Credential Access": "3.2",
    "Privilege Escalation": "3.2",
    "Lateral Movement": "3.3",
    "Persistence": "3.4",
    "Command and Control": "3.5",
    "Exfiltration": "3.6",
    "Defense Evasion": "3.7",
}


def cross_section_mappings(claim: dict[str, Any]) -> dict[str, list[str]]:
    """Other chapter-3 sections a claim's ATT&CK mappings belong to.

    Maps section → the supporting evidence of the mappings for that section, for
    a claim routed to a chapter-3 section: a Persistence mapping on a claim
    filed under 3.7 must still be reported in 3.4.
    """
    own = claim.get("report_section")
    if not str(own or "").startswith("3."):
        return {}
    out: dict[str, list[str]] = {}
    for m in claim.get("attack_mappings") or []:
        sec = TACTIC_SECTIONS.get(m.get("tactic") or "")
        evs = m.get("supporting_evidence") or []
        if sec and sec != own and evs:
            out.setdefault(sec, [])
            out[sec] += [e for e in evs if e not in out[sec]]
    return out
