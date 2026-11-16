#!/usr/bin/env python3
"""Parse the bundled IR-report checklists into normalized JSON items.

The checklists (references/checklist_customer.md and checklist_reporter.md) are
the source of truth and are expected to be updated over time. This parser turns
them into a flat list of items the review skill iterates over, so updating the
review criteria only requires editing the markdown — no code changes.

Handles the current checklist format and the legacy formats kept for
backward-compatible tests:
  - current: markdown tables with `項番` as the first column. The checklist
    item number becomes the stable item ID, e.g. `REP-3.5-3`.
  - legacy customer: `* [ ] item` bullets with `  - detail` sub-bullets
  - legacy reporter: markdown tables `| 項目 | 必須・推奨 | 詳細 |` and
    2-column appendix tables `| 項目 | 詳細 |`

Output (stdout, JSON):
  {"items": [
    {"id": "REP-3.1-4", "source": "reporter", "section": "報告書 › 基本",
     "text": "...", "level": "必須|推奨|任意|-", "detail": "...",
     "unknown_allowed": false}
  ]}

IDs are stable when the source checklist has an `項番` column
(`CUS-2.3-2`, `REP-3.5-3`). Legacy rows without `項番` continue to receive
sequential IDs (`CUS-001`, `REP-001`).

Usage:
    python parse_checklists.py --mode customer|reporter|both [--skill-dir <dir>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

LEVELS = {"必須", "推奨", "任意"}
ITEM_NO_RE = re.compile(r"^\d+(?:\.\d+)*(?:-\d+)?$")
LEVEL_TO_REQUIREMENT = {
    "必須": "mandatory",
    "推奨": "recommended",
    "任意": "optional",
    "-": "unspecified",
    "": "unspecified",
}


def _clean(cell: str) -> str:
    return cell.replace("`", "").strip()


def _item_id(prefix: str, item_no: str | None, counter: int) -> str:
    """Return a stable checklist ID when an explicit item number exists."""
    if item_no and ITEM_NO_RE.match(item_no.strip()):
        return f"{prefix}-{item_no.strip()}"
    return f"{prefix}-{counter:03d}"


def _section_path(section: str, subsection: str) -> list[str]:
    return [s for s in (section, subsection) if s]


def _applies_to(section_path: list[str], text: str) -> str:
    joined = " ".join(section_path + [text])
    if re.search(r"事前|合意|契約|提案|着手前|報告要否", joined):
        return "pre_engagement"
    if re.search(r"証拠保全|ハッシュ|改ざん|保全", joined):
        return "evidence_handling"
    if re.search(r"納品|提出|期限|報告時期", joined):
        return "delivery"
    if re.search(r"調査手法|調査方法|ヒアリング|作業", joined):
        return "investigation_process"
    return "report_content"


def _evaluable_from_report(applies_to: str) -> bool:
    return applies_to == "report_content"


def _unknown_allowed(applies_to: str) -> bool:
    """Return whether a checklist item may be left unknown.

    The review agent must decide report-content items from the submitted report:
    if the report lacks required content the correct verdict is not_met or
    partial, not unknown. Unknown is reserved for items that require materials
    outside the report, such as engagement agreements or evidence handling logs.
    """
    return applies_to != "report_content"


def _unknown_reason_type(applies_to: str) -> str | None:
    if applies_to == "report_content":
        return None
    return {
        "pre_engagement": "agreement_or_contract_required",
        "evidence_handling": "evidence_preservation_record_required",
        "investigation_process": "work_or_interview_record_required",
        "delivery": "delivery_or_submission_record_required",
    }.get(applies_to, "external_record_required")


def _item(
    *,
    item_id: str,
    source: str,
    section: str,
    subsection: str,
    text: str,
    level: str,
    detail: str,
    item_no: str | None = None,
) -> dict:
    path = _section_path(section, subsection)
    applies = _applies_to(path, text)
    data = {
        "id": item_id,
        "source": source,
        "section": " › ".join(path),
        "section_path": path,
        "section_context": [],
        "text": text,
        "level": level or "-",
        "requirement_level": LEVEL_TO_REQUIREMENT.get(level or "-", "unspecified"),
        "detail": detail,
        "applies_to": applies,
        "evaluable_from_report": _evaluable_from_report(applies),
        "unknown_allowed": _unknown_allowed(applies),
        "unknown_reason_type": _unknown_reason_type(applies),
        "applicability_condition": None,
    }
    if item_no:
        data["item_no"] = item_no
    return data


def parse_markdown(path: Path, source: str, prefix: str) -> list[dict]:
    items: list[dict] = []
    section = ""
    subsection = ""
    counter = 0

    lines = path.read_text(encoding="utf-8").splitlines()
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()

        # Section headings
        if stripped.startswith("## ") and not stripped.startswith("### "):
            section = stripped[3:].strip()
            subsection = ""
            continue
        if stripped.startswith("### "):
            subsection = stripped[4:].strip()
            continue

        section_path = section if not subsection else f"{section} › {subsection}"

        # Checkbox bullet items (customer checklist)
        m = re.match(r"^\*\s*\[[ xX]?\]\s*(.+)$", stripped)
        if m:
            counter += 1
            items.append(_item(
                item_id=f"{prefix}-{counter:03d}",
                source=source,
                section=section,
                subsection=subsection,
                text=_clean(m.group(1)),
                level="-",
                detail="",
            ))
            continue

        # Sub-bullets become detail for the last checkbox item
        sub = re.match(r"^-\s+(.+)$", stripped)
        if sub and items and items[-1]["source"] == source and items[-1]["level"] == "-":
            extra = _clean(sub.group(1))
            items[-1]["detail"] = (
                extra if not items[-1]["detail"] else items[-1]["detail"] + " / " + extra
            )
            continue

        # Table rows (current and legacy checklist formats)
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            # Skip header rows and separator rows.
            if not cells or set("".join(cells)) <= set("-: "):
                continue
            if cells[0] in ("項番", "項目"):
                continue

            item_no: str | None = None
            level = "-"
            detail = ""

            # Current format:
            #   項番 | 項目 | 区分 | 詳細
            #   項番 | 項目 | 詳細
            #   項番 | 項目
            if len(cells) >= 2 and ITEM_NO_RE.match(cells[0]):
                item_no = cells[0]
                text = _clean(cells[1])
                if len(cells) >= 4 and cells[2] in LEVELS:
                    level = cells[2]
                    detail = _clean(cells[3])
                elif len(cells) >= 3:
                    detail = _clean(cells[2])
                counter += 1
                items.append(_item(
                    item_id=_item_id(prefix, item_no, counter),
                    item_no=item_no,
                    source=source,
                    section=section,
                    subsection=subsection,
                    text=text,
                    level=level,
                    detail=detail,
                ))
                continue

            # Legacy format:
            #   項目 | 必須・推奨・任意 | 詳細
            #   項目 | 詳細
            if len(cells) >= 3 and cells[1] in LEVELS:
                text = _clean(cells[0])
                level = cells[1]
                detail = _clean(cells[2])
            elif len(cells) == 2:
                # 2-column appendix table: 項目 | 詳細
                text = _clean(cells[0])
                detail = _clean(cells[1])
            else:
                text = _clean(cells[0])
                detail = _clean(cells[-1]) if len(cells) > 1 else ""
            counter += 1
            items.append(_item(
                item_id=_item_id(prefix, item_no, counter),
                item_no=item_no,
                source=source,
                section=section,
                subsection=subsection,
                text=text,
                level=level,
                detail=detail,
            ))
            continue

    return items


def _metadata_entry(source: str, path: Path) -> dict:
    return {
        "source": source,
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill-dir", type=Path,
                        default=Path(__file__).resolve().parent.parent)
    parser.add_argument(
        "--mode",
        choices=("customer", "reporter", "both"),
        required=True,
        help=(
            "Checklist set to parse. Specify customer or reporter for normal "
            "reviews. Use both only for explicit maintenance tasks."
        ),
    )
    args = parser.parse_args()
    ref = args.skill_dir / "references"

    customer = ref / "checklist_customer.md"
    reporter = ref / "checklist_reporter.md"
    if not customer.exists() or not reporter.exists():
        print(f"error: checklists not found under {ref}", file=sys.stderr)
        return 2

    items: list[dict] = []
    checklists: list[dict] = []
    if args.mode in ("customer", "both"):
        items.extend(parse_markdown(customer, "customer", "CUS"))
        checklists.append(_metadata_entry("customer", customer))
    if args.mode in ("reporter", "both"):
        items.extend(parse_markdown(reporter, "reporter", "REP"))
        checklists.append(_metadata_entry("reporter", reporter))
    ids = [i["id"] for i in items]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        print(f"error: duplicate checklist IDs: {duplicates}", file=sys.stderr)
        return 1
    metadata = {
        "schema_version": "1.1",
        "mode": args.mode,
        "checklists": checklists,
    }
    print(json.dumps({"metadata": metadata, "items": items}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
