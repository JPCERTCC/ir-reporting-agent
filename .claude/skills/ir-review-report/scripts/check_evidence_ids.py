#!/usr/bin/env python3
"""Deterministic evidence-ID consistency checker for submitted IR reports.

Evidence-ID integrity is a mechanical property and must not depend on LLM
judgment. This script extracts every evidence-ID *definition* (rows of an
evidence list / preservation table) and every *reference* (body text, tables,
log excerpts, appendices) from the normalized report text and reports:

  problems (report-quality defects):
    - undefined_references   referenced but never defined
    - duplicate_definitions  same ID defined more than once (identical rows)
    - conflicting_definitions same ID defined with differing attributes
  info (not defects by themselves):
    - unreferenced_defined   defined but never cited (inventory candidate)
    - numbering_gaps         gaps in the defined ID sequence
    - notation_variants      raw spellings that normalization canonicalized

Normalization handles full-width characters (NFKC), stray spaces around
hyphens (``E - 109``), PDF line breaks inside an ID (``E-1`` + newline +
``09``), ranges (``E-115-01～E-115-04``), and enumerations.

Definitions are recognized as table rows whose first cell is an ID, plus
ID-led lines inside sections whose heading looks like an evidence list
(証拠一覧 / 提供データ / 証拠保全 / 関連ファイル). Everything else is a
reference. For PDF text without table markers, pass --define-sections to
name the report's evidence-list headings.

Output: JSON on stdout. Exit 1 when problems were found, else 0.

Usage:
    python check_evidence_ids.py --report <normalized.txt>
        [--prefixes E,EV] [--define-sections 証拠一覧,提供データ]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path

DEFAULT_PREFIXES = ["EV", "E"]
DEFAULT_DEFINE_SECTIONS = (
    r"証拠一覧|エビデンス一覧|提供データ|証拠保全|関連ファイル|別紙一覧|evidence list"
)

_RANGE_SEP = r"[~〜～]"  # ~ / 〜 / ～


def _id_regex(prefixes: list[str]) -> re.Pattern:
    alt = "|".join(sorted(prefixes, key=len, reverse=True))
    # Allow stray spaces around hyphens so "E - 109" is caught, then
    # canonicalized. Word boundaries keep CVE-2024-... etc. out as long as
    # its prefix is not in the list.
    return re.compile(
        rf"\b(?:{alt})\s*-\s*\d{{1,4}}(?:\s*-\s*\d{{1,4}})?\b"
    )


def canonicalize(raw: str) -> str:
    return re.sub(r"\s+", "", raw)


def rejoin_pdf_breaks(text: str, prefixes: list[str]) -> str:
    """Rejoin IDs split across a line break by PDF extraction (E-1\\n09)."""
    alt = "|".join(sorted(prefixes, key=len, reverse=True))
    # A line ending in a partial ID followed by a digits-only continuation.
    # pypdf splits table IDs mid-token ("E-10\n1\nAD01_...") — those must
    # rejoin. But a section number after a break ("E-101\n3.2 認証情報…") must
    # NOT: the negative lookahead rejects a continuation that is itself the
    # start of a sub-section number (3.2, 3-2), while a continuation followed
    # by text/newline (a real split ID) rejoins.
    pattern = re.compile(
        rf"((?:{alt})-\d{{1,3}})\n(\d{{1,3}})(?![.\-]?\d)"
    )
    prev = None
    while prev != text:
        prev = text
        text = pattern.sub(r"\1\2", text)
    return text


def expand_range(start: str, end: str) -> list[str]:
    """Expand E-115-01～E-115-04 (or E-101～E-104) into individual IDs."""
    s_base, s_num = start.rsplit("-", 1)
    e_base, e_num = end.rsplit("-", 1)
    if s_base != e_base or not (s_num.isdigit() and e_num.isdigit()):
        return [start, end]
    lo, hi = int(s_num), int(e_num)
    if not (0 < hi - lo <= 200):
        return [start, end]
    width = len(s_num)
    return [f"{s_base}-{str(n).zfill(width)}" for n in range(lo, hi + 1)]


def scan(text: str, prefixes: list[str], define_sections: str) -> dict:
    id_re = _id_regex(prefixes)
    range_re = re.compile(
        rf"({id_re.pattern})\s*{_RANGE_SEP}\s*({id_re.pattern})"
    )
    # Headings include markdown (#), 付録/表 labels, and bare numbered section
    # titles ("1.6 調査対象・提供データ") common in PDF-extracted text.
    heading_re = re.compile(
        r"^(?:#{1,6}\s+|付録[A-Za-z0-9]?[.．:]?\s*|表\s*[\d\-]+|\d+(?:\.\d+)*\s+\S)"
    )
    define_re = re.compile(define_sections, re.IGNORECASE)
    # An evidence-list column header (e.g. "証拠IDファイル名 対象 SHA-256")
    # starts a definition zone even without a preceding heading.
    table_header_re = re.compile(r"^証拠ID")

    definitions: dict[str, list[dict]] = defaultdict(list)
    references: dict[str, list[dict]] = defaultdict(list)
    variants: list[dict] = []
    in_define_zone = False

    def record(target, canon, line_no, line, attrs=None, raw=None):
        target[canon].append({
            "line": line_no,
            "text": line.strip()[:160],
            **({"attrs": attrs} if attrs else {}),
        })
        if raw is not None and raw != canon:
            variants.append({"raw": raw, "normalized": canon, "line": line_no})

    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if table_header_re.match(stripped):
            in_define_zone = True
        elif heading_re.match(stripped):
            # A new section heading opens the zone only if it names an
            # evidence list; any other heading closes it.
            in_define_zone = bool(define_re.search(stripped))

        # Expand ranges first so both scans see individual IDs.
        occurrences: list[tuple[str, str]] = []  # (canonical, raw)
        consumed_spans: list[tuple[int, int]] = []
        for m in range_re.finditer(line):
            lo_raw, hi_raw = m.group(1), m.group(2)
            for cid in expand_range(canonicalize(lo_raw), canonicalize(hi_raw)):
                occurrences.append((cid, m.group(0)))
            consumed_spans.append(m.span())
        for m in id_re.finditer(line):
            if any(s <= m.start() < e for s, e in consumed_spans):
                continue
            occurrences.append((canonicalize(m.group(0)), m.group(0)))

        if not occurrences:
            continue

        cells = [c.strip() for c in stripped.strip("|").split("|")] \
            if stripped.startswith("|") else None
        is_separator = cells is not None and set("".join(cells)) <= set("-: ")
        first_cell_id = (
            cells is not None and not is_separator and cells
            and id_re.match(cells[0]) is not None
        )

        for canon, raw in occurrences:
            if first_cell_id and canonicalize(cells[0]) == canon:
                record(definitions, canon, line_no, line,
                       attrs=cells[1:], raw=raw)
            elif in_define_zone and stripped.startswith(raw.strip()):
                record(definitions, canon, line_no, line, raw=raw)
            else:
                record(references, canon, line_no, line, raw=raw)

    return {
        "definitions": definitions,
        "references": references,
        "variants": variants,
    }


def analyze(scanned: dict) -> dict:
    defs, refs = scanned["definitions"], scanned["references"]

    undefined = [
        {"id": i, "lines": [r["line"] for r in locs]}
        for i, locs in sorted(refs.items()) if i not in defs
    ]
    duplicates, conflicts = [], []
    for i, locs in sorted(defs.items()):
        if len(locs) < 2:
            continue
        attr_sets = {tuple(loc.get("attrs", [])) for loc in locs}
        item = {"id": i, "lines": [loc["line"] for loc in locs]}
        (conflicts if len(attr_sets) > 1 else duplicates).append(item)
    unreferenced = [i for i in sorted(defs) if i not in refs]

    # Numbering gaps per (base) sequence of defined IDs.
    seqs: dict[str, list[int]] = defaultdict(list)
    for i in defs:
        base, num = i.rsplit("-", 1)
        if num.isdigit():
            seqs[base].append(int(num))
    gaps = []
    for base, nums in sorted(seqs.items()):
        nums = sorted(set(nums))
        missing = [n for n in range(nums[0], nums[-1]) if n not in nums]
        if missing:
            gaps.append({"base": base, "missing_numbers": missing})

    problems = {
        "undefined_references": undefined,
        "duplicate_definitions": duplicates,
        "conflicting_definitions": conflicts,
    }
    info = {
        "unreferenced_defined": unreferenced,
        "numbering_gaps": gaps,
        "notation_variants": scanned["variants"],
    }
    return {
        "problems": problems,
        "info": info,
        "summary": {
            "defined": len(defs),
            "referenced": len(refs),
            "problem_count": sum(len(v) for v in problems.values()),
        },
        "defined_ids": sorted(defs),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--prefixes", default=",".join(DEFAULT_PREFIXES),
                    help="Comma-separated ID prefixes (default: EV,E)")
    ap.add_argument("--define-sections", default=DEFAULT_DEFINE_SECTIONS,
                    help="Regex for headings of evidence-list sections")
    args = ap.parse_args()
    if not args.report.exists():
        print(f"error: report not found: {args.report}", file=sys.stderr)
        return 2

    prefixes = [p.strip() for p in args.prefixes.split(",") if p.strip()]
    text = unicodedata.normalize(
        "NFKC", args.report.read_text(encoding="utf-8", errors="replace")
    )
    text = rejoin_pdf_breaks(text, prefixes)
    result = analyze(scan(text, prefixes, args.define_sections))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["summary"]["problem_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
