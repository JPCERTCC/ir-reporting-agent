#!/usr/bin/env python3
"""Build a source-span index from a normalized report text.

The index gives review issues stable references to real source text. It is not
a forensic parser; it only records where text exists so later validation can
reject free-floating findings.

Usage:
    python build_source_index.py --source normalized.txt \
        --out source_index.json [--document-id primary_report]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
import review_io


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def span_id(document_id: str, start_line: int, end_line: int, text: str) -> str:
    seed = f"{document_id}:{start_line}:{end_line}:{sha(text)[:16]}"
    return "SPN-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]


def concrete_values(text: str) -> list[dict]:
    patterns = [
        ("evidence_id", r"\b(?:E|EV)-\d+(?:-\d+)?\b"),
        ("ip", r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
        ("hash_sha256", r"\b[a-fA-F0-9]{64}\b"),
        ("hash_md5", r"\b[a-fA-F0-9]{32}\b"),
        ("date", r"\b20\d{2}[-/年]\d{1,2}[-/月]\d{1,2}日?\b"),
    ]
    values = []
    for kind, pattern in patterns:
        for m in re.finditer(pattern, text):
            values.append({"kind": kind, "value": m.group(0)})
    return values


def classify_block(lines: list[str]) -> str:
    stripped = [l.strip() for l in lines if l.strip()]
    if not stripped:
        return "blank"
    if all(l.startswith("|") and l.endswith("|") for l in stripped):
        return "table"
    if any(re.search(r"\b(EventID|timestamp|src|dst|user|host|account|ip)\b\s*=", l, re.I)
           for l in stripped):
        return "log_or_key_value"
    return "paragraph"


def build_spans(text: str, document_id: str) -> list[dict]:
    lines = text.splitlines()
    spans: list[dict] = []
    section = ""
    block: list[str] = []
    block_start = 1
    in_code = False

    def flush(end_line: int) -> None:
        nonlocal block, block_start
        content = "\n".join(block).strip("\n")
        if not content.strip():
            block = []
            return
        spans.append({
            "source_span_id": span_id(document_id, block_start, end_line, content),
            "document_id": document_id,
            "kind": "code_block" if in_code else classify_block(block),
            "section": section,
            "start_line": block_start,
            "end_line": end_line,
            "sha256": sha(content),
            "text": content,
            "values": concrete_values(content),
        })
        block = []

    for lineno, line in enumerate(lines, start=1):
        if line.startswith("```") and not in_code:
            if block:
                flush(lineno - 1)
            in_code = True
            block = [line]
            block_start = lineno
            continue
        if line.startswith("```") and in_code:
            block.append(line)
            flush(lineno)
            in_code = False
            continue

        if not in_code and re.match(r"^\s{0,3}#{1,6}\s+", line):
            if block:
                flush(lineno - 1)
            section = line.strip("# ").strip()
            spans.append({
                "source_span_id": span_id(document_id, lineno, lineno, line),
                "document_id": document_id,
                "kind": "heading",
                "section": section,
                "start_line": lineno,
                "end_line": lineno,
                "sha256": sha(line),
                "text": line,
                "values": concrete_values(line),
            })
            continue

        if not line.strip() and not in_code:
            if block:
                flush(lineno - 1)
            continue

        if not block:
            block_start = lineno
        block.append(line)

    if block:
        flush(len(lines))
    return spans


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--document-id", default="primary_report")
    args = ap.parse_args()

    if not args.source.exists():
        print(f"error: source not found: {args.source}", file=sys.stderr)
        return 2
    text = args.source.read_text(encoding="utf-8")
    spans = build_spans(text, args.document_id)
    data = {
        "schema_version": "1.1",
        "document_id": args.document_id,
        "source_path": str(args.source),
        "source_sha256": hashlib.sha256(args.source.read_bytes()).hexdigest(),
        "spans": spans,
    }
    review_io.atomic_write_json(args.out, data)
    print(f"source spans: {len(spans)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
