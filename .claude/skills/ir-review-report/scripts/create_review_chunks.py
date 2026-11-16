#!/usr/bin/env python3
"""Split source_index.json into bounded review chunks for SubAgent workflows.

The script preserves whole-span coverage. It does not select "important"
content; every source span becomes a core span of exactly one chunk. Optional
overlap spans are included only as local context and are marked separately so a
parent Agent can track coverage without double-counting.

Usage:
    python create_review_chunks.py --source-index source_index.json \
        --out-dir review_chunks --mode customer
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
import review_io


def span_id(span: dict[str, Any]) -> str:
    value = span.get("source_span_id") or span.get("span_id") or span.get("id")
    if not value:
        raise ValueError("source span missing source_span_id/span_id/id")
    return str(value)


def span_text(span: dict[str, Any]) -> str:
    return str(span.get("text") or "")


def span_chars(span: dict[str, Any]) -> int:
    return len(span_text(span))


def public_span(span: dict[str, Any], role: str) -> dict[str, Any]:
    sid = span_id(span)
    return {
        "span_id": sid,
        "source_span_id": sid,
        "role": role,
        "document_id": span.get("document_id"),
        "kind": span.get("kind"),
        "section_hint": span.get("section") or span.get("section_hint") or "",
        "start_line": span.get("start_line"),
        "end_line": span.get("end_line"),
        "sha256": span.get("sha256"),
        "values": span.get("values", []),
        "text": span_text(span),
    }


def make_core_groups(
    spans: list[dict[str, Any]],
    max_spans: int,
    max_chars: int,
) -> list[list[int]]:
    groups: list[list[int]] = []
    current: list[int] = []
    current_chars = 0

    for idx, span in enumerate(spans):
        chars = span_chars(span)
        would_exceed_count = len(current) >= max_spans
        would_exceed_chars = current and current_chars + chars > max_chars
        if would_exceed_count or would_exceed_chars:
            groups.append(current)
            current = []
            current_chars = 0
        current.append(idx)
        current_chars += chars

    if current:
        groups.append(current)
    return groups


def write_chunks(
    source_index: Path,
    out_dir: Path,
    mode: str,
    max_spans: int,
    max_chars: int,
    overlap_spans: int,
) -> dict[str, Any]:
    data = json.loads(source_index.read_text(encoding="utf-8"))
    spans = data.get("spans", [])
    if not isinstance(spans, list):
        raise ValueError("source_index.json must contain a list field named 'spans'")

    out_dir.mkdir(parents=True, exist_ok=True)
    groups = make_core_groups(spans, max_spans=max_spans, max_chars=max_chars)
    chunks: list[dict[str, Any]] = []

    for chunk_no, core_indices in enumerate(groups, start=1):
        core_set = set(core_indices)
        start = max(0, core_indices[0] - overlap_spans)
        end = min(len(spans), core_indices[-1] + overlap_spans + 1)
        included_indices = list(range(start, end))

        core_span_ids = [span_id(spans[i]) for i in core_indices]
        overlap_ids = [span_id(spans[i]) for i in included_indices if i not in core_set]
        all_ids = [span_id(spans[i]) for i in included_indices]

        chunk_id = f"CHK-{chunk_no:03d}"
        file_name = f"chunk_{chunk_no:03d}.json"
        chunk_path = out_dir / file_name
        chunk = {
            "schema_version": "1.0",
            "chunk_id": chunk_id,
            "review_mode": mode,
            "source_index_path": str(source_index),
            "span_range": {
                "first": core_span_ids[0],
                "last": core_span_ids[-1],
            },
            "core_span_ids": core_span_ids,
            "overlap_span_ids": overlap_ids,
            "spans": [
                public_span(spans[i], "core" if i in core_set else "overlap")
                for i in included_indices
            ],
        }
        review_io.atomic_write_json(chunk_path, chunk)
        chunks.append({
            "chunk_id": chunk_id,
            "path": file_name,
            "span_ids": all_ids,
            "core_span_ids": core_span_ids,
            "overlap_span_ids": overlap_ids,
            "char_count": sum(span_chars(spans[i]) for i in included_indices),
        })

    manifest = {
        "schema_version": "1.0",
        "source_index_path": str(source_index),
        "document_id": data.get("document_id"),
        "source_span_count": len(spans),
        "mode": mode,
        "chunking": {
            "max_spans": max_spans,
            "max_chars": max_chars,
            "overlap_spans": overlap_spans,
        },
        "chunks": chunks,
    }
    review_io.atomic_write_json(out_dir / "chunk_manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-index", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--max-spans", type=int, default=40)
    parser.add_argument("--max-chars", type=int, default=20000)
    parser.add_argument("--overlap-spans", type=int, default=3)
    parser.add_argument("--mode", choices=("customer", "reporter"), required=True)
    args = parser.parse_args()

    if args.max_spans <= 0:
        print("error: --max-spans must be positive", file=sys.stderr)
        return 2
    if args.max_chars <= 0:
        print("error: --max-chars must be positive", file=sys.stderr)
        return 2
    if args.overlap_spans < 0:
        print("error: --overlap-spans must be zero or positive", file=sys.stderr)
        return 2
    if not args.source_index.exists():
        print(f"error: source index not found: {args.source_index}", file=sys.stderr)
        return 2

    try:
        manifest = write_chunks(
            args.source_index,
            args.out_dir,
            args.mode,
            args.max_spans,
            args.max_chars,
            args.overlap_spans,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"wrote {len(manifest['chunks'])} chunks for "
        f"{manifest['source_span_count']} source spans"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

