#!/usr/bin/env python3
"""Detect a submitted report's format and normalize it to plain text.

The review scripts operate on text/Markdown. This helper auto-detects the input
format (by magic bytes, falling back to extension) and produces a normalized
UTF-8 text file the rest of the skill consumes:

  - text / Markdown  → passed through as-is
  - .docx (Word)     → extracted with the standard library (zip + XML)
  - .pdf             → pypdf when installed (reliable, keeps page markers);
                       otherwise best-effort standard-library extraction.
                       Either way the result must pass a plausibility check
                       (enough text AND a high ratio of readable characters —
                       the stdlib path can return megabytes of embedded-font
                       garbage on some PDFs, which a length check alone does
                       not catch). Implausible output exits with code 3 so the
                       caller can provide OCR/text extracted by another PDF
                       tool and rerun on that extracted file.

Exit codes:
  0  normalized text written to --out (or stdout)
  2  input missing / unreadable
  3  PDF could not be extracted here — provide OCR/text extracted by another
     PDF tool, then rerun

Usage:
    python prepare_report.py --report <file> [--out <normalized.txt>]
"""

from __future__ import annotations

import argparse
import html
import re
import sys
import zipfile
import zlib
from pathlib import Path
import review_io

# Below this many extracted characters we consider PDF extraction a failure.
_PDF_MIN_CHARS = 200
# Minimum fraction of readable characters (ASCII / kana / CJK / fullwidth) in
# the extracted text. Embedded-font garbage decodes mostly to Latin-1 high
# bytes and control characters, which fall far below this.
_PDF_MIN_READABLE_RATIO = 0.85


def _pdf_text_plausible(text: str) -> bool:
    """True when extracted PDF text looks like report prose, not font garbage."""
    if len(text) < _PDF_MIN_CHARS:
        return False
    sample = text[:200_000]
    readable = sum(
        1
        for ch in sample
        if ch.isspace()
        or 0x20 <= ord(ch) <= 0x7E      # printable ASCII
        or 0x3000 <= ord(ch) <= 0x30FF  # CJK punctuation, hiragana, katakana
        or 0x4E00 <= ord(ch) <= 0x9FFF  # CJK unified ideographs
        or 0xFF01 <= ord(ch) <= 0xFF9F  # fullwidth forms, halfwidth katakana
    )
    return readable / len(sample) >= _PDF_MIN_READABLE_RATIO


def extract_pdf_pypdf(path: Path) -> str | None:
    """Extract text with pypdf when installed; None when unavailable/failed.

    Emits `===== [page N] =====` markers so reviewers can cite page locations.
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        return None
    try:
        pages = []
        for i, page in enumerate(PdfReader(str(path)).pages, 1):
            pages.append(f"===== [page {i}] =====\n{page.extract_text() or ''}")
        return "\n".join(pages).strip()
    except Exception:
        return None


def detect_kind(path: Path) -> str:
    """Return 'pdf' | 'docx' | 'text' from magic bytes, then extension."""
    try:
        head = path.read_bytes()[:8]
    except OSError:
        head = b""
    if head.startswith(b"%PDF"):
        return "pdf"
    # docx is a zip; distinguish from arbitrary zips by extension below.
    ext = path.suffix.lower()
    if head.startswith(b"PK\x03\x04") and ext in (".docx", ".docm"):
        return "docx"
    if ext == ".pdf":
        return "pdf"
    if ext in (".docx", ".docm"):
        return "docx"
    return "text"


def extract_docx(path: Path) -> str:
    """Extract readable text from a .docx using only the standard library."""
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist()
                 if n == "word/document.xml"
                 or re.fullmatch(r"word/(header|footer)\d*\.xml", n)]
        if "word/document.xml" not in names:
            raise ValueError("word/document.xml not found — not a valid .docx")
        parts = []
        for name in ["word/document.xml"] + [n for n in names if n != "word/document.xml"]:
            xml = z.read(name).decode("utf-8", "replace")
            # Preserve structure: paragraphs and table rows → newlines,
            # table cells → separators, tabs/breaks → their characters.
            xml = re.sub(r"<w:tab\b[^>]*/>", "\t", xml)
            xml = re.sub(r"<w:br\b[^>]*/>", "\n", xml)
            xml = xml.replace("</w:tc>", " | ").replace("</w:tr>", "\n")
            xml = xml.replace("</w:p>", "\n")
            text = re.sub(r"<[^>]+>", "", xml)
            parts.append(html.unescape(text))
    joined = "\n".join(parts)
    # Collapse runs of blank lines and trailing separators.
    joined = re.sub(r"[ \t]*\|[ \t]*\n", "\n", joined)
    joined = re.sub(r"\n{3,}", "\n\n", joined)
    return joined.strip() + "\n"


def _decode_pdf_string(raw: bytes) -> str:
    # Handle escaped parens/backslashes inside a literal PDF string.
    out = bytearray()
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0x5C and i + 1 < len(raw):  # backslash
            nxt = raw[i + 1]
            mapping = {0x6E: 0x0A, 0x72: 0x0D, 0x74: 0x09}
            out.append(mapping.get(nxt, nxt))
            i += 2
            continue
        out.append(b)
        i += 1
    return out.decode("latin-1", "replace")


def extract_pdf_best_effort(path: Path) -> str:
    """Best-effort PDF text extraction with only the standard library.

    Decompresses FlateDecode streams and pulls text from Tj/TJ operators.
    Works for many text-based PDFs (exported from Word/Markdown); fails on
    scanned or unusually encoded PDFs — the caller then provides OCR/text
    extracted by another PDF tool.
    """
    data = path.read_bytes()
    chunks: list[str] = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.DOTALL):
        stream = m.group(1)
        payload = stream
        try:
            payload = zlib.decompress(stream)
        except zlib.error:
            pass  # may be an uncompressed content stream
        # Literal strings: ( ... ) Tj   and arrays: [ (..) .. ] TJ
        for sm in re.finditer(rb"\((?:[^()\\]|\\.)*\)", payload):
            chunks.append(_decode_pdf_string(sm.group(0)[1:-1]))
    text = "".join(chunks)
    # PDFs often lack spaces between words; keep what we have but tidy newlines.
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--out", type=Path, help="Write normalized text here (else stdout)")
    args = ap.parse_args()

    if not args.report.exists():
        print(f"error: report not found: {args.report}", file=sys.stderr)
        return 2

    kind = detect_kind(args.report)
    if kind == "text":
        text = args.report.read_text(encoding="utf-8", errors="replace")
    elif kind == "docx":
        try:
            text = extract_docx(args.report)
        except (zipfile.BadZipFile, ValueError) as e:
            print(f"error: could not read .docx: {e}", file=sys.stderr)
            return 2
    else:  # pdf
        text = extract_pdf_pypdf(args.report)
        if text is None or not _pdf_text_plausible(text):
            text = extract_pdf_best_effort(args.report)
        if not _pdf_text_plausible(text):
            print(
                "PDF text extraction did not yield plausible report text "
                "(scanned, unusually encoded, or only embedded-font data was "
                "recovered). Ensure pypdf is installed, or extract the report "
                "with OCR/another PDF text extraction tool to a .md/.txt file "
                "and rerun prepare_report.py (or the review scripts) on the "
                "extracted file.",
                file=sys.stderr,
            )
            return 3
        text = text + "\n"

    if args.out:
        review_io.atomic_write_text(args.out, text)
        print(f"normalized {kind} → {args.out} ({len(text)} chars)")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
