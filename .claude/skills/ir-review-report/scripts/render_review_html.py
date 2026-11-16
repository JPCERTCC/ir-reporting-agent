#!/usr/bin/env python3
"""Render final_review.md as a single self-contained, easier-to-review HTML file.

final_review.md stays the authoritative artifact (it is what render_review.py
generates and check_review_doc.py verifies). The HTML is a *derived view*: it
never adds, removes, or rewords findings — it only re-presents the same
Markdown with a table of contents, severity/verdict badges, issue-ID
cross-links, and a verdict filter on the checklist appendix. Regenerate it
from final_review.md; never hand-edit it.

The input Markdown embeds quotes from the (untrusted) report under review, so
every piece of text is HTML-escaped before any markup is added, and the output
loads no external resources (no scripts, fonts, or stylesheets from a network).

Usage:
    python render_review_html.py --review final_review.md --out final_review.html
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path

import review_io

VERDICTS = {"met", "partial", "not_met", "unknown", "not_applicable", "out_of_scope"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
ISSUE_ID_RE = re.compile(r"ISS-[0-9a-f]{8}")
TABLE_SEP_RE = re.compile(r"^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
LIST_RE = re.compile(r"^(\s*)- (.*)$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
BADGE_RE = re.compile(r"^\[([a-z_]+) / ([a-z]+)\]\s*(.*)$")


def slugify(text: str, used: set[str]) -> str:
    base = re.sub(r"[^\w぀-ヿ㐀-鿿]+", "-", text).strip("-") or "section"
    slug, n = base, 2
    while slug in used:
        slug, n = f"{base}-{n}", n + 1
    used.add(slug)
    return slug


def inline(text: str, issue_ids: set[str]) -> str:
    """Escape first, then add markup, so report text can never inject HTML."""
    out = html.escape(text, quote=True)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)

    def link(m: re.Match) -> str:
        iid = m.group(0)
        return f'<a href="#{iid}">{iid}</a>' if iid in issue_ids else iid

    # Skip ids already wrapped as the issue's own heading anchor.
    return ISSUE_ID_RE.sub(link, out)


def split_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


def pill(value: str) -> str:
    v = value.strip()
    if v in VERDICTS or v in SEVERITIES or v in {"reported", "not_reported", "pass", "warn", "fail",
                                                   "consistent", "mapped", "partially_mapped",
                                                   "supported", "partially_supported", "unsupported"}:
        return f'<span class="pill v-{html.escape(v)}">{html.escape(v)}</span>'
    return ""


def render_table(rows: list[list[str]], issue_ids: set[str], filterable: bool) -> str:
    header, body = rows[0], rows[1:]
    verdict_col = next((i for i, h in enumerate(header) if h in ("判定", "評価", "status", "記載状況")), None)
    parts = ['<div class="table-wrap"><table>']
    parts.append("<thead><tr>" + "".join(f"<th>{inline(h, issue_ids)}</th>" for h in header) + "</tr></thead>")
    parts.append("<tbody>")
    for row in body:
        row = row + [""] * (len(header) - len(row))
        attr = ""
        if filterable and verdict_col is not None:
            attr = f' data-verdict="{html.escape(row[verdict_col].strip())}"'
        cells = []
        for i, cell in enumerate(row[: len(header)]):
            rendered = (pill(cell) if i == verdict_col else "") or inline(cell, issue_ids)
            cells.append(f"<td>{rendered}</td>")
        parts.append(f"<tr{attr}>" + "".join(cells) + "</tr>")
    parts.append("</tbody></table></div>")
    return "".join(parts)


def render_list(items: list[tuple[int, str]], issue_ids: set[str]) -> str:
    """items: (indent_level, text). Nested by indent level."""
    out: list[str] = []
    stack = 0  # current open <ul> depth
    open_li = False
    for level, text in items:
        while stack > level + 1:
            out.append("</li></ul>" if open_li else "</ul>")
            stack -= 1
            open_li = True
        if stack == level + 1 and open_li:
            out.append("</li>")
        while stack < level + 1:
            out.append("<ul>")
            stack += 1
            open_li = False
        out.append(render_item(text, issue_ids))
        open_li = True
    while stack > 0:
        out.append("</li></ul>" if open_li else "</ul>")
        stack -= 1
        open_li = True
    return "".join(out)


def render_item(text: str, issue_ids: set[str]) -> str:
    m = re.match(r"^`(ISS-[0-9a-f]{8})`\s*(.*)$", text)
    if not m:
        return f"<li>{inline(text, issue_ids)}"
    iid, rest = m.group(1), m.group(2)
    badge = ""
    b = BADGE_RE.match(rest)
    if b:
        cls, sev, rest = b.groups()
        badge = (
            f'<span class="pill sev-{html.escape(sev)}">{html.escape(sev)}</span>'
            f'<span class="pill cls">{html.escape(cls)}</span>'
        )
    return (
        f'<li class="issue" id="{iid}"><span class="issue-id">{iid}</span>{badge}'
        f'<span class="issue-cat">{inline(rest, issue_ids)}</span>'
    )


def parse_blocks(md: str) -> list[dict]:
    lines = md.splitlines()
    blocks: list[dict] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        h = HEADING_RE.match(line)
        if h:
            blocks.append({"type": "h", "level": len(h.group(1)), "text": h.group(2)})
            i += 1
            continue
        if line.lstrip().startswith("|") and i + 1 < len(lines) and TABLE_SEP_RE.match(lines[i + 1].strip()):
            rows = [split_row(line)]
            i += 2
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append(split_row(lines[i]))
                i += 1
            blocks.append({"type": "table", "rows": rows})
            continue
        if LIST_RE.match(line):
            items = []
            while i < len(lines):
                m = LIST_RE.match(lines[i])
                if not m:
                    break
                items.append((len(m.group(1)) // 2, m.group(2)))
                i += 1
            blocks.append({"type": "list", "items": items})
            continue
        para = [line]
        i += 1
        while i < len(lines) and lines[i].strip() and not (
            HEADING_RE.match(lines[i]) or LIST_RE.match(lines[i]) or lines[i].lstrip().startswith("|")
        ):
            para.append(lines[i])
            i += 1
        blocks.append({"type": "p", "text": " ".join(s.strip() for s in para)})
    return blocks


CSS = """
:root{--bg:#fff;--fg:#1f2328;--muted:#656d76;--line:#d0d7de;--card:#f6f8fa;--accent:#0969da;
--met:#1a7f37;--partial:#9a6700;--not_met:#cf222e;--unknown:#6e40c9;--na:#6e7781;
--critical:#82071e;--high:#cf222e;--medium:#bc4c00;--low:#9a6700;--info:#0969da}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;
--card:#161b22;--accent:#58a6ff;--met:#3fb950;--partial:#d29922;--not_met:#f85149;--unknown:#a371f7;
--na:#8b949e;--critical:#ff7b72;--high:#f85149;--medium:#db6d28;--low:#d29922;--info:#58a6ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.7 -apple-system,"Hiragino Sans","Noto Sans JP",sans-serif}
.layout{display:flex;max-width:1400px;margin:0 auto}
nav{position:sticky;top:0;align-self:flex-start;width:280px;max-height:100vh;overflow:auto;padding:20px 12px;
border-right:1px solid var(--line);font-size:13px;flex:none}
nav a{display:block;padding:3px 8px;color:var(--muted);text-decoration:none;border-radius:4px}
nav a:hover{background:var(--card);color:var(--fg)}nav a.h3{padding-left:22px}
main{flex:1;min-width:0;padding:24px 32px 80px}
h1{font-size:24px;margin:0 0 16px}
h2{font-size:19px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:24px 0 8px}
code{background:var(--card);padding:1px 5px;border-radius:4px;font-size:.9em}
ul{margin:4px 0;padding-left:22px}
li.issue{list-style:none;margin:14px 0 4px -22px;padding:10px 14px;background:var(--card);
border:1px solid var(--line);border-left:4px solid var(--line);border-radius:6px}
li.issue>ul{margin-top:6px}li.issue li{margin:2px 0}
.issue-id{font-family:ui-monospace,monospace;font-weight:600;margin-right:8px}
.issue-cat{color:var(--muted);margin-left:6px}
.pill{display:inline-block;padding:0 8px;border-radius:10px;font-size:12px;line-height:20px;
border:1px solid currentColor;margin-right:4px;white-space:nowrap}
.pill.cls{color:var(--muted)}
.v-met,.v-pass,.v-consistent,.v-mapped,.v-supported{color:var(--met)}
.v-partial,.v-warn,.v-partially_mapped,.v-partially_supported{color:var(--partial)}
.v-not_met,.v-fail,.v-unsupported,.v-not_reported{color:var(--not_met)}
.v-unknown{color:var(--unknown)}.v-not_applicable,.v-out_of_scope,.v-reported{color:var(--na)}
.sev-critical{color:var(--critical);font-weight:700}.sev-high{color:var(--high)}
.sev-medium{color:var(--medium)}.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.table-wrap{overflow-x:auto;margin:10px 0}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
th{background:var(--card);position:sticky;top:0}
.filters{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}
.filters button{cursor:pointer;background:var(--card);color:var(--fg);border:1px solid var(--line);
border-radius:14px;padding:2px 12px;font:inherit;font-size:13px}
.filters button[aria-pressed=true]{border-color:var(--accent);color:var(--accent)}
.note{color:var(--muted);font-size:13px}
@media (max-width:860px){.layout{display:block}nav{position:static;width:auto;max-height:none;border:0;
border-bottom:1px solid var(--line)}main{padding:16px}}
@media print{nav,.filters{display:none}.layout{display:block}li.issue{break-inside:avoid}}
"""

JS = """
(function(){
  var bar=document.getElementById('verdict-filters'); if(!bar) return;
  var rows=document.querySelectorAll('tr[data-verdict]');
  bar.addEventListener('click',function(e){
    var b=e.target.closest('button'); if(!b) return;
    var v=b.getAttribute('data-filter');
    bar.querySelectorAll('button').forEach(function(x){x.setAttribute('aria-pressed',x===b?'true':'false')});
    rows.forEach(function(r){r.hidden=(v!=='all'&&r.getAttribute('data-verdict')!==v)});
  });
})();
"""


def build_html(md: str, title_suffix: str = "") -> str:
    blocks = parse_blocks(md)
    issue_ids = set(ISSUE_ID_RE.findall("\n".join(
        m.group(1) for line in md.splitlines()
        for m in [re.match(r"^- `(ISS-[0-9a-f]{8})`", line)] if m
    )))
    used: set[str] = set()
    toc: list[tuple[int, str, str]] = []
    body: list[str] = []
    in_appendix = False
    doc_title = "インシデント調査報告書レビュー結果"
    for b in blocks:
        if b["type"] == "h":
            lvl, text = b["level"], b["text"]
            if lvl == 1:
                doc_title = text
                body.append(f"<h1>{inline(text, issue_ids)}</h1>")
                continue
            slug = slugify(text, used)
            in_appendix = lvl == 2 and text.startswith("付録A")
            if lvl in (2, 3):
                toc.append((lvl, slug, text))
            body.append(f'<h{lvl} id="{slug}">{inline(text, issue_ids)}</h{lvl}>')
        elif b["type"] == "p":
            body.append(f"<p>{inline(b['text'], issue_ids)}</p>")
        elif b["type"] == "list":
            body.append(render_list(b["items"], issue_ids))
        elif b["type"] == "table":
            if in_appendix:
                body.append(
                    '<div class="filters" id="verdict-filters" role="group" aria-label="判定で絞り込み">'
                    '<button type="button" data-filter="all" aria-pressed="true">すべて</button>'
                    + "".join(
                        f'<button type="button" data-filter="{v}" aria-pressed="false">{v}</button>'
                        for v in ("not_met", "partial", "unknown", "met", "not_applicable")
                    )
                    + "</div>"
                )
            body.append(render_table(b["rows"], issue_ids, filterable=in_appendix))
    nav = "".join(
        f'<a class="h{lvl}" href="#{slug}">{html.escape(text)}</a>' for lvl, slug, text in toc
    )
    return (
        '<!doctype html><html lang="ja"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(doc_title)}</title><style>{CSS}</style></head><body>"
        f'<div class="layout"><nav aria-label="目次">{nav}</nav><main>'
        + "\n".join(body)
        + '<p class="note">このHTMLは final_review.md から機械的に生成した閲覧用ビューです。'
        "正本は final_review.md です（このファイルは編集しません）。</p>"
        f"</main></div><script>{JS}</script></body></html>\n"
    )


def main() -> int:
    review_io.require_via_review_status("render_review_html.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--review", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    if not args.review.exists():
        print(f"error: review markdown not found: {args.review}", file=sys.stderr)
        return 2
    try:
        md = args.review.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {args.review}: {exc}", file=sys.stderr)
        return 2
    if not md.strip():
        print(f"error: {args.review} is empty", file=sys.stderr)
        return 2
    review_io.atomic_write_text(args.out, build_html(md))
    print(f"rendered html: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
