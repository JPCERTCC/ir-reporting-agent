"""Interactive HTML views of the human review documents, and their import.

The Markdown review documents (evidence_review_NNN.md, claim_review_NNN.md,
gap_review_NNN.md) stay the source of truth: their YAML decision blocks are
what promote-evidence / apply-claim-review / apply-gap-disposition parse, and
what the audit trail refers to. This module adds two things around them:

- ``render_review_html``: a self-contained HTML page per review document with a
  pull-down per item, reason fields, attention badges (low confidence, single
  source, injection traces, elevated confidence, major gaps), progress, filters
  and selection-based bulk actions. Attention items are never bulk-decided —
  they have to be decided one by one. The page exports the human's decisions
  as JSON (download or clipboard); nothing is written by the browser.
- ``import_decisions``: transcribes that JSON into the YAML blocks verbatim,
  after checking it was made from the current version of the document.

The page is generic: it is built from the Markdown itself (``## <item>``
sections and their YAML block, with allowed values read from the block's
inline comment), so the three generators need no HTML-specific code.
Artifact-derived text is untrusted and always HTML-escaped.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ir_agent.governance.injection_guard import PromptInjectionGuard
from ir_agent.governance.review_options import OPTION_HELP, OPTION_LABELS

DECISION_KEYS = ("decision", "disposition")
UNDECIDED = {"", "pending", "null", "none"}
CONFIDENCE_VALUES = ["confirmed", "probable", "possible", "unknown", "not_observed"]
EXPORT_FORMAT = "ir-agent-review-decisions/v1"

_YAML_BLOCK = re.compile(r"```yaml[ \t]*\n(.*?)\n[ \t]*```", re.DOTALL)
_FIELD_LINE = re.compile(
    r"^(?P<key>[A-Za-z_]+):[ \t]*(?P<value>.*?)(?:[ \t]+#[ \t]?(?P<comment>.*))?$"
)
_PLACEHOLDER = re.compile(
    r"^[（(].*(ここに記載|listed here|レポート作成時|for report writing).*[）)]$"
)
_PAGE_TEMPLATE = Path(__file__).parent / "templates" / "review_page.html"


@dataclass
class ReviewField:
    key: str
    value: str
    comment: str = ""
    options: list[str] = field(default_factory=list)


@dataclass
class ReviewItem:
    item_id: str
    item_type: str
    heading: str
    body_md: str
    fields: list[ReviewField]
    decision_key: str
    attention: list[str]

    def field_value(self, key: str) -> str:
        return next((f.value for f in self.fields if f.key == key), "")


@dataclass
class ReviewDocument:
    title: str
    items: list[ReviewItem]


@dataclass
class ImportResult:
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _unquote(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        try:
            return str(json.loads(raw))
        except json.JSONDecodeError:
            return raw[1:-1]
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return raw[1:-1].replace("''", "'")
    return raw


def _parse_fields(yaml_text: str) -> list[ReviewField]:
    fields: list[ReviewField] = []
    for line in yaml_text.splitlines():
        m = _FIELD_LINE.match(line.strip())
        if not m:
            continue
        comment = (m.group("comment") or "").strip()
        options: list[str] = []
        if "|" in comment:
            options = [part.split(":")[0].strip() for part in comment.split("|")]
            options = [o for o in options if re.fullmatch(r"[a-z_]+", o)]
        fields.append(ReviewField(m.group("key"), _unquote(m.group("value")), comment, options))
    return fields


_RANK = {c: i for i, c in enumerate(reversed(CONFIDENCE_VALUES))}


def _attention(body: str, item_type: str, guard: PromptInjectionGuard) -> list[str]:
    """Why an item deserves an individual look (it is then excluded from bulk
    decisions). Kept selective on purpose: when everything is flagged, nothing is."""
    flags: list[str] = []
    if re.search(r"interpretation_confidence:\s*`?(unknown|not_observed)", body):
        flags.append("解釈を判断できない")
    if re.search(r"confidence_level:\s*`?(possible|unknown|not_observed)", body):
        flags.append("確度が低い")
    lift = re.search(r"Base confidence from evidence: (\w+); Final confidence: (\w+)", body)
    if lift and _RANK.get(lift.group(2), 0) > _RANK.get(lift.group(1), 0):
        flags.append(f"確度が引き上げられている({lift.group(1)}→{lift.group(2)})")
    if re.search(r"(?m)^-?\s*severity:\s*(major|critical)", body):
        flags.append("重大度が高い")
    support = re.search(r"### 支持証拠\n+((?:- .*\n?)+)", body)
    if item_type == "claim" and support and len(support.group(1).strip().splitlines()) == 1:
        flags.append("単一の証拠")
    if guard.detect_injection_patterns(body):
        flags.append("インジェクションの疑い")
    return flags


def parse_review_document(text: str) -> ReviewDocument:
    title_m = re.search(r"(?m)^# (.+)$", text)
    sections = re.split(r"(?m)^## ", text)
    guard = PromptInjectionGuard()
    items: list[ReviewItem] = []
    for section in sections[1:]:
        heading, _, rest = section.partition("\n")
        block = _YAML_BLOCK.search(rest)
        if not block:
            continue
        fields = _parse_fields(block.group(1))
        keys = {f.key for f in fields}
        decision_key = next((k for k in DECISION_KEYS if k in keys), "")
        item_id = next((f.value for f in fields if f.key == "item_id"), "")
        if not item_id or not decision_key:
            continue
        body = rest[: block.start()]
        body = re.sub(r"\n### [^\n]*$", "", body.rstrip())  # drop the trailing 判定 heading
        item_type = next((f.value for f in fields if f.key == "item_type"), "")
        items.append(ReviewItem(item_id, item_type, heading.strip(), body.strip(), fields,
                                decision_key, _attention(body, item_type, guard)))
    return ReviewDocument(title_m.group(1).strip() if title_m else "レビュー", items)


# ---------------------------------------------------------------- Markdown → HTML


def _inline(text: str) -> str:
    out, pos = [], 0
    for m in re.finditer(r"`([^`]+)`", text):
        out.append(html.escape(text[pos: m.start()]))
        out.append(f"<code>{html.escape(m.group(1))}</code>")
        pos = m.end()
    out.append(html.escape(text[pos:]))
    return "".join(out)


def _body_to_html(body: str) -> str:
    """Small, safe Markdown subset: ### headings, lists, paragraphs, inline code.

    Placeholder-only sections (「…をここに記載」) are dropped. Continuation lines
    are joined into the preceding list item so multi-line excerpts stay intact.
    """
    sections: list[tuple[str, list[str]]] = [("", [])]
    for line in body.splitlines():
        if line.startswith("### "):
            sections.append((line[4:].strip(), []))
        else:
            sections[-1][1].append(line)
    parts: list[str] = []
    for title, lines in sections:
        content = [ln for ln in lines if ln.strip()]
        if not content or all(_PLACEHOLDER.match(ln.strip()) for ln in content):
            continue
        blocks: list[str] = []
        items: list[str] = []
        para: list[str] = []

        def flush() -> None:
            if items:
                blocks.append("<ul>" + "".join(f"<li>{_inline(i)}</li>" for i in items) + "</ul>")
                items.clear()
            if para:
                blocks.append(f"<p>{_inline(' '.join(para))}</p>")
                para.clear()

        for ln in lines:
            stripped = ln.strip()
            if not stripped:
                if not (items and "`" in items[-1] and items[-1].count("`") % 2):
                    flush()
                continue
            if re.match(r"^\s*- ", ln):
                if para:
                    flush()
                items.append(re.sub(r"^\s*- ", "", ln))
            elif items:
                items[-1] += "\n" + ln
            else:
                para.append(stripped)
        flush()
        heading = f"<h4>{html.escape(title)}</h4>" if title else ""
        parts.append(f"<section>{heading}{''.join(blocks)}</section>")
    return "".join(parts)


def _item_payload(item: ReviewItem) -> dict[str, Any]:
    return {
        "id": item.item_id,
        "type": item.item_type,
        "heading": item.heading,
        "decisionKey": item.decision_key,
        "fields": [
            {"key": f.key, "value": f.value, "comment": f.comment,
             "options": f.options
             or (CONFIDENCE_VALUES if f.key == "downgraded_confidence" else [])}
            for f in item.fields if f.key not in ("item_id", "item_type")
        ],
        "attention": item.attention,
    }


def render_review_html(md_path: Path, out_path: Path | None = None) -> Path:
    text = md_path.read_text(encoding="utf-8")
    doc = parse_review_document(text)
    out_path = out_path or md_path.with_suffix(".html")
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    data = {
        "format": EXPORT_FORMAT,
        "document": md_path.name,
        "sha256": sha,
        "title": doc.title,
        "labels": OPTION_LABELS,
        "help": OPTION_HELP,
        "items": [_item_payload(i) for i in doc.items],
    }
    bodies = "".join(
        f'<template id="body-{html.escape(i.item_id)}">{_body_to_html(i.body_md)}</template>'
        for i in doc.items
    )
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    title = html.escape(f"{doc.title} — {md_path.name}")
    page = (_PAGE_TEMPLATE.read_text(encoding="utf-8").replace("__TITLE__", title)
            .replace("__BODIES__", bodies).replace("__DATA__", payload))
    out_path.write_text(page, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------- import


def _yaml_scalar(key: str, value: str, options: list[str]) -> str:
    if key in DECISION_KEYS or key == "downgraded_confidence" or options:
        return value
    return json.dumps(value, ensure_ascii=False)


def import_decisions(md_path: Path, export: dict[str, Any]) -> ImportResult:
    """Write the exported HTML decisions into the Markdown YAML blocks."""
    result = ImportResult()
    text = md_path.read_text(encoding="utf-8")
    if export.get("format") != EXPORT_FORMAT:
        result.errors.append("HTML レビュー画面から書き出した決定ファイルではありません")
        return result
    if export.get("document") != md_path.name:
        result.errors.append(
            f"決定ファイルは {export.get('document')} 用です({md_path.name} ではありません)")
        return result
    if export.get("sha256") != hashlib.sha256(text.encode("utf-8")).hexdigest():
        result.errors.append(
            "HTML を生成した後にレビュー文書が変更されています。"
            "最新の HTML で判定をやり直してください")
        return result
    analyst = str(export.get("analyst_id") or "").strip()
    if not analyst:
        result.errors.append("analyst_id(判定した人の ID)が入力されていません")
        return result

    doc = parse_review_document(text)
    by_id = {i.item_id: i for i in doc.items}
    for entry in export.get("decisions", []):
        item = by_id.get(str(entry.get("item_id")))
        if item is None:
            result.errors.append(f"{entry.get('item_id')}: レビュー文書にない項目です")
            continue
        value = str(entry.get(item.decision_key) or "").strip()
        allowed = next((f.options for f in item.fields if f.key == item.decision_key), [])
        if value.lower() in UNDECIDED:
            continue
        if allowed and value not in allowed:
            result.errors.append(f"{item.item_id}: 判定値 {value!r} は選択肢にありません")
            continue
        keys = {f.key for f in item.fields}
        if value == "edited" and "edited_claim_text" in keys \
                and not str(entry.get("edited_claim_text") or "").strip():
            result.errors.append(f"{item.item_id}: 「編集して承認」には修正後の文言が必要です")
            continue
        if value == "downgraded" and "downgraded_confidence" in keys \
                and entry.get("downgraded_confidence") not in CONFIDENCE_VALUES:
            result.errors.append(f"{item.item_id}: 「確度を下げて承認」には変更後の確度が必要です")
            continue
        reason_key = f"{item.decision_key}_reason"
        updates = {item.decision_key: value, "analyst_id": analyst,
                   reason_key: str(entry.get(reason_key) or "").strip()
                   or f"decided via HTML review by {analyst}"}
        for key in ("edited_claim_text", "downgraded_confidence"):
            if key in keys and entry.get(key):
                updates[key] = str(entry[key]).strip()
        new_text = _rewrite_block(text, item, updates)
        if new_text == text:
            result.unchanged.append(item.item_id)
        else:
            text = new_text
            result.updated.append(item.item_id)
    if result.updated and not result.errors:
        md_path.write_text(text, encoding="utf-8")
    return result


def _rewrite_block(text: str, item: ReviewItem, updates: dict[str, str]) -> str:
    for block in _YAML_BLOCK.finditer(text):
        if not re.search(rf"(?m)^item_id:[ \t]*{re.escape(item.item_id)}[ \t]*$", block.group(1)):
            continue
        lines = block.group(1).splitlines()
        for i, line in enumerate(lines):
            m = _FIELD_LINE.match(line.strip())
            if m and m.group("key") in updates:
                key = m.group("key")
                options = next((f.options for f in item.fields if f.key == key), [])
                comment = f"  # {m.group('comment')}" if m.group("comment") else ""
                lines[i] = f"{key}: {_yaml_scalar(key, updates[key], options)}{comment}"
        new_block = block.group(0).replace(block.group(1), "\n".join(lines), 1)
        return text[: block.start()] + new_block + text[block.end():]
    return text


def load_export(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("decision file must be a JSON object")
    return data


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
