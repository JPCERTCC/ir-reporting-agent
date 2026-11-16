#!/usr/bin/env python3
"""Self-consistency check for the final review document.

The review tool flags summary-vs-body inconsistencies in vendors' reports, so
its own output must not contain them. This script verifies the generated
review Markdown against the machine outputs:

  1. every summary line from check_issues.py (summary.md content) appears in
     the document verbatim — the executive summary may not restate or invent
     counts/distributions of its own
  2. every issue_id in issues.json appears somewhere in the document body
     (no issue silently dropped), and every ISS- token in the document exists
     in issues.json (no summary-only / phantom claims)
  3. when optional_enhancement issues exist, the document has a 改善提案
     section containing each of their issue IDs; same for
     external_confirmation and the 被害組織が追加確認すべき事項 section —
     so section item counts can never drift from the summary counts

Exit 1 on any inconsistency.

Usage:
    python check_review_doc.py --review <review.md>
        --issues <issues_normalized.json> --summary <summary.json>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Local import of the markdown renderer keeps the "expected summary lines"
# definition in one place (check_issues.to_markdown).
sys.path.insert(0, str(Path(__file__).resolve().parent))
import review_io
from check_issues import issue_quotes, result_id, to_markdown  # noqa: E402

_SECTION_HINTS = {
    "optional": ("改善提案|任意改善事項", "optional_enhancement_ids"),
    "external": ("被害組織が追加確認すべき事項|外部確認事項", "external_confirmation_ids"),
}

FIXED_HEADINGS = [
    "# インシデント調査報告書レビュー結果",
    "## 1. レビュー対象",
    "## 2. 総合評価",
    "## 3. 重大な指摘事項",
    "## 4. 主要結論の妥当性",
    "## 5. 推奨対策の妥当性",
    "## 6. 形式・チェックリスト上の指摘",
    "## 7. 機械チェック・証拠IDの検査結果",
    "## 8. 外部確認事項",
    "## 9. 任意改善事項",
    "## 10. AIレビューの制約",
    "## 付録A. チェックリスト全項目結果",
]


def _norm(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _norm_line_endings(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def _section_body(doc: str, heading_regex: str) -> str | None:
    m = re.search(rf"(?m)^(#{{1,3}})\s*.*(?:{heading_regex}).*$", doc)
    if not m:
        return None
    level = len(m.group(1))
    tail = doc[m.end():]
    nxt = re.search(rf"(?m)^#{{1,{level}}}\s+", tail)
    return tail[: nxt.start()] if nxt else tail


def main() -> int:
    review_io.require_via_review_status("check_review_doc.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--review", required=True, type=Path)
    ap.add_argument("--issues", required=True, type=Path)
    ap.add_argument("--summary", required=True, type=Path)
    ap.add_argument("--results", type=Path,
                    help="checklist_results.json; enables fixed-template appendix checks")
    ap.add_argument("--source", type=Path,
                    help="normalized report text; verifies quoted issue snippets exist")
    ap.add_argument("--rendered", type=Path,
                    help="code-rendered review.md; requires exact full-document match")
    args = ap.parse_args()

    doc = args.review.read_text(encoding="utf-8")
    issues_data = json.loads(args.issues.read_text(encoding="utf-8"))
    issues = issues_data.get("issues", issues_data if isinstance(issues_data, list) else [])
    summary = json.loads(args.summary.read_text(encoding="utf-8"))

    problems: list[str] = []
    doc_norm = _norm(doc)

    if args.rendered:
        rendered = args.rendered.read_text(encoding="utf-8")
        if _norm_line_endings(doc) != _norm_line_endings(rendered):
            problems.append(
                "レビュー文書が固定レンダラーの出力と一致しない"
                "(自由編集された可能性があります)"
            )

    if args.results:
        for heading in FIXED_HEADINGS:
            if heading not in doc:
                problems.append(f"固定見出しが不足しています: {heading}")

        results_data = json.loads(args.results.read_text(encoding="utf-8"))
        results = results_data.get("results", results_data if isinstance(results_data, list) else [])
        appendix = _section_body(doc, r"付録A\.\s*チェックリスト全項目結果")
        if appendix is None:
            problems.append("付録A. チェックリスト全項目結果 セクションがない")
        else:
            appendix_norm = _norm(appendix)
            for rid in sorted({result_id(r) for r in results if isinstance(r, dict) and result_id(r)}):
                if _norm(str(rid)) not in appendix_norm:
                    problems.append(f"{rid}: 付録Aにチェックリスト判定が記載されていない")

    if args.source:
        source_norm = _norm(args.source.read_text(encoding="utf-8"))
        for issue in issues:
            label = issue.get("issue_id", "<unknown>")
            for quote in issue_quotes(issue):
                text = str(quote.get("text") or "").strip()
                if not text or text == "(記載なし)":
                    continue
                if _norm(text) not in source_norm:
                    problems.append(
                        f"{label}: 引用がレビュー対象の正規化テキストに存在しない: {text[:80]}"
                    )

    # 1) Verbatim transcription of the code-generated summary lines.
    for line in to_markdown(summary).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if _norm(line) not in doc_norm:
            problems.append(f"サマリー行が文書に転記されていない: {line[:80]}")

    # 2) Bidirectional issue-id consistency.
    known_ids = {i["issue_id"] for i in issues}
    for issue_id in sorted(known_ids):
        if issue_id not in doc:
            problems.append(f"{issue_id}: 文書のどこにも記載がない(指摘の欠落)")
    for token in sorted(set(re.findall(r"ISS-[0-9a-f]{8}", doc))):
        if token not in known_ids:
            problems.append(
                f"{token}: issues.json に存在しない ID が文書に記載されている"
                "(サマリー/本文限定の幽霊指摘)"
            )

    # 3) Bucket sections must exist and contain each of their issue IDs.
    for _, (heading_regex, key) in _SECTION_HINTS.items():
        ids = summary.get(key) or []
        if not ids:
            continue
        body = _section_body(doc, heading_regex)
        display = heading_regex.replace("|", "/")
        if body is None:
            problems.append(
                f"「{display}」セクションがない(該当 issue {len(ids)} 件)"
            )
            continue
        for issue_id in ids:
            if issue_id not in body:
                problems.append(
                    f"{issue_id}: 「{display}」セクション内に記載がない"
                    "(サマリー件数とセクション項目が乖離する)"
                )

    if problems:
        print(f"FAIL ({len(problems)}):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("PASS: review document is self-consistent with issues/summary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
