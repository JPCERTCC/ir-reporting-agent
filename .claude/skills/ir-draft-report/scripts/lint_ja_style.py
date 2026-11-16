#!/usr/bin/env python3
"""Advisory Japanese-style linter for IR documents.

Mechanical subset of references/ja_writing_norms.md, applicable to both draft
reports and review documents. Unlike lint_draft.py (structural contract,
FAIL blocks the draft), style needs judgment: template boilerplate and
verbatim quotes legitimately trigger some patterns. So this linter only
*warns* — exit 0 whether or not warnings were found, exit 2 on unreadable
input — and the agent/human decides what to fix.

Checks (code blocks are stripped first; tables are skipped where noted):
  - llm_phrases          dictionary of empty LLM-style phrasing (「重要なのは」
                         「掘り下げる」「不可欠」「多角的」「非常に」...)
  - long_sentence        prose sentences longer than --max-sentence chars
                         (default 200 — IR sentences carry evidence IDs and
                         timestamps, so they run long legitimately;
                         tables/headings excluded)
  - duplicate_sentence   the same prose sentence (>= 20 chars) written twice
  - dash_usage           em dash / horizontal bar in Japanese prose
  - connector_chains     3+ consecutive paragraphs opening with また/さらに/加えて

Output: JSON to stdout, same shape as mechanical_checks.py
({"checks": [{key,label,status,detail,samples}]}, status pass|warn).

Usage:
    python lint_ja_style.py --file <markdown> [--max-sentence 200]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# Empty LLM-style phrasing (ja_writing_norms.md 「書かない表現」).
# Deliberately excludes IR-legitimate wording: 「総合して」(evidence synthesis),
# 「可能性があります」(certainty system), 「本章では〜を記載します」(template).
LLM_PHRASES = [
    "重要なのは",
    "に他ならない",
    "に他なりません",
    "掘り下げ",
    "深掘り",
    "不可欠",
    "核心的",
    "鍵となる",
    "多角的",
    "包括的",
    "正面から",
    "言うまでもなく",
    "非常に",
    "極めて",
    "大いに",
    "と言えるだろう",
    "と言えるでしょう",
    "見ていきましょう",
    "見ていきます",
]

_DASH = re.compile(r"[—―]|──|——")
_CONNECTOR_HEAD = re.compile(r"^(また|さらに|加えて)、")
_SENTENCE_MIN_DUP = 20


def strip_code_blocks(text: str) -> str:
    return re.sub(r"(?ms)^```.*?^```\s*$", "", text)


def prose_lines(text: str) -> list[str]:
    """Lines of running prose: no headings, tables, or bullet markers."""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "|", ">")):
            continue
        out.append(re.sub(r"^[-*+]\s+|^\d+\.\s+", "", stripped))
    return out


def sentences(lines: list[str]) -> list[str]:
    sents: list[str] = []
    # One sentence per line is the source convention, but paragraphs may still
    # hold multiple sentences; split on 。 and keep the terminator.
    for line in lines:
        sents.extend(s + "。" for s in line.split("。") if s.strip())
    return sents


def check_llm_phrases(text: str) -> dict:
    hits: list[str] = []
    for phrase in LLM_PHRASES:
        for m in re.finditer(re.escape(phrase), text):
            line = text[: m.start()].count("\n") + 1
            hits.append(f"{phrase} (line {line})")
    return _result(
        "llm_phrases", "LLM 定型表現",
        hits, "空虚な定型表現を {n} 件検出(規範「LLM っぽい表現の禁止」参照)",
    )


def check_long_sentences(sents: list[str], limit: int) -> dict:
    hits = [s[:60] + "…" for s in sents if len(s) > limit]
    return _result(
        "long_sentence", "長すぎる一文",
        hits, f"{limit} 文字を超える文を {{n}} 件検出(分割を検討)",
    )


def check_duplicates(sents: list[str]) -> dict:
    counts = Counter(s for s in sents if len(s) >= _SENTENCE_MIN_DUP)
    hits = [f"{s[:60]}… ×{n}" if len(s) > 60 else f"{s} ×{n}"
            for s, n in counts.items() if n >= 2]
    return _result(
        "duplicate_sentence", "同一文の重複",
        hits, "同じ文が複数回現れます({n} 種)。一つの主張は一度だけ書く",
    )


def check_dashes(lines: list[str]) -> dict:
    # 【…】 spans hold mandated boilerplate (the draft watermark 「【ドラフト —
    # 最終版ではありません】」 is required verbatim by lint_draft.py) — exempt.
    hits = [line[:60] for line in lines
            if _DASH.search(re.sub(r"【[^】]*】", "", line))]
    return _result(
        "dash_usage", "地の文のダッシュ",
        hits, "ダッシュ(—/―/──)を {n} 行で検出。括弧・読点・二文分割に置き換える",
    )


def check_connector_chains(text: str) -> dict:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    hits: list[str] = []
    run: list[str] = []
    for para in paragraphs:
        head = para.splitlines()[0].strip()
        if _CONNECTOR_HEAD.match(head):
            run.append(head[:30])
            if len(run) == 3:
                hits.append(" / ".join(run))
        else:
            run = []
    return _result(
        "connector_chains", "接続詞の連打",
        hits, "「また/さらに/加えて」で始まる段落が3連続({n} 箇所)。論理関係を示す接続に変える",
    )


def _result(key: str, label: str, hits: list[str], detail_tpl: str) -> dict:
    status = "warn" if hits else "pass"
    detail = detail_tpl.format(n=len(hits)) if hits else "問題なし"
    return {"key": key, "label": label, "status": status,
            "detail": detail, "samples": hits[:8]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--max-sentence", type=int, default=200)
    args = parser.parse_args()

    try:
        raw = args.file.read_text(encoding="utf-8")
    except OSError as e:
        print(f"error: cannot read {args.file}: {e}", file=sys.stderr)
        return 2

    text = strip_code_blocks(raw)
    lines = prose_lines(text)
    sents = sentences(lines)

    checks = [
        check_llm_phrases(text),
        check_long_sentences(sents, args.max_sentence),
        check_duplicates(sents),
        check_dashes(lines),
        check_connector_chains(text),
    ]
    warn_count = sum(1 for c in checks if c["status"] == "warn")
    print(json.dumps(
        {"file": str(args.file), "warn_count": warn_count, "checks": checks},
        ensure_ascii=False, indent=2,
    ))
    return 0  # advisory: warnings never block


if __name__ == "__main__":
    sys.exit(main())
