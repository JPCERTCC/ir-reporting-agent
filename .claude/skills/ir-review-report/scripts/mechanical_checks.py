#!/usr/bin/env python3
"""Objective, checklist-independent checks over a submitted IR report.

These are the mechanical signals a reviewer can compute without judgment:
timezone declaration, defang formatting of attacker IoCs, access-warning notes,
evidence-ID linkage, section presence, and coarse overclaim detection. The
review skill uses these as a first pass; the agent still makes the qualitative
calls and cross-references them to checklist items.

The report is plain text or Markdown. For PDF/Word, extract to text first
(e.g. with the pdf / docx skills) and pass the extracted text here.

Output (stdout, JSON): {"checks": [{"key","label","status","detail","samples"}]}
status is one of: pass | warn | info. "warn" means a reviewer should look.

Usage:
    python mechanical_checks.py --report <path-to-report.md|.txt>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Raw (non-defanged) IPv4, excluding common private/loopback ranges.
_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
_PRIVATE = re.compile(r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.)")
# Raw URLs still clickable (http/https, not hxxp).
_RAW_URL = re.compile(r"https?://[^\s)\]\">]+")
# Bare domains not defanged (has a dot, no [.] and no hxxp); heuristic.
_BARE_DOMAIN = re.compile(
    r"(?<![\w@./\[])((?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|jp|co|link|live))(?![\w.\[])"
)

_STAGE_TERMS = ["情報漏えい", "情報漏洩", "漏えい", "漏洩", "窃取", "持ち出し",
                "初期侵入", "侵入経路", "侵害範囲"]
# A stage-term sentence is a candidate overclaim only if it asserts (past-tense
# completion) AND carries no hedge/negation. Hedges include uncertainty markers
# and any "...できない/できません/不明" negation so that sentences like
# 「断定はできません」「原因は不明です」 are never flagged.
_HEDGES = ["可能性", "示唆", "考えられ", "とみられ", "推測", "推定",
           "確認できな", "特定できな", "判断でき", "疑い", "おそれ",
           "断定でき", "断定しない", "断定しません", "断定せず", "断定を避け",
           "できません", "できない", "不明", "確認されなかった",
           "確認されませんでした", "痕跡はなかった", "検出されなかった"]
_ASSERT = ["された", "されました", "しました", "しています", "された。", "確定した",
           "判明した", "漏えいした", "漏洩した", "窃取された", "窃取しました",
           "侵入した", "発生しています", "発生した", "発生しました"]


def _samples(matches: list[str], n: int = 5) -> list[str]:
    seen: list[str] = []
    for m in matches:
        if m not in seen:
            seen.append(m)
        if len(seen) >= n:
            break
    return seen


def _split_sentences(text: str) -> list[str]:
    # Split on Japanese and ASCII sentence enders; keep it simple.
    parts = re.split(r"(?<=[。\.!?！？\n])", text)
    return [p.strip() for p in parts if p.strip()]


def _strip_code_blocks(text: str) -> str:
    return re.sub(r"(?ms)^```.*?^```\s*$", "", text)


def _valid_ip(value: str) -> bool:
    """True if every octet is 0-255 (rejects table-concatenation artifacts)."""
    return all(0 <= int(o) <= 255 for o in value.split("."))


# Authoring guidance is not an incident assertion (誤検出削減):
# template notes, structure explanations, examples, and instruction sentences
# must not be scanned for overclaims.
_GUIDANCE_SECTION = re.compile(
    r"調査目的|参考文献|References|本資料の取扱い|留意事項|チェックリスト"
)
_GUIDANCE_SENTENCE = re.compile(
    r"を記載します|を記載してください|を確認してください|を検討してください|"
    r"を説明します|本節では|本章では|記載例|サンプル|例[::)]|note-block|"
    r"^>\s"
)


def _prose_for_overclaim(text: str) -> str:
    """Prose with guidance sections/sentences removed (overclaim scan input)."""
    kept: list[str] = []
    in_guidance_section = False
    for line in _strip_code_blocks(text).splitlines():
        stripped = line.strip()
        if re.match(r"^#{1,6}\s+", stripped):
            in_guidance_section = bool(_GUIDANCE_SECTION.search(stripped))
            continue
        if in_guidance_section or _GUIDANCE_SENTENCE.search(stripped):
            continue
        kept.append(line)
    return "\n".join(kept)


def run_checks(text: str) -> list[dict]:
    checks: list[dict] = []
    # Raw IoCs inside fenced code blocks are verbatim log excerpts — evidence
    # fidelity wins there. Defang and overclaim checks strip code blocks and
    # authoring guidance (see _prose_for_overclaim).

    def add(key, label, status, detail, samples=None):
        checks.append({
            "key": key, "label": label, "status": status,
            "detail": detail, "samples": samples or [],
        })

    # 1) Timezone declared
    tz = re.search(r"タイムゾーン|\bJST\b|\bUTC\b|\bAsia/Tokyo\b|\+09:?00", text)
    add("timezone_declared", "タイムゾーンの明記", "pass" if tz else "warn",
        "時刻基準となるタイムゾーンの記載を検出" if tz
        else "タイムゾーンの明記が見つかりません(必須項目)")

    # 2) Defang of attacker IoCs — raw public IPs / URLs / domains.
    # Guidance sections (参考文献, examples, template notes) are excluded:
    # reference URLs and sample values are not attacker IoCs.
    ioc_prose = _prose_for_overclaim(text)
    raw_ips = [
        ip for ip in _IPV4.findall(ioc_prose)
        if not _PRIVATE.match(ip) and _valid_ip(ip)
    ]
    raw_urls = _RAW_URL.findall(ioc_prose)
    raw_domains = _BARE_DOMAIN.findall(ioc_prose)
    n_raw = len(raw_ips) + len(raw_urls) + len(raw_domains)
    if n_raw:
        add("defang_ioc", "IoC の defang 形式", "warn",
            f"defang されていない可能性のある値を {n_raw} 件検出"
            "(攻撃関連であれば 203[.]0[.]113[.]10 / hxxps:// 形式にする)",
            _samples(raw_ips + raw_urls + raw_domains))
    else:
        add("defang_ioc", "IoC の defang 形式", "pass",
            "clickable な生の IP/URL/ドメインは検出されませんでした")

    # 3) Access-warning note for attacker IoCs
    warn = re.search(r"アクセス(?:し(?:ては|ない)|禁止)|接続しないで|クリックしないで", text)
    add("ioc_access_warning", "攻撃関連IoCへのアクセス禁止注記",
        "pass" if warn else "warn",
        "アクセス禁止の注記を検出" if warn
        else "攻撃関連IoCへのアクセス禁止の注記が見つかりません(必須項目)")

    # 4) Contact point
    contact = re.search(r"問い合わせ|問合せ|連絡先|担当窓口|お問合せ|連絡窓口", text)
    add("contact_point", "問い合わせ先の記載", "pass" if contact else "warn",
        "問い合わせ先の記載を検出" if contact
        else "報告書に関する問い合わせ先が見つかりません(必須項目)")

    # 5) Disclaimer / point-in-time caveat
    disclaimer = re.search(
        r"免責|作成時点|調査時点|追加(?:資料|情報|調査).{0,6}(?:変更|変わる)", text
    )
    add("disclaimer", "免責・時点情報の記載", "pass" if disclaimer else "info",
        "免責/時点情報の記載を検出" if disclaimer
        else "免責事項・時点情報の記載が見当たりません(任意項目)")

    # 6) Evidence-ID linkage
    ev = re.findall(r"(?:証拠ID|evidence[ _-]?id|EV-\d+|証拠番号)", text, re.IGNORECASE)
    add("evidence_ids", "証拠IDによる根拠づけ", "pass" if ev else "warn",
        f"証拠ID相当の参照を {len(ev)} 件検出" if ev
        else "証拠IDによる根拠づけが見つかりません(必須項目)")

    # 7) Undetermined / limitation acknowledgement
    limits = re.findall(
        r"確認できな|特定できな|判断でき(?:ない|ず)|未確認|調査対象外"
        r"|ログ(?:欠損|不足|未取得)",
        text,
    )
    add("limitations_stated", "未確認事項・調査上の制約の記載",
        "pass" if limits else "warn",
        f"制約・未確認の記載を {len(limits)} 件検出" if limits
        else "調査上の制約や未確認事項の記載が見当たりません(必須項目)")

    # 8) Section presence signals
    for key, label, pattern in [
        ("exec_summary", "エグゼクティブサマリー", r"エグゼクティブサマリー|概要|サマリー"),
        ("timeline", "インシデントタイムライン", r"タイムライン|時系列"),
        ("ioc_list", "IoC一覧", r"\bIoC\b|\bIOC\b|Indicator|侵害指標"),
        ("attack_mapping", "MITRE ATT&CK 対応表", r"ATT&CK|MITRE"),
        ("containment", "封じ込め・復旧", r"封じ込め|復旧|根絶"),
        ("recurrence", "再発防止策", r"再発防止|恒久対策|対策案"),
    ]:
        found = re.search(pattern, text)
        add(key, f"{label}の有無", "pass" if found else "info",
            f"{label} に関する記載を検出" if found
            else f"{label} に相当する記載が見当たりません")

    # 9) Coarse overclaim detection (prose only, guidance excluded)
    overclaims: list[str] = []
    for sent in _split_sentences(_prose_for_overclaim(text)):
        if any(t in sent for t in _STAGE_TERMS):
            has_hedge = any(h in sent for h in _HEDGES)
            has_assert = any(a in sent for a in _ASSERT)
            if has_assert and not has_hedge:
                overclaims.append(sent[:120])
    if overclaims:
        add("overclaim", "過大主張の疑い", "warn",
            f"侵入・漏えい等について、確度表現を伴わない断定的記述を {len(overclaims)} 件検出",
            _samples(overclaims, 6))
    else:
        add("overclaim", "過大主張の疑い", "pass",
            "侵入・漏えい等の断定的記述で確度表現を欠くものは検出されませんでした")

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if not args.report.exists():
        print(f"error: report not found: {args.report}", file=sys.stderr)
        return 2
    text = args.report.read_text(encoding="utf-8", errors="replace")
    checks = run_checks(text)
    warns = sum(1 for c in checks if c["status"] == "warn")
    print(json.dumps({"report": str(args.report), "warn_count": warns,
                      "checks": checks}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
