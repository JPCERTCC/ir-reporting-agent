"""Deterministic checks for the agent-written Japanese draft report.

One pass reports every problem at once (no FAIL → fix → FAIL loop):

- structure: watermark, the headings of templates/report_template_ja.md, reviewer fill-in sections,
  forbidden wording, defang, metadata dates;
- completeness: no ``【要記入`` skeleton marker left unwritten;
- carry-over: every analysis result approved at CP2 is cited in the section it
  is routed to, and every gap accepted as a limitation is mentioned — so what
  the human approved cannot silently drop out of the report;
- grounding: cited EV-### exist, chapter-4 log lines are verbatim ledger
  excerpts, IP addresses in prose exist in the case material.

Advisory warnings (never failures) flag sentences that assert attacker
activity while every cited evidence item has only a weak interpretation.

Used by the skill script lint_draft.py and by ``ir-agent check-draft``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ir_agent.governance.injection_guard import processing_note_hits
from ir_agent.reporting import report_template

Material = dict[str, Any]

PLACEHOLDER = "【要記入"
# Pristine copy of the CLI-generated skeleton, written next to the draft.
SKELETON_NAME = "draft_skeleton.md"

# Structure comes from the template (templates/report_template_ja.md) so the
# lint, the skeleton and the template cannot drift apart.
REQUIRED_HEADINGS = report_template.required_headings()
SECTION_HEADINGS = {h.split()[1]: h for h in REQUIRED_HEADINGS if h.startswith("### 3.")}
REVIEW_COMMENT_SECTIONS = report_template.reviewer_sections()

FORBIDDEN_PATTERNS = [
    (r"(?m)^##\s*5\.\s*調査上の制約", "5章を「調査上の制約」にしてはいけない"),
    (r"(?m)^##\s*6\.", "6章を新設してはいけない"),
    (r"Claim", "ユーザー向け文書では「Claim」ではなく「分析結果」と書く"),
    (r"ギャップ", "「ギャップ」ではなく「不足事項」と書く"),
    (r"```mermaid", "概要図にMermaidは使わない(箇条書きまたはASCII図)"),
    (r"確認されています", "完了報告のため過去形「確認されました」を使う"),
]

# Checked against prose only (fenced code blocks stripped first), because raw
# log excerpts legitimately contain UTC timestamps and other flagged strings.
PROSE_FORBIDDEN_PATTERNS = [
    (r"\*\*", "強調記法(**太字**)は使わない — フォーマルな報告書では文章構成で強調する"),
    (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?Z",
     "本文の時刻は report_timezone に変換して「2026-05-01 22:18 (UTC)」形式にする"
     "(ISO/UTC生値はコードブロック内のログ抜粋のみ)"),
    (r"精読した結果|ケース材料|入力JSON|case_material",
     "生成プロセスを語るメタ表現は使わない — 分析担当者の所見として書く"),
]

# Checked against prose with code blocks and HTML comments removed: the text a
# customer reads once the report is finalized. finalize-report only swaps the
# watermark and the metadata, so the body must already read as the final text.
CUSTOMER_PROSE_PATTERNS = [
    (r"本ドラフト|最終版まで|最終版作成時|最終版では(?!ありません)|正式な最終報告書では",
     "本文で自らを「ドラフト」と呼んだり最終版への作業指示を書かない — 確定時にそのまま"
     "顧客へ出る。人間が記入・確認すべき事項は品質レビュー文書に残す"),
    (r"manifest|ir-agent|check-draft|draft_skeleton|workflow_state|証拠候補|レビュー文書",
     "ツール内部(manifest・ir-agent・検査コマンド・中間ファイル)に言及しない — "
     "調査範囲や手法は顧客の言葉で書く"),
]

WEAK_CONFIDENCE = {"possible", "unknown", "not_observed"}
_ASSERTIVE = re.compile(r"確認されました|判明しました|断定|特定されました")
_ATTRIBUTION = re.compile(r"攻撃者|侵害|窃取|持ち出|漏えい|不正|C2")
_HEDGE = re.compile(r"可能性|と考えられ|推定|示唆|疑われ")
# Gaps check-gaps adds for the source coverage of the whole case.
CASE_SCOPE_CLAIM_ID = "CASE-SCOPE"

_RAW_IPV4 = re.compile(r"(?<![\d.\[])((?:\d{1,3}\.){3}\d{1,3})(?![\d.\]])")
_ANY_IPV4 = re.compile(r"(?<![\d\]])(\d{1,3}(?:\[?\.\]?\d{1,3}){3})(?![\d\[])")
_PRIVATE_IP = re.compile(
    r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.|169\.254\.)"
)
# RFC 5737 documentation ranges appear in the fixed defang example text.
_DOC_IP = re.compile(r"^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)")
_RAW_URL = re.compile(r"https?://[^\s)\]\">`]+")
_HTML_COMMENT = re.compile(r"(?s)<!--.*?-->")
_FENCE = re.compile(r"(?ms)^(`{3,})[^\n]*\n(.*?)^\1\s*$")


@dataclass
class LintResult:
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures


def strip_code_blocks(draft: str) -> str:
    return _FENCE.sub("", draft)


def section_body(draft: str, heading: str) -> str:
    match = re.search(rf"(?m)^{re.escape(heading)}\s*(\{{#[^}}]*\}})?\s*$", draft)
    if not match:
        return ""
    level = len(heading) - len(heading.lstrip("#"))
    nxt = re.compile(rf"(?m)^#{{1,{level}}}\s+").search(draft, match.end())
    return draft[match.end(): nxt.start() if nxt else len(draft)]


def defang_violations(prose: str) -> list[str]:
    hits = [
        ip for ip in _RAW_IPV4.findall(prose)
        if not _PRIVATE_IP.match(ip)
        and all(0 <= int(o) <= 255 for o in ip.split("."))
    ]
    # Internal-only URLs (.local hosts) are infrastructure references, not IoCs.
    hits += [u for u in _RAW_URL.findall(prose)
             if not re.match(r"https?://[^/\s]*\.local(?:[/:]|$)", u)]
    return list(dict.fromkeys(hits))


def defang_text(text: str) -> str:
    """``text`` with the IoCs :func:`defang_violations` flags written defanged."""
    for hit in defang_violations(text):
        safe = (hit.replace(".", "[.]") if _RAW_IPV4.fullmatch(hit)
                else re.sub(r"^http", "hxxp", hit))
        text = re.sub(rf"(?<![\w\[.]){re.escape(hit)}(?![\w\].])", safe, text)
    return text


def _parse_iso_date(value: str) -> date | None:
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", value)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def check_metadata_dates(draft: str, material: Material | None,
                         today: date | None = None) -> list[str]:
    """作成日 / 報告時点 / first change-history date: well-formed, at or after
    the investigation end, and near the run date (UP-03)."""
    failures: list[str] = []
    today = today or date.today()
    end_dt = None
    if material:
        end_raw = material.get("case", {}).get("time_range_utc", {}).get("end", "")
        end_dt = _parse_iso_date(end_raw or "")

    checked: list[tuple[str, str]] = []
    for label in ("作成日", "報告時点"):
        m = re.search(rf"\|\s*{label}\s*\|\s*([^|]+?)\s*\|", draft)
        if m:
            checked.append((label, m.group(1).strip()))
    hist = re.search(
        r"(?m)^\|\s*0?\.?1[^|]*\|\s*([0-9]{4}-[0-9]{2}-[0-9]{2}[^|]*)\|", draft
    )
    if hist:
        checked.append(("変更履歴", hist.group(1).strip()))

    for label, raw in checked:
        d = _parse_iso_date(raw)
        if d is None:
            failures.append(f"{label}の日付が YYYY-MM-DD 形式でない: {raw!r}")
            continue
        if end_dt and d < end_dt:
            failures.append(f"{label}({d}) が調査対象期間の終了日({end_dt})より前になっている")
        if d > today + timedelta(days=1):
            failures.append(f"{label}({d}) が未来日になっている(実行日: {today})")
        elif d < today - timedelta(days=7):
            failures.append(
                f"{label}({d}) が実行日({today})から7日以上離れている。"
                "生成日の年月日が誤っている可能性がある"
            )
    return failures


def _placeholder_locations(draft: str) -> list[str]:
    where: list[str] = []
    heading = "(冒頭)"
    for line in draft.splitlines():
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
        if PLACEHOLDER in line and heading not in where:
            where.append(heading)
    return where


def _material_text(material: Material) -> str:
    """All fact-bearing text of the material, IPs normalized to dotted form."""
    blob = json.dumps(
        {k: material.get(k) for k in ("evidence_ledger", "approved_claims", "timeline")},
        ensure_ascii=False,
    )
    return blob.replace("[.]", ".")


def check_carry_over(draft: str, material: Material) -> list[str]:
    failures: list[str] = []
    for claim in material.get("approved_claims", []):
        evs = claim.get("supporting_evidence") or []
        if not evs:
            continue
        sec = claim.get("report_section")
        heading = SECTION_HEADINGS.get(sec)
        body = section_body(draft, heading) if heading else draft
        if not any(ev in body for ev in evs):
            where = f"{sec} 節" if heading else "本文"
            failures.append(
                f"承認済みの分析結果 {claim.get('claim_id')}({sec}) が{where}に"
                f"反映されていない(根拠証拠 {', '.join(evs)} のいずれも{where}で引用されていない)"
            )
        for other, mapped in report_template.cross_section_mappings(claim).items():
            heading = SECTION_HEADINGS.get(other)
            if heading and not any(ev in section_body(draft, heading) for ev in mapped):
                failures.append(
                    f"承認済みの分析結果 {claim.get('claim_id')}({sec}) は {other} 節の戦術にも"
                    f"対応付けられているが、{other} 節で根拠証拠 {', '.join(mapped)} の"
                    "いずれも引用されていない(該当する事象は該当節に記載する)"
                )
    missing = [g["gap_id"] for g in material.get("gaps", [])
               if g.get("disposition") == "accepted_as_limitation"
               and g.get("gap_id") and g["gap_id"] not in draft]
    if missing:
        failures.append(
            "制約として受け入れた不足事項が本文に記載されていない"
            f"(「（不足事項ID: …）」で該当所見に併記する): {missing}"
        )
    # Source-coverage gaps describe what the report did not look at; they must
    # be disclosed whatever the disposition, or unanalysed files vanish silently.
    scope = [g["gap_id"] for g in material.get("gaps", [])
             if g.get("related_claim_id") == CASE_SCOPE_CLAIM_ID
             and g.get("gap_id") and g["gap_id"] not in draft]
    if scope:
        failures.append(
            "ケース全体の不足事項(提供資料の未抽出・未承認など)が本文に記載されていない"
            f"(処置に関わらず 1.4 調査範囲・制約 などに不足事項IDを併記する): {scope}"
        )
    return failures


def check_chapter4_verbatim(draft: str, material: Material) -> list[str]:
    excerpts = [r.get("excerpt") or ""
                for e in material.get("evidence_ledger", [])
                for r in e.get("source_refs", [])]
    if not any(excerpts):
        return []
    bad: list[str] = []
    for _, block in _FENCE.findall(section_body(draft, "## 4. 対象別調査結果詳細")):
        for line in block.splitlines():
            text = line.strip()
            if text and not any(text in x for x in excerpts) and text not in bad:
                bad.append(text)
    if not bad:
        return []
    return [f"4章のログ抜粋に証拠台帳の excerpt と一致しない行がある({len(bad)} 行。"
            f"抜粋は改変せず逐語で掲載する): {[b[:60] for b in bad[:3]]}"]


def check_unknown_ips(prose: str, material: Material) -> list[str]:
    if not any(r.get("excerpt") for e in material.get("evidence_ledger", [])
               for r in e.get("source_refs", [])):
        return []
    known = _material_text(material)
    unknown = []
    for raw in _ANY_IPV4.findall(prose):
        ip = raw.replace("[.]", ".").replace("[", "").replace("]", "")
        if _DOC_IP.match(ip) or not all(0 <= int(o) <= 255 for o in ip.split(".")):
            continue
        if not re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d])", known) and ip not in unknown:
            unknown.append(ip)
    if not unknown:
        return []
    return [f"証拠に存在しないIPアドレスが本文・表に書かれている(事実を作らない): {unknown[:5]}"]


def _units(prose: str) -> list[str]:
    """Sentences (split on 。) and lines — the unit a citation applies to."""
    return [u for line in prose.splitlines() for u in re.split(r"(?<=。)", line) if u.strip()]


def _short(text: str) -> str:
    return " ".join(text.split())[:80]


def check_weak_assertions(prose: str, material: Material) -> tuple[list[str], list[str]]:
    """Assertive attribution needs confirmed evidence or a hedge.

    Fails when a sentence asserts attacker activity (確認されました + 攻撃者/侵害…)
    while none of its cited evidence has a confirmed interpretation and the
    sentence carries no hedge. Hedged sentences resting only on possible/unknown
    evidence are still warned about.
    """
    conf = {e.get("report_evidence_id"): e.get("interpretation_confidence")
            for e in material.get("evidence_ledger", [])}
    if not any(conf.values()):
        return [], []
    failures: list[str] = []
    warnings: list[str] = []
    for unit in _units(prose):
        cited = re.findall(r"EV-\d{3}", unit)
        if not (cited and _ASSERTIVE.search(unit) and _ATTRIBUTION.search(unit)):
            continue
        if any(conf.get(ev) == "confirmed" for ev in cited):
            continue
        if not _HEDGE.search(unit):
            failures.append(
                "根拠証拠の解釈確度に confirmed がないのに攻撃・侵害を断定している"
                f"(確度に応じて「〜の可能性があります」等で表現する): {_short(unit)}"
            )
        elif all(conf.get(ev) in WEAK_CONFIDENCE for ev in cited):
            warnings.append(
                "根拠証拠の解釈確度がすべて possible/unknown なのに断定している可能性: "
                f"{_short(unit)}"
            )
    return failures, warnings


def weak_assertion_warnings(prose: str, material: Material) -> list[str]:
    return check_weak_assertions(prose, material)[1]


# --- time grounding -------------------------------------------------------

_DATE = r"(?:(?P<{0}>\d{{4}}-\d{{2}}-\d{{2}})\s*)?"
_HM = r"(?P<{0}>(?:[01]?\d|2[0-3]):[0-5]\d)(?::[0-5]\d)?"
_TIME_EXPR = re.compile(
    r"(?<![\d:.\w\\/\-])"
    + _DATE.format("d1") + _HM.format("t1")
    + r"(?:\s*[-〜~–]\s*" + _DATE.format("d2") + _HM.format("t2") + r")?"
    + r"(?![\d:])"
    + r"(?P<label>\s*[（(]\s*(?P<tz>[A-Za-z][A-Za-z0-9+:\-/_]*)\s*[)）]|\s+(?P<tz2>UTC|JST|GMT))?"
)
_ISO_TS = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})"
)
_INLINE_CODE = re.compile(r"`[^`\n]*`")


def _report_zone(material: Material | None) -> tuple[Any, str]:
    name = ((material or {}).get("case", {}) or {}).get("report_timezone") or "UTC"
    try:
        from zoneinfo import ZoneInfo

        zone: Any = ZoneInfo(name)
    except Exception:
        return timezone.utc, "UTC"
    label = datetime.now(zone).tzname() or name
    return zone, label


def _parse_ts(value: str, zone: Any) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(zone).replace(second=0, microsecond=0, tzinfo=None)


def _evidence_times(material: Material, zone: Any) -> dict[str, list[datetime]]:
    times: dict[str, list[datetime]] = {}
    for entry in material.get("evidence_ledger", []):
        ev = entry.get("report_evidence_id")
        if not ev:
            continue
        raw = [str((entry.get("observed_event") or {}).get("timestamp") or "")]
        raw += [m for r in entry.get("source_refs", [])
                for m in _ISO_TS.findall(r.get("excerpt") or "")]
        times.setdefault(ev, []).extend(t for t in (_parse_ts(x, zone) for x in raw if x) if t)
    for item in material.get("timeline", []):
        ev = item.get("evidence_id")
        t = _parse_ts(str(item.get("event_time") or ""), zone)
        if ev and t:
            times.setdefault(ev, []).append(t)
    return times


def _time_prose(prose: str) -> str:
    # Inline code spans quote raw log text verbatim; they are not report times.
    return _INLINE_CODE.sub("", prose)


def check_time_labels(prose: str, material: Material | None) -> list[str]:
    """Every time in prose carries the report_timezone label, e.g. ``22:44 (UTC)``."""
    _, label = _report_zone(material)
    bad: list[str] = []
    for m in _TIME_EXPR.finditer(_time_prose(prose)):
        tz = m.group("tz") or m.group("tz2")
        if tz != label:
            snippet = m.group(0).strip()
            if snippet not in bad:
                bad.append(snippet)
    if not bad:
        return []
    return [f"本文・表の時刻にタイムゾーン表記「({label})」がない、または異なる"
            f"(時刻は report_timezone={label} に統一し「2026-05-01 22:44 ({label})」と書く。"
            f"{len(bad)} 種): {bad[:5]}"]


def check_times_against_evidence(prose: str, material: Material) -> list[str]:
    """Times written next to EV citations must be times those EVs carry."""
    zone, label = _report_zone(material)
    ev_times = _evidence_times(material, zone)
    if not ev_times:
        return []
    slack = timedelta(minutes=1)
    bad: list[str] = []
    for unit in _units(_time_prose(prose)):
        cited = [ev for ev in dict.fromkeys(re.findall(r"EV-\d{3}", unit)) if ev_times.get(ev)]
        if not cited:
            continue
        known = sorted({t for ev in cited for t in ev_times[ev]})
        dates = sorted({t.date() for t in known})
        lo, hi = known[0] - slack, known[-1] + slack
        for m in _TIME_EXPR.finditer(unit):
            for dkey, tkey in (("d1", "t1"), ("d2", "t2")):
                hm = m.group(tkey)
                if not hm:
                    continue
                raw_date = m.group(dkey) or m.group("d1")
                candidates = ([raw_date] if raw_date else [d.isoformat() for d in dates])
                ok = False
                for d in candidates:
                    try:
                        t = datetime.fromisoformat(f"{d} {int(hm[:-3]):02d}:{hm[-2:]}")
                    except ValueError:
                        continue
                    if lo <= t <= hi:
                        ok = True
                        break
                if not ok:
                    bad.append(f"{m.group(0).strip()} ↔ {','.join(cited)}: {_short(unit)[:50]}")
                    break
    if not bad:
        return []
    return [f"本文の時刻が引用した証拠の時刻({label}換算)と一致しない"
            f"(証拠の時刻を {label} のまま転記する。{len(bad)} 箇所): {bad[:4]}"]


# --- skeleton preservation -------------------------------------------------

def check_skeleton_preserved(draft: str, skeleton: str | None) -> list[str]:
    """CLI-generated fixed text (everything without 【要記入) stays verbatim."""
    if not skeleton:
        return []
    lines = {line.strip() for line in draft.splitlines()}
    missing = [line.strip() for line in skeleton.splitlines()
               if line.strip() and PLACEHOLDER not in line and line.strip() not in lines]
    missing = list(dict.fromkeys(missing))
    if not missing:
        return []
    return [f"雛形(reports/draft_skeleton.md)の固定文が改変・削除されている"
            f"(【要記入】以外の行は CLI 生成のまま残す。{len(missing)} 行): "
            f"{[m[:60] for m in missing[:4]]}"]


# --- entity grounding ------------------------------------------------------

_FILE_NAME = re.compile(
    r"(?<![\w.\-$])([\w\-$]+(?:\.[\w\-]+)*\."
    r"(?:exe|dll|ps1|bat|cmd|rar|zip|7z|vbs|js|sh|py|php|aspx|jsp|xlsx|docx|evtx))"
    r"(?![\w])",
    re.IGNORECASE,
)
_HASH = re.compile(
    r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
)


def _known_text(material: Material, skeleton: str | None) -> str:
    extra = json.dumps(material.get("source_coverage"), ensure_ascii=False)
    return (_material_text(material) + extra + (skeleton or "")).lower().replace("\\\\", "\\")


def check_unknown_entities(prose: str, material: Material, skeleton: str | None) -> list[str]:
    """File names and hashes in prose must occur in the evidence material."""
    # A ledger without excerpts (an ID-only stub) has nothing to ground against.
    if not any(r.get("excerpt") for e in material.get("evidence_ledger", [])
               for r in e.get("source_refs", [])):
        return []
    known = _known_text(material, skeleton)
    names = [n for n in dict.fromkeys(_FILE_NAME.findall(prose)) if n.lower() not in known]
    hashes = [h for h in dict.fromkeys(_HASH.findall(prose)) if h.lower() not in known]
    out: list[str] = []
    if names:
        out.append("証拠に存在しないファイル名が本文・表に書かれている"
                   f"(事実を作らない): {names[:5]}")
    if hashes:
        out.append("証拠に存在しないハッシュ値が本文・表に書かれている"
                   f"(事実を作らない): {hashes[:3]}")
    return out


# --- negative claims contradicting evidence --------------------------------

_NEGATION = (
    r"[^。\n]{0,40}?(?:確認でき(?:ませんでした|なかった)|確認されませんでした"
    r"|認められませんでした|ありませんでした|見られませんでした)"
)
_NEG_EXTERNAL = re.compile(r"外部(?:への|との)?(?:通信|接続)" + _NEGATION)
_NEG_EXFIL = re.compile(r"(?:持ち出し|外部送信|流出|アップロード)" + _NEGATION)
_NEG_QUALIFIER = re.compile(r"以外|を除|上記|内容|範囲|有無|かどうか|か否か|他の|ほか|詳細|全容")
_TRANSFER = re.compile(r"\b(?:sftp|scp|ftp|rclone|upload|put|curl|wget|megacmd)\b", re.IGNORECASE)


def check_negative_contradictions(prose: str, material: Material) -> list[str]:
    """「外部通信は確認できなかった」 while the evidence shows external traffic."""
    excerpts = " ".join(r.get("excerpt") or "" for e in material.get("evidence_ledger", [])
                        for r in e.get("source_refs", []))
    if not excerpts:
        return []
    public = sorted({ip for ip in _RAW_IPV4.findall(excerpts.replace("[.]", "."))
                     if not _PRIVATE_IP.match(ip)
                     and all(0 <= int(o) <= 255 for o in ip.split("."))})
    transfer = bool(_TRANSFER.search(excerpts))
    out: list[str] = []
    for unit in _units(prose):
        if _NEG_QUALIFIER.search(unit):
            continue
        if public and _NEG_EXTERNAL.search(unit):
            out.append(f"「外部通信なし」と書いているが証拠に外部IP({', '.join(public[:3])})"
                       f"への通信がある: {_short(unit)}")
        elif transfer and _NEG_EXFIL.search(unit):
            out.append(f"「持ち出し・送信なし」と書いているが証拠にファイル転送の記録がある: "
                       f"{_short(unit)}")
    return out


_PADDING = re.compile(
    r"(提供資料|資料)(から|上|では|からは|上は)?[^。\n]{0,20}確認でき(ません|ない|ず)"
)


def reviewer_text(draft: str, heading: str) -> str:
    """What a reviewer section holds once its fill-in comment is removed."""
    return _HTML_COMMENT.sub("", section_body(draft, heading)).strip()


def empty_reviewer_sections(draft: str) -> list[str]:
    """Reviewer sections present in ``draft`` with nothing but the fill-in comment."""
    return [h for h in REVIEW_COMMENT_SECTIONS
            if re.search(rf"(?m)^{re.escape(h)}\s*$", draft) and not reviewer_text(draft, h)]


def check_reviewer_padding(draft: str) -> list[str]:
    """Reviewer sections are the human's to fill: no "not in the materials" filler."""
    padded = [h for h in REVIEW_COMMENT_SECTIONS if _PADDING.search(reviewer_text(draft, h))]
    if not padded:
        return []
    return [f"レビュー担当者記入欄 {padded} を「提供資料からは確認できない」旨の文で埋めない — "
            "これらは人間が持つ情報(経緯・連絡先・手法・ヒアリング・保全記録)の欄。空欄のまま"
            "人間に渡し、人間が示した内容だけを記入する"]


def final_problems(final: str) -> list[str]:
    """Why ``final`` (the finalize-report output) may not be issued to the customer."""
    out = []
    if PLACEHOLDER in final:
        out.append(f"未執筆の【要記入】が {final.count(PLACEHOLDER)} 箇所残っている")
    if "<!--" in final:
        out.append("レビュー用の HTML コメントが残っている")
    visible = _HTML_COMMENT.sub("", strip_code_blocks(final))
    for pattern, message in CUSTOMER_PROSE_PATTERNS:
        hits = re.findall(pattern, visible)
        if hits:
            out.append(f"{message}(検出 {len(hits)} 箇所: {sorted(set(hits))[:5]})")
    drafty = [ln.strip()[:40] for ln in visible.splitlines()
              if "ドラフト" in ln and "初版ドラフト作成" not in ln]
    if drafty:
        out.append(f"ドラフトを示す記載が残っている: {drafty[:3]}")
    if (re.search(r"(?m)^\|\s*版数\s*\|", final)
            and not re.search(r"(?m)^\|\s*版数\s*\|\s*1\.0（確定）\s*\|", final)):
        out.append("メタデータの版数が 1.0（確定）になっていない")
    if empty := empty_reviewer_sections(final):
        out.append(f"レビュー担当者記入欄が空のまま: {empty}")
    return out


def lint_draft(draft: str, material: Material | None, today: date | None = None,
               skeleton: str | None = None) -> LintResult:
    result = LintResult()
    fail = result.failures.append

    if not draft.lstrip().startswith("【ドラフト"):
        fail("冒頭に「【ドラフト — 最終版ではありません】」がない")
    for heading in REQUIRED_HEADINGS:
        if not re.search(rf"(?m)^{re.escape(heading)}\s*(\{{#[^}}]*\}})?\s*$", draft):
            fail(f"必須見出しがない: {heading}")

    locations = _placeholder_locations(draft)
    if locations:
        fail(f"未執筆の【要記入】が {draft.count(PLACEHOLDER)} 箇所残っている: {locations[:8]}")

    for pattern, message in FORBIDDEN_PATTERNS:
        if re.search(pattern, draft):
            fail(message)
    prose = strip_code_blocks(draft)
    for pattern, message in PROSE_FORBIDDEN_PATTERNS:
        hits = re.findall(pattern, prose)
        if hits:
            fail(f"{message}(検出 {len(hits)} 箇所)")
    visible = _HTML_COMMENT.sub("", prose)
    for pattern, message in CUSTOMER_PROSE_PATTERNS:
        hits = re.findall(pattern, visible)
        if hits:
            fail(f"{message}(検出 {len(hits)} 箇所: {sorted(set(hits))[:5]})")
    if note_hits := processing_note_hits(visible):
        fail("アーティファクト内の命令文の扱い(プロンプトインジェクション対策)は処理上の注意で"
             f"あり調査結果ではない — 報告書に書かない(検出: {note_hits[:5]})")
    raw_iocs = defang_violations(prose)
    if raw_iocs:
        fail("本文・表の攻撃関連IoCはdefang形式(203[.]0[.]113[.]10 / hxxps://)にする"
             f"(生の値 {len(raw_iocs)} 種: {raw_iocs[:5]})")

    notice = section_body(draft, "### 本報告書に関する留意事項")
    if notice and "アクセスしない" not in notice:
        fail("留意事項にIoCへのアクセス禁止の注記がない")
    for heading in REVIEW_COMMENT_SECTIONS:
        body = section_body(draft, heading)
        if body and "レビュー担当者記入欄" not in body:
            fail(f"{heading} のレビュー担当者記入欄コメントを削除しない")

    result.failures.extend(check_reviewer_padding(draft))

    cited = set(re.findall(r"EV-\d{3}", draft))
    if not cited:
        fail("証拠ID(EV-###)の引用が1件もない")
    if material is not None:
        known = {e.get("report_evidence_id") for e in material.get("evidence_ledger", [])}
        unknown = sorted(cited - known)
        if unknown:
            fail(f"素材に存在しない証拠IDを引用: {unknown}")
        unused = sorted(known - cited)
        if unused:
            result.warnings.append(f"未引用の証拠: {unused}")
        result.failures.extend(check_carry_over(draft, material))
        result.failures.extend(check_chapter4_verbatim(draft, material))
        result.failures.extend(check_unknown_ips(prose, material))
        result.failures.extend(check_unknown_entities(prose, material, skeleton))
        result.failures.extend(check_negative_contradictions(prose, material))
        result.failures.extend(check_times_against_evidence(prose, material))
        weak_fail, weak_warn = check_weak_assertions(prose, material)
        result.failures.extend(weak_fail)
        result.warnings.extend(weak_warn)
    else:
        result.warnings.append("case_material.json がないため証拠IDの実在検証をスキップ")

    result.failures.extend(check_metadata_dates(draft, material, today))
    result.failures.extend(check_time_labels(prose, material))
    result.failures.extend(check_skeleton_preserved(draft, skeleton))

    ch4 = section_body(draft, "## 4. 対象別調査結果詳細")
    if ch4 and "```" not in ch4:
        fail("4章に証拠ログ抜粋のコードブロックがない")
    return result


def lint_case(case_dir: Path, draft_path: Path | None = None) -> LintResult:
    draft_path = draft_path or case_dir / "reports" / "draft_report.md"
    material_path = case_dir / "reports" / "case_material.json"
    material = (json.loads(material_path.read_text(encoding="utf-8"))
                if material_path.exists() else None)
    skeleton_path = case_dir / "reports" / SKELETON_NAME
    skeleton = (skeleton_path.read_text(encoding="utf-8")
                if skeleton_path.exists() else None)
    result = lint_draft(draft_path.read_text(encoding="utf-8"), material, skeleton=skeleton)
    from ir_agent.reporting.skeleton_integrity import integrity_problems
    from ir_agent.workflow.workspace import case_layout_message, stray_case_entries

    result.failures += integrity_problems(case_dir)
    stray = stray_case_entries(case_dir)
    if stray:
        result.failures.append(case_layout_message(stray))
    return result
