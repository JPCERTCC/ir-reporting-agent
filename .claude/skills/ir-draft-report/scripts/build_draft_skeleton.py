#!/usr/bin/env python3
"""Generate the draft-report skeleton from the approved case material.

The structure (headings, fixed text, reviewer fill-in comments, table headers)
is copied from ir_agent/reporting/templates/report_template_ja.md — the single
source shared with the draft lint — in template order. Everything decided by
the data, not by judgment, is rendered deterministically: metadata dates,
the 2.4 timeline grid, the chapter-4 verbatim log excerpts (line breaks
preserved), and appendices A-C. The places that need
the analyst's writing are left as one-line ``【要記入: …】`` markers, each
naming the approved analysis results / evidence / gaps that belong there, so
nothing approved at CP2 has to be remembered across a long drafting session.

The Agent replaces every ``【要記入`` marker; lint_draft.py fails while any
remains. Called by build_case_material.py; it never overwrites an existing
reports/draft_report.md (move the old draft away to regenerate).

Usage:
    python build_draft_skeleton.py --case-dir <case>
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make the repository's ir_agent package importable without an install.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ir_agent.reporting import report_template as tpl  # noqa: E402
from ir_agent.reporting.draft_lint import defang_text  # noqa: E402

PLACEHOLDER = "【要記入"

# Timeline / ATT&CK confidence labels describe how strongly the logged event is
# read as attacker activity, never whether the event happened.
CONFIDENCE_LABEL = {
    "confirmed": "確認",
    "probable": "可能性が高い",
    "possible": "可能性あり",
    "unknown": "判断できず",
    "not_observed": "判断できず",
}
CONFIDENCE_RANK = {"confirmed": 4, "probable": 3, "possible": 2, "unknown": 1,
                   "not_observed": 0}

IOC_TYPE_LABEL = {
    "ip": "IPアドレス", "domain": "ドメイン", "url": "URL", "hash": "ハッシュ値",
    "file_path": "ファイルパス", "registry_key": "レジストリキー", "email": "メールアドレス",
}
_PRIVATE_IP = re.compile(
    r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.|169\.254\.)"
)

def _zone(name: str):
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name or "UTC")
    except Exception:
        return timezone.utc


def _tz_label(tz, when: datetime) -> str:
    label = when.astimezone(tz).tzname() or "UTC"
    return label


def to_local(value: str | None, tz) -> str:
    """ISO timestamp → 'YYYY-MM-DD HH:MM (UTC)'; '—' when unparseable."""
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone(tz)
    return f"{local:%Y-%m-%d %H:%M} ({_tz_label(tz, dt)})"


def cell(text) -> str:
    # Fixed table text must already pass check-draft's defang rule: the agent
    # may not edit it.
    return defang_text(" ".join(str(text or "").split())).replace("|", "\\|") or "—"


def lines_label(lines: list) -> str:
    if not lines:
        return "—"
    return f"{lines[0]}–{lines[-1]}" if len(lines) > 1 else str(lines[0])


def fence(excerpt: str) -> str:
    ticks = "```"
    while ticks in excerpt:
        ticks += "`"
    return f"{ticks}text\n{excerpt.rstrip(chr(10))}\n{ticks}"


def evidence_host(entry: dict) -> str:
    host = (entry.get("observed_event") or {}).get("host")
    if host:
        return str(host)
    refs = entry.get("source_refs") or []
    path = refs[0].get("source_path", "") if refs else ""
    return path.split("/")[0] if "/" in path else "ケース全体"


def marker(label: str, claims: list[dict] = (), evidence: list[str] = (),
           gaps: list[str] = ()) -> str:
    parts = [label]
    if claims:
        parts.append("分析結果 " + ", ".join(
            f"{c['claim_id']}({c.get('confidence') or '—'})" for c in claims))
    if evidence:
        parts.append("証拠 " + ", ".join(evidence))
    if gaps:
        parts.append("不足事項 " + ", ".join(gaps))
    return f"{PLACEHOLDER}: {' / '.join(parts)}】"


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def default_section(heading: str) -> list[str]:
    """Template body as-is, ``<…>`` slots turned into 【要記入】 markers and an
    empty table given one row to fill."""
    out: list[str] = []
    for line in tpl.body(heading).splitlines():
        if line.startswith("<") and line.endswith(">") and not line.startswith("<!--"):
            out.append(f"{PLACEHOLDER}: {line[1:-1]}】")
        else:
            out.append(line)
    header = tpl.table_header(heading)
    if header and header == "\n".join(r for r in out if r.startswith("|")):
        cols = header.splitlines()[0].count("|") - 1
        idx = max(i for i, r in enumerate(out) if r.startswith("|"))
        out.insert(idx + 1, f"| {PLACEHOLDER}: 確認済み/疑い/未確認を明記して列挙】"
                   + " | —" * (cols - 1) + " |")
    return out


def _row_hint(row: dict) -> str:
    """What a 2.4 row summarizes: its own log line, not the whole evidence item."""
    text = row.get("source_text")
    if not text:
        return "事象の要約"
    text = defang_text(" ".join(str(text).split()))[:120].replace("|", "\\|").replace("】", "]")
    return f"この行の事象のみ要約(行 {row.get('source_line')}: {text})"


def render(material: dict, case_dir: Path, now: datetime | None = None) -> str:
    case = material.get("case", {})
    tz = _zone(case.get("report_timezone", "UTC"))
    now = now or datetime.now(timezone.utc)
    today = now.astimezone(tz).date().isoformat()
    ledger = material.get("evidence_ledger", [])
    claims = material.get("approved_claims", [])
    gaps = material.get("gaps", [])
    alias_map = material.get("alias_map", {})
    uuid_to_alias = {v: k for k, v in alias_map.items()}
    rng = case.get("time_range_utc") or {}
    sections: dict[str, list[str]] = {}

    # 報告書メタデータ — fill the template's <…> cells
    period = f"{to_local(rng.get('start'), tz)} 〜 {to_local(rng.get('end'), tz)}"
    meta = {"作成日": today, "報告時点": today, "調査対象期間": period,
            "対象組織 / ケース": f"{cell(case.get('case_name'))} ({cell(case.get('case_id'))})"}
    sections["## 報告書メタデータ"] = [
        (f"| {label} | {meta[label]} |"
         if (label := line.split("|")[1].strip()) in meta else line)
        if line.startswith("|") else line
        for line in tpl.body("## 報告書メタデータ").splitlines()
    ]
    sections["## 目次"] = [f"- {h[3:]}" for h in tpl.required_headings()
                          if h.startswith("## ") and h not in (
                              "## 報告書メタデータ", "## 目次", "## 変更履歴")]
    sections["## 変更履歴"] = [tpl.table_header("## 変更履歴"),
                             f"| 0.1 | {today} | 初版ドラフト作成 | IR Reporting Support Agent |"]

    # 1.2 / 1.3 — prefill what the manifest states so the reviewer only has to
    # confirm it; the reviewer comment stays for anything the manifest lacks.
    scope_lines = []
    if case.get("scope"):
        scope_lines.append(f"- 調査範囲: {cell(case.get('scope'))}")
    if case.get("hosts"):
        scope_lines.append(f"- 調査対象ホスト: {', '.join(cell(h) for h in case['hosts'])}")
    if scope_lines:
        sections["### 1.2 調査目的・調査範囲"] = [
            *scope_lines, "", tpl.body("### 1.2 調査目的・調査範囲").strip()]
    if rng.get("start") or rng.get("end"):
        sections["### 1.3 調査日程・調査期間"] = [
            f"- 調査対象期間: {period}", "",
            tpl.body("### 1.3 調査日程・調査期間").strip()]

    # 1.4 provided data
    sources: dict[str, dict] = {}
    for e in ledger:
        for r in e.get("source_refs", []):
            src = sources.setdefault(r.get("source_path", ""),
                                     {"host": evidence_host(e), "ev": []})
            if e["report_evidence_id"] not in src["ev"]:
                src["ev"].append(e["report_evidence_id"])
    sections["### 1.4 調査対象・提供データ"] = [
        tpl.table_header("### 1.4 調査対象・提供データ"),
        *[f"| `{cell(path)}` | {cell(src['host'])} | {', '.join(src['ev'])} |"
          for path, src in sources.items()],
        "",
        marker("1.4 提供データから確認できる調査対象・データ種別・期間と、"
               "データ上の制約(未提供・対象外のログ)"),
    ]

    sections["## 2. エグゼクティブサマリー・調査結果概要"] = [marker(
        "2 攻撃経路・影響・未確認事項・優先対応を3〜6点に統合。うち1点は"
        "事業影響・情報漏えい可能性・再侵入リスク・残存リスク(確度付き)",
        claims=[c for c in claims if c.get("report_section") != "limitation"])]

    # 2.4 timeline grid
    timeline_heading = "### 2.4 インシデントタイムライン"
    rows = [f"| 時刻 ({_tz_label(tz, now)}) | ホスト | 事象 | 確度 | 証拠ID |",
            "|---|---|---|---|---|"]
    for t in sorted(material.get("timeline", []), key=lambda t: str(t.get("event_time") or "")):
        conf = t.get("interpretation_confidence") or t.get("confidence")
        rows.append(f"| {to_local(t.get('event_time'), tz)} | {cell(t.get('host'))} | "
                    f"{PLACEHOLDER}: {_row_hint(t)}】 | {CONFIDENCE_LABEL.get(conf, '—')} | "
                    f"{t.get('evidence_id') or '—'} |")
    sections[timeline_heading] = [tpl.fixed_body(timeline_heading), "", *rows]

    # 3. findings — one marker per stage naming what CP2 approved for it
    limitation_gaps = [g["gap_id"] for g in gaps
                       if g.get("disposition") == "accepted_as_limitation"]
    for sec, title in tpl.attack_sections():
        routed = [c for c in claims if c.get("report_section") == sec]
        ev = sorted({e for c in routed for e in c.get("supporting_evidence", [])})
        sections[f"### {sec} {title}"] = [
            marker(f"{sec} 確認事実→複数証拠のつながりの考察→制約(最低2段落)",
                   claims=routed, evidence=ev) if routed else
            marker(f"{sec} 該当する観測なし。「確認できませんでした」と関連する不足事項を1〜2段落")
        ]
        # Claims filed elsewhere whose ATT&CK mapping belongs here (e.g. an
        # account creation inside a 3.7 claim is still persistence → 3.4).
        crossed = [(c, tpl.cross_section_mappings(c)[sec]) for c in claims
                   if sec in tpl.cross_section_mappings(c)]
        if crossed:
            sections[f"### {sec} {title}"] += ["", marker(
                f"{sec} 他節の分析結果のうち本節の戦術に該当する事象(本節でも証拠IDを引用する)",
                claims=[c for c, _ in crossed],
                evidence=sorted({e for _, evs in crossed for e in evs}))]
    other = [c for c in claims if c.get("report_section") in ("context", "limitation")]
    if other or limitation_gaps:
        last = tpl.attack_sections()[-1]
        sections[f"### {last[0]} {last[1]}"] += ["", marker(
            "3章 制約として各所見内に併記する事項(独立した制約章は作らない)",
            claims=other, gaps=limitation_gaps)]

    # 4. per-host subsections with verbatim excerpts
    full_ledger = {e.get("evidence_id"): e
                   for e in read_jsonl(case_dir / "data" / "evidence_ledger.jsonl")}
    hosts: dict[str, list[dict]] = {}
    for e in ledger:
        hosts.setdefault(evidence_host(e), []).append(e)
    ch4 = [tpl.fixed_body("## 4. 対象別調査結果詳細")]
    for n, (host, entries) in enumerate(hosts.items(), 1):
        ch4 += ["", f"### 4.{n} {host}", "",
                marker(f"4.{n} {host} の確認事実・時系列・考察・制約",
                       evidence=[e["report_evidence_id"] for e in entries])]
        for e in entries:
            raw = full_ledger.get(alias_map.get(e["report_evidence_id"]), {})
            for r in raw.get("source_refs") or e.get("source_refs") or []:
                ch4 += ["", f"{e['report_evidence_id']}(`{r.get('source_path', '')}` 行 "
                        f"{lines_label(r.get('source_lines') or [])})", "",
                        fence(r.get("excerpt") or "")]
    sections["## 4. 対象別調査結果詳細"] = ch4
    supplement_no = len(hosts)

    # 5. countermeasures
    action_gaps = [g["gap_id"] for g in gaps
                   if g.get("disposition") != "out_of_scope_with_analyst_approval"]
    sections["### 5.1 封じ込め・復旧"] = [marker(
        "5.1 各対応の対応する調査結果・目的・対象・優先度・期待効果・注意・依存関係")]
    sections["### 5.2 再発防止策"] = [marker(
        "5.2 各対策の対応する調査結果/不足事項・優先度・期待効果・注意", gaps=action_gaps)]

    # 付録A — IoC candidates from extract-iocs
    ioc_csv = case_dir / "reports" / "iocs.csv"
    iocs: dict[tuple[str, str], dict] = {}
    if ioc_csv.exists():
        with ioc_csv.open(encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                kind = row.get("ioc_type") or ""
                value = (row.get("value") or "").strip()
                shown = (row.get("defanged") or value).strip()
                if kind == "file_path":
                    # extract-iocs sometimes keeps the trailing CSV columns of
                    # the source line ("path,File,Allocated,…"): keep the path.
                    value = shown = value.split(",")[0].strip()
                if not value or value.startswith(("0.", "127.")):
                    continue
                if _PRIVATE_IP.match(value):
                    shown = value
                evs = [uuid_to_alias[u] for u in (row.get("evidence_ids") or "").split(";")
                       if u in uuid_to_alias]
                if not evs:
                    continue
                entry = iocs.setdefault((kind, value), {"shown": shown, "ev": []})
                entry["ev"] += [e for e in evs if e not in entry["ev"]]
    ioc_rows = [
        f"| {IOC_TYPE_LABEL.get(kind, cell(kind))} | {cell(entry['shown'])} | "
        f"{PLACEHOLDER}: 概要/役割。IoCとして不要な行は削除】 | "
        f"証拠ID: {', '.join(sorted(entry['ev']))} |"
        for (kind, _), entry in iocs.items()
    ] or [f"| {PLACEHOLDER}: 承認済み証拠から抽出できるIoC。ない場合はその旨】 | — | — | — |"]
    sections["## 付録A. IoC一覧"] = [tpl.table_header("## 付録A. IoC一覧"), *ioc_rows]

    # 付録B — ATT&CK, heuristic low-confidence rows dropped
    techniques: dict[str, dict] = {}
    for m in read_jsonl(case_dir / "data" / "attack_mappings.jsonl"):
        conf = m.get("confidence")
        if m.get("mapping_source") == "heuristic" and conf in ("possible", "unknown", None):
            continue
        alias = uuid_to_alias.get(m.get("evidence_id"))
        tid = m.get("technique_id")
        if not alias or not tid:
            continue
        t = techniques.setdefault(tid, {**m, "ev": []})
        if alias not in t["ev"]:
            t["ev"].append(alias)
        if CONFIDENCE_RANK.get(conf, 0) > CONFIDENCE_RANK.get(t.get("confidence"), 0):
            t["confidence"] = conf
    attack_rows = [
        f"| {cell(t.get('tactic'))} | {tid} | {cell(t.get('technique_name'))} | "
        f"{cell(t.get('mapping_reason'))} | {CONFIDENCE_LABEL.get(t.get('confidence'), '—')} | "
        f"証拠ID: {', '.join(sorted(t['ev']))} |"
        for tid, t in techniques.items()
    ] or ["| — | — | — | 対応付けられたテクニックはありません | — | — |"]
    sections["## 付録B. MITRE ATT&CK対応表"] = [
        tpl.table_header("## 付録B. MITRE ATT&CK対応表"), *attack_rows]

    # 付録C — evidence ↔ source mapping
    sections["## 付録C. 関連ファイル・別紙一覧"] = [
        tpl.table_header("## 付録C. 関連ファイル・別紙一覧"),
        *[f"| {e['report_evidence_id']} | `{cell(r.get('source_path'))}` | "
          f"{lines_label(r.get('source_lines') or [])} |"
          for e in ledger for r in e.get("source_refs", [])],
    ]

    # Assemble in template order.
    text = tpl.template_text()
    first = re.search(r"(?m)^#", text)
    out = [text[: first.start() if first else 0].strip("\n"), ""]
    for heading in tpl.all_headings():
        shown = heading
        if tpl.SUPPLEMENT_MARK in heading:
            supplement_no += 1
            shown = heading.replace(tpl.SUPPLEMENT_MARK, f"4.{supplement_no}")
        content = sections.get(heading)
        if content is None:
            content = default_section(heading)
        out += [shown, ""]
        body = "\n".join(content).strip("\n")
        if body:
            out += [body, ""]
    return "\n".join(out).rstrip("\n") + "\n"


def write_skeleton(case_dir: Path, material: dict) -> tuple[Path, bool]:
    """Write reports/draft_report.md unless a draft already exists.

    A pristine copy goes to reports/draft_skeleton.md; check-draft uses it to
    verify that every fixed (non-【要記入】) line survives drafting.
    """
    draft = case_dir / "reports" / "draft_report.md"
    if draft.exists():
        return draft, False
    text = render(material, case_dir)
    draft.write_text(text, encoding="utf-8")
    (case_dir / "reports" / "draft_skeleton.md").write_text(text, encoding="utf-8")
    return draft, True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", required=True, type=Path)
    args = parser.parse_args()
    material_path = args.case_dir / "reports" / "case_material.json"
    if not material_path.exists():
        print("error: reports/case_material.json がありません。"
              "build_case_material.py を先に実行してください")
        return 2
    material = json.loads(material_path.read_text(encoding="utf-8"))
    draft, written = write_skeleton(args.case_dir, material)
    if written:
        count = draft.read_text(encoding="utf-8").count(PLACEHOLDER)
        print(f"written: {draft} ({PLACEHOLDER}】 {count} 箇所)")
    else:
        print(f"skipped: {draft} は既にあります(雛形から作り直す場合は退避してから再実行)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
