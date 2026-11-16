"""Deterministic forensic-report sections.

These helpers render the parts of the Japanese forensic report that should not
be left to free-form LLM structure: fixed headings, per-target evidence detail,
response recommendations, IoC extraction, ATT&CK mapping, and related files.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass

from ir_agent.models.analysis import Claim, Gap, TimelineEntry
from ir_agent.models.base import TimeRange
from ir_agent.models.evidence import EvidenceLedgerEntry

FIXED_JA_HEADINGS: list[str] = [
    "## 0. 本資料の取扱い",
    "## 1. 調査概要",
    "### 1.1 調査にかかる経緯",
    "### 1.2 調査目的・調査範囲",
    "### 1.3 調査日程・調査期間",
    "### 1.4 調査対象・提供データ",
    "### 1.5 調査方法・調査ツール",
    "## 2. エグゼクティブサマリー・調査結果概要",
    "### 2.1 ヒアリング内容",
    "### 2.2 調査方針・対応方針",
    "### 2.3 インシデント概要図",
    "### 2.4 インシデントタイムライン",
    "### 2.5 推奨対応事項",
    "## 3. 調査結果",
    "### 3.1 初期侵入",
    "### 3.2 認証情報取得・アカウント悪用",
    "### 3.3 内部探索・横展開",
    "### 3.4 永続化",
    "### 3.5 C2通信・プロキシ・外部通信",
    "### 3.6 情報窃取・情報持ち出し",
    "### 3.7 防衛回避・痕跡消去",
    "## 4. 対象別調査結果詳細",
    "## 5. 対応状況・推奨対策",
    "### 5.1 封じ込め・復旧",
    "### 5.2 再発防止策",
    "## 付録A. IoC一覧",
    "## 付録B. MITRE ATT&CK対応表",
    "## 付録C. 関連ファイル・別紙一覧",
    "## 付録D. 証拠保全記録",
]


@dataclass(frozen=True)
class IOCItem:
    """A rendered IoC row."""

    ioc_type: str
    value: str
    summary: str
    source: str


@dataclass(frozen=True)
class TimelineRow:
    """A normalized timeline row for rendered sections."""

    event_time: str
    evidence: str
    description: str


def render_table_of_contents(
    evidence_entries: list[EvidenceLedgerEntry] | None = None,
) -> str:
    """Render the fixed table of contents; only Chapter 4 children are dynamic."""
    targets = list(_group_entries_by_target(evidence_entries or []).keys())
    parts = [
        "## 目次",
        "",
        "- 0. 本資料の取扱い",
        "- 1. 調査概要",
        "  - 1.1 調査にかかる経緯",
        "  - 1.2 調査目的・調査範囲",
        "  - 1.3 調査日程・調査期間",
        "  - 1.4 調査対象・提供データ",
        "  - 1.5 調査方法・調査ツール",
        "- 2. エグゼクティブサマリー・調査結果概要",
        "  - 2.1 ヒアリング内容",
        "  - 2.2 調査方針・対応方針",
        "  - 2.3 インシデント概要図",
        "  - 2.4 インシデントタイムライン",
        "  - 2.5 推奨対応事項",
        "- 3. 調査結果",
        "  - 3.1 初期侵入",
        "  - 3.2 認証情報取得・アカウント悪用",
        "  - 3.3 内部探索・横展開",
        "  - 3.4 永続化",
        "  - 3.5 C2通信・プロキシ・外部通信",
        "  - 3.6 情報窃取・情報持ち出し",
        "  - 3.7 防衛回避・痕跡消去",
        "- 4. 対象別調査結果詳細",
    ]
    for index, target in enumerate(targets[:10], 1):
        parts.append(f"  - 4.{index} {target}")
    parts.extend(
        [
            "- 5. 対応状況・推奨対策",
            "  - 5.1 封じ込め・復旧",
            "  - 5.2 再発防止策",
            "- 付録A. IoC一覧",
            "- 付録B. MITRE ATT&CK対応表",
            "- 付録C. 関連ファイル・別紙一覧",
            "- 付録D. 証拠保全記録",
        ]
    )
    return "\n".join(parts)


def render_review_comment(label: str) -> str:
    """Render a stable reviewer-fill comment."""
    comments = {
        "1.1": "<!-- レビュー担当者記入欄: 調査にかかる経緯、初動対応、調査依頼に至った背景を確認のうえ記載してください。 -->",
        "1.2": "<!-- レビュー担当者記入欄: 調査目的、調査範囲、対象期間、対象外事項を確認のうえ記載してください。 -->",
        "1.3": "<!-- レビュー担当者記入欄: 調査日程、調査実施期間、主調査対象期間を確認のうえ記載してください。 -->",
        "1.5": "<!-- レビュー担当者記入欄: 実際に使用した調査方法、解析ツール、バージョン、実施条件を確認のうえ記載してください。 -->",
        "2.1": "<!-- レビュー担当者記入欄: ヒアリング日時、参加者、確認事項、回答内容を確認のうえ記載してください。 -->",
        "2.2": "<!-- レビュー担当者記入欄: ヒアリング内容と調査依頼範囲に基づき、調査方針および対応方針を記載してください。 -->",
        "D": "<!-- レビュー担当者記入欄: 証拠保全作業の実施日時、対象、作業場所、作業者、立会人、使用機器、取得方法、ハッシュ値、保管場所を確認のうえ記載してください。 -->",
    }
    return comments[label]


def render_investigation_targets(
    evidence_entries: list[EvidenceLedgerEntry],
    evidence_aliases: dict[str, str] | None = None,
) -> str:
    """Render section 1.4 from evidence-derived targets and source files."""
    evidence_aliases = evidence_aliases or {}
    grouped = _group_entries_by_target(evidence_entries)
    if not grouped:
        return "提供資料から調査対象・提供データを自動抽出できませんでした。レビュー担当者が確認してください。"

    parts = [
        "提供済みエビデンスから確認できる調査対象・提供データは以下のとおりです。",
        "",
        _table_caption("表1-1 調査対象・提供データ"),
        "",
        "| 調査対象 | データ種別 | 対象期間 | 主な提供データ | 制約 | 関連証拠 |",
        "|---|---|---|---|---|---|",
    ]
    for target, entries in grouped.items():
        source_paths = []
        evidence_ids = []
        for entry in entries:
            evidence_ids.append(_alias(entry.evidence_id, evidence_aliases))
            if entry.source_refs:
                source_paths.append(entry.source_refs[0].source_path)
        sources = ", ".join(f"`{path}`" for path in sorted(set(source_paths))[:4])
        if len(set(source_paths)) > 4:
            sources += f" ほか{len(set(source_paths)) - 4}件"
        evidence = ", ".join(evidence_ids[:8])
        data_types = _data_types_for_entries(entries)
        period = _period_for_entries(entries)
        limitation = _coverage_limitation_for_entries(entries)
        parts.append(
            f"| {target} | {_escape_md(data_types)} | {_escape_md(period)} | "
            f"{sources or '—'} | {_escape_md(limitation)} | {evidence} |"
        )
    return "\n".join(parts)


def render_chapter2_incident_overview(
    claims: list[Claim],
    evidence_entries: list[EvidenceLedgerEntry],
    timeline: list[TimelineEntry] | None = None,
    case_time_range: TimeRange | None = None,
) -> str:
    """Render a short incident overview at the beginning of Chapter 2."""
    timeline = timeline or []
    targets = (
        ", ".join(list(_group_entries_by_target(evidence_entries).keys())[:8]) or "提供資料上の対象"
    )
    start = case_time_range.start if case_time_range else ""
    end = case_time_range.end if case_time_range else ""
    if not start or not end:
        start = min((item.event_time for item in timeline), default="")
        end = max((item.event_time for item in timeline), default="")
    period = f"調査対象期間は {start} から {end} です。" if start and end else ""
    flow_summary = _incident_flow_summary(claims, evidence_entries)
    key_facts = _key_incident_facts(claims, evidence_entries)
    facts = " ".join(key_facts)
    return "\n".join(
        [
            "本章では、調査対象インシデントの全体像、確認した主要事実、時系列、推奨対応事項を整理します。",
            f"提供資料からは、{targets} に関連する認証、プロセス実行、ファイルアクセス、外部通信等の記録が確認されました。{period}",
            flow_summary,
            facts
            or "現時点では、提供済みエビデンスに基づく概要を記載するための分析結果が限定的です。",
        ]
    )


def render_incident_overview_diagram(
    claims: list[Claim],
    evidence_entries: list[EvidenceLedgerEntry],
) -> str:
    """Render section 2.3 as a simple target/tactic overview diagram."""
    steps = _overview_steps_from_case_material(claims, evidence_entries)

    labels = [_safe_report_text(label.replace("\\n", " / ")) for _node_id, label in steps]
    lines = ["```text"]
    if labels:
        lines.append(labels[0])
        for label in labels[1:]:
            lines.append(f"  -> {label}")
    else:
        lines.append("提供資料からは、概要図に記載できる関係性を特定できませんでした。")
    lines.append("```")
    lines.extend(
        [
            "",
            "上図は、提供済みエビデンスから確認または示唆された事象の関係を概略化したものです。",
            "各ノードの正当性・主体・目的は、本文の証拠IDおよび制約事項とあわせて確認してください。",
        ]
    )
    return "\n".join(lines)


def render_chapter4(
    evidence_entries: list[EvidenceLedgerEntry],
    claims: list[Claim] | None = None,
    timeline: list[TimelineEntry] | None = None,
    evidence_aliases: dict[str, str] | None = None,
    case_time_range: TimeRange | None = None,
    *,
    max_groups: int = 10,
    max_entries_per_group: int = 8,
) -> str:
    """Render Chapter 4 as target-grouped evidence detail with log excerpts."""
    evidence_aliases = evidence_aliases or {}
    claims = claims or []
    timeline = timeline or []
    active_entries = [entry for entry in evidence_entries if not entry.withdrawn]

    parts = [
        "## 4. 対象別調査結果詳細",
        "",
        "本章では、対象機器・システム別に確認した事象と、根拠となるログ・ファイル抜粋を示します。",
        "各節では、確認事実、時系列、関連ログ、制約を分けて記載します。",
    ]

    if not active_entries:
        parts.extend(["", "関連する証拠ログ抜粋は特定されませんでした。"])
        return "\n".join(parts)

    grouped = _group_entries_by_target(active_entries)

    for index, (target, entries) in enumerate(list(grouped.items())[:max_groups], 1):
        entry_ids = {entry.evidence_id for entry in entries}
        target_claims = [
            claim for claim in claims if entry_ids.intersection(claim.supporting_evidence)
        ]
        target_timeline: list[TimelineEntry] = []
        seen_timeline: set[tuple[str, str]] = set()
        for item in timeline:
            label = _timeline_evidence_label(item, evidence_aliases)
            if label is None:
                continue
            if item.evidence_id not in entry_ids and _canonical_target(item.host or "") != target:
                continue
            key = (item.event_time, item.event_description)
            if key in seen_timeline:
                continue
            seen_timeline.add(key)
            target_timeline.append(item)
            if len(target_timeline) >= 8:
                break

        parts.extend(["", f"### 4.{index} {target}", "", "#### 確認事実"])
        facts = _summarize_facts(entries, target_claims)
        parts.append(facts)

        timeline_rows = _timeline_rows_for_target(
            entries,
            target_timeline,
            evidence_aliases,
            case_time_range,
        )
        parts.extend(["", "#### 時系列"])
        if timeline_rows:
            parts.extend(
                [
                    _table_caption(f"表4-{index} {target}で確認した事象の時系列"),
                    "",
                    "| 時刻 | 証拠 | 確認した事象 |",
                    "|---|---|---|",
                ]
            )
            for row in timeline_rows[:8]:
                parts.append(
                    f"| {_escape_md(row.event_time)} | "
                    f"{row.evidence} | "
                    f"{_escape_md(_normalize_target_labels_in_text(row.description))} |"
                )
        else:
            parts.append(
                "提供資料上、対象内のイベントを時系列表として整理できる十分な期間内タイムスタンプは限定的です。"
            )

        parts.extend(["", "#### 証拠ログ抜粋"])
        parts.extend(_render_grouped_evidence_excerpts(entries[:max_entries_per_group], evidence_aliases))

        limitations = _limitations_for_target(entries, target_claims)
        parts.extend(["", "#### 制約", limitations])

    omitted = len(grouped) - max_groups
    if omitted > 0:
        parts.extend(
            [
                "",
                f"※ 対象数が多いため、追加の {omitted} 対象は付録Cの関連ファイル一覧を参照してください。",
            ]
        )

    parts.extend(
        [
            "",
            "### 4.補足 侵害・侵害疑いのアカウント/ホスト一覧",
            "",
            _table_caption("表4-X 侵害・侵害疑いのアカウント/ホスト一覧"),
            "",
            *_compromised_account_host_rows(active_entries, claims, evidence_aliases),
            "",
            "### 4.補足 窃取・窃取疑いデータ一覧",
            "",
            _table_caption("表4-Y 窃取・窃取疑いデータ一覧"),
            "",
            *_suspected_exfiltrated_data_rows(active_entries, claims, evidence_aliases),
        ]
    )

    return "\n".join(parts)


def render_chapter5(
    gaps: list[Gap],
    claims: list[Claim] | None = None,
    evidence_aliases: dict[str, str] | None = None,
) -> str:
    """Render response and recommendation chapter as concrete tables."""
    claims = claims or []
    evidence_aliases = evidence_aliases or {}
    relevant_gaps = _meaningful_gaps(gaps)
    containment_rows, prevention_rows = _recommendation_rows_from_findings(
        relevant_gaps,
        claims,
        evidence_aliases,
    )

    if not containment_rows:
        containment_rows.append(
            "| 中 | 関連アカウント・対象システム | 状態確認 | 調査結果に基づき、侵害が疑われるアカウント、端末、通信経路の利用状況を確認してください。 | 影響範囲と正当性を切り分けるためです。 | 侵害範囲と正当な運用記録を切り分けられます。 | 業務影響、証拠保全、復旧順序を確認してから実施してください。 | 分析結果レビュー |"
        )
    if not prevention_rows:
        prevention_rows.append(
            "| 中 | ログ取得・保存基盤 | 保存範囲の見直し | 未取得または未分析のログがある場合、今後の調査で確認できるよう保存期間、取得対象、監査設定を見直してください。 | 事後調査で必要な証跡を確保するためです。 | 類似事案発生時の調査可能性が向上します。 | 保存コスト、個人情報、ログ量、既存監視基盤への影響を確認してください。 | 不足事項レビュー |"
        )

    return "\n".join(
        [
            "## 5. 対応状況・推奨対策",
            "",
            "本章では、確認済みの調査結果および不足事項レビューを踏まえ、封じ込め・復旧と再発防止の観点で推奨事項を整理します。",
            "",
            "### 5.1 封じ込め・復旧",
            "",
            _table_caption("表5-1 封じ込め・復旧対応"),
            "",
            "| 優先度 | 対象 | 対応項目 | 実施内容 | 目的 | 期待効果 | 実施上の注意・依存関係 | 根拠 |",
            "|---|---|---|---|---|---|---|---|",
            *containment_rows,
            "",
            "### 5.2 再発防止策",
            "",
            _table_caption("表5-2 再発防止策"),
            "",
            "| 優先度 | 対象 | 対応項目 | 実施内容 | 目的 | 期待効果 | 実施上の注意・依存関係 | 根拠 |",
            "|---|---|---|---|---|---|---|---|",
            *prevention_rows,
        ]
    )


def render_ioc_appendix(
    claims: list[Claim],
    evidence_entries: list[EvidenceLedgerEntry],
    evidence_aliases: dict[str, str] | None = None,
) -> str:
    """Extract IoCs from approved claims and evidence excerpts."""
    evidence_aliases = evidence_aliases or {}
    items = extract_iocs(claims, evidence_entries, evidence_aliases)
    rows = [
        f"| {item.ioc_type} | `{item.value}` | {_escape_md(item.summary)} | {item.source} |"
        for item in items[:80]
    ]
    if not rows:
        rows.append("| — | 抽出対象なし | — | — |")
    return "\n".join(
        [
            "## 付録A. IoC一覧",
            "",
            _table_caption("表A-1 IoC一覧"),
            "",
            "| 種別 | 値 | 概要/役割 | 確認箇所 |",
            "|---|---|---|---|",
            *rows,
        ]
    )


def render_attack_mapping_appendix(
    claims: list[Claim],
    evidence_entries: list[EvidenceLedgerEntry] | None = None,
    evidence_aliases: dict[str, str] | None = None,
) -> str:
    """Render MITRE ATT&CK mappings from approved claims."""
    evidence_aliases = evidence_aliases or {}
    grouped: "OrderedDict[tuple[str, str, str], dict[str, list[str]]]" = OrderedDict()

    def add_mapping(
        tactic: str,
        technique_id: str,
        technique_name: str,
        detail: str,
        evidence: str,
        confidence: str,
    ) -> None:
        if evidence == "—":
            return
        key = (tactic, technique_id, technique_name)
        bucket = grouped.setdefault(key, {"details": [], "evidence": [], "confidence": []})
        if detail and detail not in bucket["details"]:
            bucket["details"].append(detail)
        if confidence and confidence not in bucket["confidence"]:
            bucket["confidence"].append(confidence)
        for item in [part.strip() for part in evidence.split(",") if part.strip()]:
            if item not in bucket["evidence"]:
                bucket["evidence"].append(item)

    for claim in claims:
        claim_text = claim.approved_claim_text or claim.claim_text
        evidence = _evidence_for_claim(claim, evidence_aliases)
        if evidence == "—":
            continue
        detail = _trim(claim_text, 90)
        for mapping in claim.attack_mappings:
            add_mapping(
                mapping.tactic,
                mapping.technique_id,
                mapping.technique_name,
                detail,
                evidence,
                getattr(mapping.confidence, "value", str(mapping.confidence)),
            )

    rows = []
    for (tactic, technique_id, technique_name), bucket in list(grouped.items())[:20]:
        detail = " / ".join(bucket["details"][:3]) or "関連する事象が確認されました。"
        evidence = ", ".join(bucket["evidence"][:8])
        confidence = ", ".join(bucket["confidence"][:3]) or "—"
        rows.append(
            f"| {_escape_md(tactic)} | {_escape_md(technique_id)} | "
            f"{_escape_md(technique_name)} | {_escape_md(_safe_report_text(detail))} | "
            f"{_escape_md(confidence)} | {evidence} |"
        )

    if not rows:
        rows.append("| — | — | — | ATT&CK対応候補は抽出されていません。 | — | — |")
    return "\n".join(
        [
            "## 付録B. MITRE ATT&CK対応表",
            "",
            _table_caption("表B-1 MITRE ATT&CK対応表"),
            "",
            "| 戦術 | ID | テクニック | 本件で確認した内容 | 確度 | 関連証拠 |",
            "|---|---|---|---|---|---|",
            *rows,
        ]
    )


def render_related_files_appendix(
    evidence_entries: list[EvidenceLedgerEntry],
    evidence_aliases: dict[str, str] | None = None,
) -> str:
    """Render customer-facing related files, not the internal evidence ledger."""
    evidence_aliases = evidence_aliases or {}
    grouped: "OrderedDict[str, dict[str, object]]" = OrderedDict()
    for entry in evidence_entries:
        ref = entry.source_refs[0] if entry.source_refs else None
        source_path = ref.source_path if ref else ""
        if not source_path:
            continue
        bucket = grouped.setdefault(
            source_path,
            {
                "target": _target_name_for_entry(entry),
                "data_type": _data_type_for_source(source_path),
                "periods": [],
                "evidence": [],
            },
        )
        period_source = "\n".join([entry.observed_fact, ref.excerpt if ref else ""])
        bucket["periods"].extend(_extract_event_times(period_source))  # type: ignore[index, union-attr]
        bucket["evidence"].append(  # type: ignore[index, union-attr]
            _alias(entry.evidence_id, evidence_aliases)
        )

    rows: list[str] = []
    for source_path, bucket in grouped.items():
        periods = sorted(set(bucket["periods"]))  # type: ignore[arg-type]
        period = _format_period(periods)
        evidence = ", ".join(list(dict.fromkeys(bucket["evidence"]))[:8])  # type: ignore[arg-type]
        rows.append(
            f"| {_escape_md(bucket['target'])} | {_escape_md(bucket['data_type'])} | "
            f"`{_escape_md(source_path)}` | {_escape_md(period)} | {evidence} |"
        )
    if not rows:
        rows.append("| — | — | — | — | — |")
    return "\n".join(
        [
            "## 付録C. 関連ファイル・別紙一覧",
            "",
            _table_caption("表C-1 関連ファイル・別紙一覧"),
            "",
            "| 対象 | データ種別 | 関連ファイル | 確認できた期間 | 関連証拠 |",
            "|---|---|---|---|---|",
            *rows,
            "",
            "※ 証拠IDと内部台帳ID、行番号、アーティファクトバージョンの対応は内部証拠台帳で管理します。",
        ]
    )


def extract_iocs(
    claims: list[Claim],
    evidence_entries: list[EvidenceLedgerEntry],
    evidence_aliases: dict[str, str] | None = None,
) -> list[IOCItem]:
    """Extract basic IoCs from claims and evidence text."""
    evidence_aliases = evidence_aliases or {}
    seen: set[tuple[str, str]] = set()
    items: list[IOCItem] = []

    def add(ioc_type: str, value: str, source: str) -> None:
        clean = value.strip().strip(".,;:()[]{}<>\"'")
        if not clean or len(clean) < 3:
            return
        rendered = _defang(clean) if ioc_type in {"IP", "Domain", "URL"} else clean
        key = (ioc_type, rendered)
        if key in seen:
            return
        seen.add(key)
        items.append(IOCItem(ioc_type, rendered, _ioc_summary(ioc_type), source))

    for entry in evidence_entries:
        source = _alias(entry.evidence_id, evidence_aliases)
        chunks = [entry.observed_fact, entry.interpretation]
        chunks.extend(ref.excerpt for ref in entry.source_refs[:2])
        _extract_iocs_from_text("\n".join(chunks), source, add)

    for claim in claims:
        source = _evidence_for_claim(claim, evidence_aliases)
        _extract_iocs_from_text(claim.approved_claim_text or claim.claim_text, source, add)

    return items


def _extract_iocs_from_text(text: str, source: str, add) -> None:
    for value in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        if all(0 <= int(part) <= 255 for part in value.split(".")):
            add("IP", value, source)

    for value in re.findall(r"https?://[^\s\"'<>）,，]+", text):
        if not _is_noise_url(value):
            add("URL", value, source)

    for value in re.findall(r"\b[a-fA-F0-9]{64}\b", text):
        add("Hash", value.lower(), source)
    for value in re.findall(r"\b[a-fA-F0-9]{40}\b", text):
        add("Hash", value.lower(), source)
    for value in re.findall(r"\b[a-fA-F0-9]{32}\b", text):
        add("Hash", value.lower(), source)

    for value in re.findall(
        r"(?:[A-Za-z]:\\[A-Za-z0-9_.$(){}\[\]\-\\/:]+|\\\\[A-Za-z0-9_.$(){}\[\]\-\\/:]+)",
        text,
    ):
        if _is_useful_path(value):
            add("File/Path", value, source)
    for value in re.findall(
        r"(?<!https:)(?<!http:)(?<![A-Za-z0-9])/(?:[\w.\-]+/)+[\w.\-]+",
        text,
    ):
        if _is_useful_path(value):
            add("File/Path", value, source)

    for value in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text):
        if not _is_noise_domain(value):
            add("Domain", value, source)


def _ioc_summary(ioc_type: str) -> str:
    summaries = {
        "IP": "通信先または接続元として確認されたIPアドレスです。",
        "Domain": "通信先または参照先として確認されたドメイン名です。",
        "URL": "通信先または参照先として確認されたURLです。",
        "Hash": "ファイル識別子として確認されたハッシュ値です。",
        "File/Path": "調査過程で確認されたファイルまたはパスです。",
    }
    return summaries.get(ioc_type, "調査過程で確認された指標です。")


def _compromised_account_host_rows(
    entries: list[EvidenceLedgerEntry],
    claims: list[Claim],
    evidence_aliases: dict[str, str],
) -> list[str]:
    """Render a generic account/host impact table from approved claims."""
    rows = ["| アカウント | ホスト | 確認状況 | 根拠 | 推奨対応 |"]
    rows.append("|---|---|---|---|---|")
    by_id = {entry.evidence_id: entry for entry in entries}
    seen: set[tuple[str, str, str]] = set()
    impact_terms = (
        "侵害",
        "悪用",
        "不審",
        "横展開",
        "ログオン",
        "永続化",
        "外部通信",
        "防衛回避",
        "資格情報",
    )
    for claim in claims:
        if claim.review_status not in ("approved", "edited"):
            continue
        text = claim.approved_claim_text or claim.claim_text
        if not any(term in text for term in impact_terms):
            continue
        status = _confirmation_status_for_claim(claim)
        evidence = _evidence_for_claim(claim, evidence_aliases)
        for evidence_id in claim.supporting_evidence:
            entry = by_id.get(evidence_id)
            if not entry:
                continue
            account = (
                _entry_value(entry, "user", "username", "account", "account_name")
                or "—"
            )
            host = _target_name_for_entry(entry)
            key = (account, host, evidence)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                f"| {_escape_md(account)} | {_escape_md(host)} | {status} | "
                f"{evidence} | 必要に応じて状態確認、認証情報変更、隔離、"
                "監視強化を実施してください。 |"
            )
    if len(rows) == 2:
        rows.append("| — | — | 本資料からは特定できませんでした | — | 追加情報を確認してください。 |")
    return rows


def _suspected_exfiltrated_data_rows(
    entries: list[EvidenceLedgerEntry],
    claims: list[Claim],
    evidence_aliases: dict[str, str],
) -> list[str]:
    """Render a suspected exfiltration table without overclaiming."""
    rows = ["| データ/ファイル | 保存場所・関連ホスト | 確認状況 | 根拠 | 制約 |"]
    rows.append("|---|---|---|---|---|")
    by_id = {entry.evidence_id: entry for entry in entries}
    seen: set[tuple[str, str, str]] = set()
    exfil_terms = ("窃取", "持ち出し", "漏えい", "漏洩", "外部送信", "送信量", "SFTP", "コピー")
    for claim in claims:
        if claim.review_status not in ("approved", "edited"):
            continue
        text = claim.approved_claim_text or claim.claim_text
        if claim.report_section != "3.6" and not any(term in text for term in exfil_terms):
            continue
        status = _confirmation_status_for_claim(claim)
        evidence = _evidence_for_claim(claim, evidence_aliases)
        limitation = "送信内容やファイル内容は、根拠証拠の範囲でのみ評価してください。"
        if claim.limitations:
            limitation = _trim(" / ".join(_translate_limitation(v) for v in claim.limitations), 90)
        for evidence_id in claim.supporting_evidence:
            entry = by_id.get(evidence_id)
            if not entry:
                continue
            data_name = _entry_value(entry, "file_path", "path", "file")
            if not data_name:
                data_name = _data_name_from_text("\n".join([entry.observed_fact, entry.interpretation]))
            if not data_name:
                data_name = _trim(text, 50)
            host = _target_name_for_entry(entry)
            key = (data_name, host, evidence)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                f"| {_escape_md(data_name)} | {_escape_md(host)} | {status} | "
                f"{evidence} | {_escape_md(limitation)} |"
            )
    if len(rows) == 2:
        rows.append("| — | — | 本資料からは特定できませんでした | — | 追加情報を確認してください。 |")
    return rows


def _entry_value(entry: EvidenceLedgerEntry, *keys: str) -> str:
    for key in keys:
        value = entry.observed_event.get(key)
        if isinstance(value, str) and value.strip():
            return _safe_report_text(value.strip())
    return ""


def _data_name_from_text(text: str) -> str:
    path_match = re.search(
        r"(?:[A-Za-z]:\\[^\s\"'<>|]+|/(?:[^\s/]+/)*[^\s]+)",
        text,
    )
    if path_match:
        return _safe_report_text(path_match.group(0).strip(".,;:"))
    quoted = re.search(r"[\"'`「](.{3,80}?)[\"'`」]", text)
    if quoted:
        return _safe_report_text(quoted.group(1).strip())
    return ""


def _confirmation_status_for_claim(claim: Claim) -> str:
    confidence = getattr(claim.confidence_level, "value", str(claim.confidence_level))
    if confidence == "confirmed":
        return "確認済み"
    if confidence in {"probable", "possible"}:
        return "疑い"
    return "未確認"


def _render_evidence_excerpt(
    entry: EvidenceLedgerEntry,
    evidence_aliases: dict[str, str],
) -> list[str]:
    ref = entry.source_refs[0] if entry.source_refs else None
    source_path = ref.source_path if ref else "source unavailable"
    source_lines = f"{ref.source_lines[0]}-{ref.source_lines[1]}" if ref else "N/A"
    excerpt = (ref.excerpt if ref else entry.observed_fact).strip() or "(抜粋なし)"
    alias = _alias(entry.evidence_id, evidence_aliases)
    return [
        "",
        "```text",
        f"# {alias}: {source_path} 行 {source_lines}",
        excerpt,
        "```",
    ]


def _render_grouped_evidence_excerpts(
    entries: list[EvidenceLedgerEntry],
    evidence_aliases: dict[str, str],
) -> list[str]:
    """Render source excerpts by contiguous source range to avoid chopped snippets."""
    groups: list[list[EvidenceLedgerEntry]] = []
    for entry in entries:
        ref = entry.source_refs[0] if entry.source_refs else None
        if not ref:
            groups.append([entry])
            continue
        placed = False
        for group in groups:
            group_ref = group[0].source_refs[0] if group[0].source_refs else None
            if not group_ref:
                continue
            if ref.source_path != group_ref.source_path:
                continue
            group_start = min(
                item.source_refs[0].source_lines[0] for item in group if item.source_refs
            )
            group_end = max(
                item.source_refs[0].source_lines[1] for item in group if item.source_refs
            )
            if ref.source_lines[0] <= group_end + 2 and ref.source_lines[1] >= group_start - 2:
                group.append(entry)
                placed = True
                break
        if not placed:
            groups.append([entry])

    rendered: list[str] = []
    for group in groups:
        refs = [item.source_refs[0] for item in group if item.source_refs]
        if not refs:
            rendered.extend(_render_evidence_excerpt(group[0], evidence_aliases))
            continue
        source_path = refs[0].source_path
        source_start = min(ref.source_lines[0] for ref in refs)
        source_end = max(ref.source_lines[1] for ref in refs)
        aliases = ", ".join(_alias(item.evidence_id, evidence_aliases) for item in group)
        excerpt_lines: list[str] = []
        seen_lines: set[str] = set()
        for ref in sorted(refs, key=lambda item: item.source_lines):
            for line in ref.excerpt.strip().splitlines():
                if line in seen_lines:
                    continue
                seen_lines.add(line)
                excerpt_lines.append(line)
        excerpt = "\n".join(excerpt_lines).strip() or "(抜粋なし)"
        rendered.extend(
            [
                "",
                "```text",
                f"# {aliases}: {source_path} 行 {source_start}-{source_end}",
                excerpt,
                "```",
            ]
        )
    return rendered


def _timeline_rows_for_target(
    entries: list[EvidenceLedgerEntry],
    target_timeline: list[TimelineEntry],
    evidence_aliases: dict[str, str],
    case_time_range: TimeRange | None,
) -> list[TimelineRow]:
    rows: list[TimelineRow] = []
    seen: set[tuple[str, str, str]] = set()

    def add(event_time: str, evidence: str, description: str) -> None:
        event_time = _normalize_event_time(event_time)
        description = _safe_report_text(description)
        if not event_time or not _time_in_range(event_time, case_time_range):
            return
        key = (event_time, evidence, description)
        if key in seen:
            return
        seen.add(key)
        rows.append(TimelineRow(event_time, evidence, _trim(description, 180)))

    for item in target_timeline:
        label = _timeline_evidence_label(item, evidence_aliases)
        if label:
            add(item.event_time, label, item.event_description)

    for entry in entries:
        alias = _alias(entry.evidence_id, evidence_aliases)
        text_chunks = [entry.observed_fact, entry.interpretation]
        text_chunks.extend(ref.excerpt for ref in entry.source_refs[:1])
        text = "\n".join(text_chunks)
        for event_time in _extract_event_times(text):
            add(event_time, alias, entry.observed_fact or text)

    rows.sort(key=lambda row: row.event_time)
    return rows


def _extract_event_times(text: str) -> list[str]:
    values: list[str] = []
    for match in re.findall(r"\b20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b", text):
        values.append(_normalize_event_time(match))
    return list(dict.fromkeys(values))


def _normalize_event_time(value: str) -> str:
    if value and "." in value and value.endswith("Z"):
        return value.split(".", 1)[0] + "Z"
    return value


def _time_in_range(event_time: str, case_time_range: TimeRange | None) -> bool:
    if case_time_range is None:
        return True
    if case_time_range.start and event_time < case_time_range.start:
        return False
    if case_time_range.end and event_time > case_time_range.end:
        return False
    return True


def _target_name_for_entry(entry: EvidenceLedgerEntry) -> str:
    ref = entry.source_refs[0] if entry.source_refs else None
    source_path = ref.source_path if ref else ""
    candidates = [
        entry.observed_event.get("host"),
        entry.observed_event.get("hostname"),
        entry.observed_event.get("system"),
        entry.observed_event.get("device"),
        entry.observed_event.get("target"),
    ]
    for value in candidates:
        target = _canonical_target(str(value or ""))
        if target:
            return target

    return _target_from_source_path(source_path) or "その他"


def _group_entries_by_target(
    evidence_entries: list[EvidenceLedgerEntry],
) -> "OrderedDict[str, list[EvidenceLedgerEntry]]":
    grouped: "OrderedDict[str, list[EvidenceLedgerEntry]]" = OrderedDict()
    for entry in evidence_entries:
        grouped.setdefault(_target_name_for_entry(entry), []).append(entry)
    return grouped


def _canonical_target(value: str) -> str | None:
    text = value.strip().replace("\\", "/")
    if not text:
        return None
    if "/" in text:
        return _target_from_source_path(text)
    return _humanize_target_label(text)


def _target_from_source_path(source_path: str) -> str | None:
    parts = [part for part in source_path.replace("\\", "/").split("/") if part]
    if not parts:
        return None
    generic_dirs = {
        "artifact",
        "artifacts",
        "evidence",
        "evidences",
        "input",
        "inputs",
        "raw",
        "data",
        "logs",
        "log",
        "case",
        "cases",
        "samples",
        "sample",
    }
    for part in parts[:-1] or parts:
        if part.lower() in generic_dirs:
            continue
        return _humanize_target_label(part)
    leaf = parts[-1]
    stem = leaf.rsplit(".", 1)[0]
    return _humanize_target_label(stem) if stem else None


def _humanize_target_label(value: str) -> str:
    label = value.strip().strip("`")
    label = re.sub(r"\.(?:log|txt|csv|json|md|evtx)$", "", label, flags=re.I)
    label = label.replace("_", " ").strip()
    return label.upper() if re.fullmatch(r"[a-z]{1,4}\d+(?:-[a-z0-9]+)?", label, re.I) else label


def _summarize_facts(entries: list[EvidenceLedgerEntry], claims: list[Claim]) -> str:
    facts = [_safe_report_text(_trim(entry.observed_fact, 160)) for entry in entries[:3] if entry.observed_fact]
    if facts:
        return " ".join(facts)
    if claims:
        return "本対象に関連する分析結果は確認されましたが、証拠台帳から要約可能な確認事実は限定的です。"
    return "提供資料上、対象に関連する証拠は確認されましたが、要約可能な確認事実は限定的です。"


def _limitations_for_target(entries: list[EvidenceLedgerEntry], claims: list[Claim]) -> str:
    limitations: list[str] = []
    for claim in claims:
        limitations.extend(_translate_limitation(item) for item in claim.limitations[:2])
        limitations.extend(_translate_limitation(item) for item in claim.missing_evidence[:2])
    if limitations:
        unique = list(dict.fromkeys(_trim(item, 140) for item in limitations if item))
        return "\n".join(f"- {item}" for item in unique[:5])
    if len(entries) == 1:
        return "- 本節の判断は単一の証拠に依存しているため、追加ログまたは関連証跡による補強が望まれます。"
    return "- 本節は提供済み証拠の範囲に基づく整理であり、未取得・未分析データにより結論が変わる可能性があります。"


def _meaningful_gaps(gaps: list[Gap]) -> list[Gap]:
    return [
        gap
        for gap in gaps
        if gap.disposition
        in (
            "accepted_as_limitation",
            "out_of_scope_with_analyst_approval",
            None,
        )
        and not _is_low_value_gap(gap)
    ]


def _is_low_value_gap(gap: Gap) -> bool:
    text = f"{gap.description} {gap.recommended_action}".lower()
    low_value = [
        "based on single source",
        "single source only",
        "low interpretation confidence",
        "all supporting evidence has low",
    ]
    return any(item in text for item in low_value)


def _recommendation_rows_from_findings(
    gaps: list[Gap],
    claims: list[Claim],
    evidence_aliases: dict[str, str],
) -> tuple[list[str], list[str]]:
    containment: list[tuple[str, str, str, str, str, str, str, str]] = []
    prevention: list[tuple[str, str, str, str, str, str, str, str]] = []

    def add_once(
        rows: list[tuple[str, str, str, str, str, str, str, str]],
        row: tuple[str, str, str, str, str, str, str, str],
    ) -> None:
        if row not in rows:
            rows.append(row)

    topic_rows: "OrderedDict[tuple[str, str], tuple[str, str, str]]" = OrderedDict()
    for claim in claims:
        if claim.review_status not in ("approved", "edited"):
            continue
        topic = _recommendation_topic_for_claim(claim)
        target = _target_label_for_claim(claim, evidence_aliases)
        evidence = _evidence_for_claim(claim, evidence_aliases)
        if evidence == "—":
            continue
        priority = _priority_from_claim(claim)
        key = (target, topic)
        existing = topic_rows.get(key)
        if existing:
            previous_priority, _previous_evidence, previous_claim = existing
            priority = _higher_priority(previous_priority, priority)
            evidence = _merge_evidence_refs(_previous_evidence, evidence)
            claim_summary = previous_claim
        else:
            claim_summary = f"{topic}に関係する分析結果"
        topic_rows[key] = (priority, evidence, claim_summary)

    for (target, topic), (priority, evidence, claim_summary) in list(topic_rows.items())[:8]:
        add_once(
            containment,
            (
                priority,
                target,
                f"{topic}に関する事実確認",
                f"{claim_summary} 関連する対象、時刻、実行主体、影響範囲、正当な運用記録との整合性を確認してください。",
                "調査結果の正当性と影響範囲を確定するためです。",
                "侵害範囲、正当利用、復旧対象の切り分け精度が向上します。",
                "業務影響、証拠保全、復旧順序を確認し、必要に応じて関係部門と調整してください。",
                evidence,
            ),
        )
        add_once(
            prevention,
            (
                priority,
                target,
                f"{topic}に関する再発防止",
                "同種事象を検知・抑止できるよう、アクセス制御、監査ログ、アラート、運用承認記録の設定を見直してください。",
                "同じ攻撃段階または運用上の弱点が再発するリスクを低減するためです。",
                "同種の攻撃活動を早期に検知し、影響拡大を抑止できます。",
                "既存業務、運用手順、監視基盤、ログ保存コストへの影響を確認してください。",
                evidence,
            ),
        )

    for gap in gaps[:8]:
        claim = _claim_by_id(claims, gap.related_claim_id)
        row = (
            _priority_from_severity(gap.severity),
            "追加確認対象",
            _trim(gap.recommended_action, 90),
            _trim(gap.description, 120),
            "不足事項を解消し、判断の信頼性を高めるためです。",
            "未確認事項を減らし、追加対応の優先順位を判断しやすくなります。",
            "追加取得により証拠が変更・消失する可能性や、対象システムへの負荷を確認してください。",
            _evidence_for_claim(claim, evidence_aliases),
        )
        if _looks_like_containment(gap):
            add_once(containment, row)
        else:
            add_once(prevention, row)

    containment_rows = [
        f"| {p} | {target} | {action} | {detail} | {purpose} | {effect} | {caution} | {evidence} |"
        for p, target, action, detail, purpose, effect, caution, evidence in containment[:8]
    ]
    prevention_rows = [
        f"| {p} | {target} | {action} | {detail} | {purpose} | {effect} | {caution} | {evidence} |"
        for p, target, action, detail, purpose, effect, caution, evidence in prevention[:8]
    ]
    return containment_rows, prevention_rows


def _translate_limitation(value: str) -> str:
    translations = {
        "Based on single source only": "単一の証拠に依存しているため、追加証跡による補強が望まれます。",
        "All supporting evidence has low interpretation confidence": "関連証拠の解釈信頼度が低いため、判断には追加確認が必要です。",
    }
    return _safe_report_text(translations.get(value, value))


def _claim_by_id(claims: list[Claim], claim_id: str) -> Claim | None:
    for claim in claims:
        if claim.claim_id == claim_id:
            return claim
    return None


def _overview_steps_from_case_material(
    claims: list[Claim],
    evidence_entries: list[EvidenceLedgerEntry],
) -> list[tuple[str, str]]:
    targets = list(_group_entries_by_target(evidence_entries).keys())
    if targets:
        return [
            (f"target{index}", f"{_mermaid_label(target)}\\n調査対象")
            for index, target in enumerate(targets[:6], 1)
        ]

    tactics = _ordered_tactic_labels(claims)
    if tactics:
        return [
            (f"phase{index}", f"{_mermaid_label(tactic)}\\n分析結果")
            for index, tactic in enumerate(tactics[:6], 1)
        ]

    return [("scope", "提供資料\\n追加確認が必要")]


def _incident_flow_summary(
    claims: list[Claim],
    evidence_entries: list[EvidenceLedgerEntry],
) -> str:
    phases = _ordered_tactic_labels(claims)
    if not phases:
        targets = list(_group_entries_by_target(evidence_entries).keys())[:5]
        if targets:
            return "インシデントの全体像としては、" + "、".join(targets) + "に関連する事象が確認または示唆されました。"
        return "提供資料の範囲では、インシデント全体の侵入経路から影響範囲までを一連の流れとして判断するには追加確認が必要です。"
    return "インシデントの流れとしては、" + "、".join(phases[:5]) + "に関係する事象が確認または示唆されました。"


def _key_incident_facts(
    claims: list[Claim],
    evidence_entries: list[EvidenceLedgerEntry],
) -> list[str]:
    selected_claims = sorted(
        [claim for claim in claims if claim.review_status in ("approved", "edited")],
        key=lambda claim: (
            _confidence_rank(claim.confidence_level.value),
            -len(claim.supporting_evidence),
            claim.claim_id,
        ),
    )
    selected = [
        _safe_report_text(_trim(claim.approved_claim_text or claim.claim_text, 150))
        for claim in selected_claims[:3]
    ]
    if selected:
        return selected
    return [_safe_report_text(_trim(entry.observed_fact, 150)) for entry in evidence_entries[:3]]


def _ordered_tactic_labels(claims: list[Claim]) -> list[str]:
    labels: list[str] = []
    for claim in claims:
        if claim.review_status not in ("approved", "edited"):
            continue
        for mapping in claim.attack_mappings:
            label = _ja_tactic_label(mapping.tactic)
            if label not in labels:
                labels.append(label)
    return labels


def _recommendation_topic_for_claim(claim: Claim) -> str:
    if claim.attack_mappings:
        mapping = claim.attack_mappings[0]
        return _ja_tactic_label(mapping.tactic) or mapping.technique_name or mapping.technique_id
    section = claim.report_section.strip()
    if section and not _looks_internal_section_key(section):
        return section
    return _ja_claim_category_label(claim.claim_category.value)


def _target_label_for_claim(claim: Claim, evidence_aliases: dict[str, str]) -> str:
    section = claim.report_section.strip()
    if section and section not in {"調査結果", "Findings", "findings"} and not _looks_internal_section_key(section):
        return section
    return "関連対象"


def _priority_from_claim(claim: Claim) -> str:
    if claim.confidence_level.value in {"confirmed", "probable"}:
        return "高"
    if claim.confidence_level.value == "possible":
        return "中"
    return "低"


def _higher_priority(left: str, right: str) -> str:
    order = {"高": 0, "中": 1, "低": 2}
    return left if order.get(left, 9) <= order.get(right, 9) else right


def _merge_evidence_refs(left: str, right: str) -> str:
    refs = [item.strip() for item in f"{left},{right}".split(",") if item.strip()]
    return ", ".join(dict.fromkeys(refs))


def _confidence_rank(value: str) -> int:
    return {
        "confirmed": 0,
        "probable": 1,
        "possible": 2,
        "unknown": 3,
        "not_observed": 4,
    }.get(value, 9)


def _ja_tactic_label(value: str) -> str:
    labels = {
        "Reconnaissance": "偵察",
        "Resource Development": "リソース準備",
        "Initial Access": "初期侵入",
        "Execution": "実行",
        "Persistence": "永続化",
        "Privilege Escalation": "権限昇格",
        "Defense Evasion": "防衛回避",
        "Credential Access": "認証情報アクセス",
        "Discovery": "探索",
        "Lateral Movement": "横展開",
        "Collection": "収集",
        "Command and Control": "C2通信",
        "Exfiltration": "情報持ち出し",
        "Impact": "影響",
    }
    return labels.get(value, value)


def _ja_claim_category_label(value: str) -> str:
    labels = {
        "observed_fact": "確認事実",
        "interpretation": "分析結果",
        "recommendation": "推奨対応",
        "limitation": "制約事項",
    }
    return labels.get(value, value.replace("_", " "))


def _looks_internal_section_key(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9_:-]+", value))


def _mermaid_label(value: str) -> str:
    return value.replace('"', "'").replace("\n", " ")


def _evidence_for_claim(claim: Claim | None, evidence_aliases: dict[str, str]) -> str:
    if claim is None or not claim.supporting_evidence:
        return "—"
    rendered = [
        _alias(eid, evidence_aliases)
        for eid in claim.supporting_evidence[:5]
        if eid in evidence_aliases or re.fullmatch(r"EV-\d{3,}", eid)
    ]
    return ", ".join(rendered) if rendered else "—"


def _normalize_target_labels_in_text(text: str) -> str:
    """Normalize only mechanical duplicate labels; do not map case-specific names."""

    normalized = text
    duplicate_pattern = re.compile(
        r"(?<![/\\\w.-])(?P<label>[^/\n|`]{2,60}?)\s*/\s*(?P=label)(?![/\\\w.-])",
        re.IGNORECASE,
    )
    while True:
        updated = duplicate_pattern.sub(lambda match: match.group("label").strip(), normalized)
        if updated == normalized:
            return normalized
        normalized = updated


def _timeline_evidence_label(
    item: TimelineEntry,
    evidence_aliases: dict[str, str],
) -> str | None:
    if item.evidence_id in evidence_aliases:
        return evidence_aliases[item.evidence_id]
    if re.fullmatch(r"EV-\d{3,}", item.evidence_id):
        return item.evidence_id
    return None


def _priority_from_severity(severity: str) -> str:
    return {"critical": "高", "major": "中", "minor": "低"}.get(severity, "中")


def _looks_like_containment(gap: Gap) -> bool:
    text = f"{gap.description} {gap.recommended_action}".lower()
    keywords = [
        "隔離",
        "無効",
        "リセット",
        "遮断",
        "封じ込め",
        "復旧",
        "確認",
        "contain",
        "isolate",
        "reset",
        "block",
    ]
    return any(keyword in text for keyword in keywords)


def _alias(evidence_id: str, evidence_aliases: dict[str, str]) -> str:
    return evidence_aliases.get(evidence_id, evidence_id)


def _escape_md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _is_noise_url(value: str) -> bool:
    lower = value.lower().rstrip("/,")
    return lower.endswith((".local", ".example.local")) or "example.local" in lower


def _is_noise_domain(value: str) -> bool:
    lower = value.lower().strip(".")
    if lower.endswith(".example") or lower == "example":
        return True
    if lower.endswith(
        (".php", ".html", ".ps1", ".exe", ".dll", ".txt", ".csv", ".log", ".md", ".local")
    ):
        return True
    if lower in {"net.webclient"}:
        return True
    if re.fullmatch(r"[a-z]\.[a-z]+", lower):
        return True
    return False


def _is_useful_path(value: str) -> bool:
    lower = value.lower()
    if any(ord(ch) > 127 for ch in value):
        return False
    if any(token in lower for token in ("commandline", "example.local", ".local/")):
        return False
    if any(token in value for token in ("CommandLine=", "を実行", "、")):
        return False
    stripped = value.rstrip("`")
    normalized = stripped.replace("\\", "/")
    normalized_lower = normalized.lower()
    if stripped.startswith("\\\\"):
        return False
    leaf = normalized.rsplit("/", 1)[-1].lower()
    if _looks_like_directory_path(normalized):
        return False
    if _is_common_platform_path(normalized_lower):
        return False
    if _is_static_web_asset(leaf):
        return False
    if len(stripped) > 140:
        return False
    return ("\\" in stripped or "/" in stripped) and not stripped.endswith("\\")


def _looks_like_directory_path(normalized_path: str) -> bool:
    leaf = normalized_path.rstrip("/").rsplit("/", 1)[-1]
    return "." not in leaf


def _is_common_platform_path(normalized_lower: str) -> bool:
    common_prefixes = (
        "c:/windows/",
        "c:/program files/",
        "c:/program files (x86)/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/lib/",
        "/lib64/",
    )
    return normalized_lower.startswith(common_prefixes)


def _is_static_web_asset(leaf: str) -> bool:
    static_extensions = (
        ".html",
        ".htm",
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".txt",
        ".md",
    )
    return leaf.endswith(static_extensions)


def _table_caption(title: str) -> str:
    return f'<div class="table-caption">{title}</div>'


def _data_types_for_entries(entries: list[EvidenceLedgerEntry]) -> str:
    types: list[str] = []
    for entry in entries:
        ref = entry.source_refs[0] if entry.source_refs else None
        data_type = _data_type_for_source(ref.source_path if ref else "")
        if data_type not in types:
            types.append(data_type)
    return "、".join(types[:4]) if types else "提供資料"


def _period_for_entries(entries: list[EvidenceLedgerEntry]) -> str:
    times: list[str] = []
    for entry in entries:
        ref = entry.source_refs[0] if entry.source_refs else None
        chunks = [entry.observed_fact, entry.interpretation, ref.excerpt if ref else ""]
        times.extend(_extract_event_times("\n".join(chunks)))
    return _format_period(times)


def _format_period(times: list[str]) -> str:
    unique = sorted(set(times))
    if not unique:
        return "提供資料上は特定できません"
    if len(unique) == 1:
        return unique[0]
    return f"{unique[0]} ～ {unique[-1]}"


def _coverage_limitation_for_entries(entries: list[EvidenceLedgerEntry]) -> str:
    if any(entry.interpretation_confidence.value == "low" for entry in entries):
        return "解釈信頼度が低い証拠を含みます"
    if len(entries) == 1:
        return "単一証拠に基づきます"
    return "提供済み証拠の範囲に基づきます"


def _data_type_for_source(source_path: str) -> str:
    lower = source_path.lower()
    if lower.endswith((".evtx", ".evtx.txt")) or "security_event" in lower:
        return "Windowsイベントログ"
    if lower.endswith((".log", ".log.txt")):
        return "ログ"
    if lower.endswith((".csv", ".csv.txt")):
        return "CSV/一覧"
    if lower.endswith((".md", ".txt")) or "notes" in lower:
        return "調査メモ"
    if lower:
        return "ファイル"
    return "提供資料"


def _trim(value: str, limit: int) -> str:
    value = " ".join(str(value).split())
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def _safe_report_text(value: str) -> str:
    """Normalize only sentence-ending expressions in report prose.

    Broad replacements break noun-modifying clauses such as
    「確認できる調査対象」, so this function only touches phrase endings.
    Fenced code blocks are excluded by the caller.
    """
    value = value.replace("断定", "判断")
    value = re.sub(r"と思われます(?=。|、|\n|$)", "可能性があります", value)
    value = re.sub(r"と思われる(?=。|、|\n|$)", "可能性があります", value)
    sentence_endings = [
        ("確認されています", "確認されました"),
        ("確認されていました", "確認されました"),
        ("確認されている", "確認されました"),
        ("確認された", "確認されました"),
        ("記録されています", "記録されました"),
        ("記録されていました", "記録されました"),
        ("記録されている", "記録されました"),
        ("記録された", "記録されました"),
        ("記録がある", "記録されました"),
        ("示されています", "示されました"),
        ("示されていました", "示されました"),
        ("示されている", "示されました"),
        ("示された", "示されました"),
        ("記載されています", "記載されました"),
        ("記載されていました", "記載されました"),
        ("記載されている", "記載されました"),
        ("記載された", "記載されました"),
        ("含まれています", "含まれます"),
        ("含まれている", "含まれます"),
        ("示唆された", "示唆されました"),
        ("示唆される", "示唆されます"),
        ("判明した", "判明しました"),
        ("考えられる", "考えられます"),
        ("見える", "見えます"),
        ("特定できない", "特定できません"),
        ("確認できない", "確認できません"),
        ("確認できていない", "確認できませんでした"),
        ("判断できない", "判断できません"),
        ("となっている", "となっていました"),
        ("可能性がある", "可能性があります"),
        ("必要がある", "必要があります"),
        ("必要である", "必要です"),
        ("妥当である", "妥当です"),
        ("限定的である", "限定的です"),
        ("不明である", "不明です"),
        ("である", "です"),
    ]
    for old, new in sentence_endings:
        value = re.sub(rf"{re.escape(old)}(?=。|\n|$)", new, value)
    return value


def _defang(value: str) -> str:
    value = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return value.replace(".", "[.]")
