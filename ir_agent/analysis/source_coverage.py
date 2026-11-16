"""Source coverage: how far each ingested artifact made it into the ledger.

The evidence ledger only records what was approved, so an artifact that was
provided but never extracted from (or whose candidates were all rejected) is
invisible downstream: the report can silently omit a whole log source. This
module compares the file inventory against chunks, evidence candidates, and
the active evidence ledger, and classifies every provided file:

- ``in_ledger``      : cited by at least one active ledger entry
- ``not_approved``   : has candidates, but none reached the ledger
                       (rejected or not yet judged)
- ``not_extracted``  : chunked, but no evidence candidate cites it
- ``not_chunked``    : in the inventory but never chunked

Manifest hosts that have no file in the inventory are reported as
``not_provided``. The distinction matters for the report: "not provided"
is a collection limitation, "not extracted" / "not approved" are gaps in
the analysis itself.

The module is dict-based (plain JSON in, plain JSON out) so that skill
scripts can read ``data/source_coverage.json`` without importing models.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ir_agent.analysis.coverage import infer_data_source_type

SOURCE_COVERAGE_FILE = "source_coverage.json"

IN_LEDGER = "in_ledger"
NOT_APPROVED = "not_approved"
NOT_EXTRACTED = "not_extracted"
NOT_CHUNKED = "not_chunked"
NOT_PROVIDED = "not_provided"

STATUS_LABELS_JA = {
    IN_LEDGER: "台帳あり",
    NOT_APPROVED: "未承認",
    NOT_EXTRACTED: "未抽出",
    NOT_CHUNKED: "未取り込み",
    NOT_PROVIDED: "未提供",
}

# Statuses that mean a provided file contributed nothing to the ledger.
UNUSED_STATUSES = (NOT_APPROVED, NOT_EXTRACTED, NOT_CHUNKED)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _active_ledger(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Active view of the append-only ledger: drop withdrawn and superseded."""
    withdrawn = {r.get("evidence_id") for r in records if r.get("withdrawn")}
    superseded = {r.get("supersedes") for r in records if r.get("supersedes")}
    seen: set[str] = set()
    active = []
    for r in records:
        eid = r.get("evidence_id")
        if not eid or eid in withdrawn or eid in superseded or eid in seen:
            continue
        seen.add(eid)
        active.append(r)
    return active


def _ref_keys(ref: dict[str, Any]) -> list[str]:
    keys = []
    if ref.get("source_file_id"):
        keys.append(f"id:{ref['source_file_id']}")
    if ref.get("source_path"):
        keys.append(f"path:{ref['source_path']}")
    return keys


def _cited_lines(refs: list[dict[str, Any]]) -> int:
    lines: set[int] = set()
    for ref in refs:
        span = ref.get("source_lines") or []
        if len(span) == 2 and all(isinstance(n, int) for n in span):
            lines.update(range(span[0], span[1] + 1))
    return len(lines)


def build_source_coverage(
    case_dir: Path, manifest_hosts: list[str] | None = None
) -> dict[str, Any]:
    """Classify every inventory file and every manifest host.

    Args:
        case_dir: The case working directory.
        manifest_hosts: Hosts in scope (from manifest.yaml). Hosts with no
            inventory file are reported as not provided.

    Returns:
        A JSON-serializable report with ``files``, ``missing_hosts`` and
        ``summary`` (counts per status).
    """
    data_dir = case_dir / "data"
    inventory_path = data_dir / "file_inventory.json"
    inventory: list[dict[str, Any]] = []
    if inventory_path.exists():
        loaded = json.loads(inventory_path.read_text(encoding="utf-8"))
        if isinstance(loaded, list):
            inventory = loaded

    chunked: set[str] = set()
    chunks_dir = data_dir / "chunks"
    if chunks_dir.is_dir():
        for chunk_path in chunks_dir.glob("*.json"):
            try:
                chunk = json.loads(chunk_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            chunked.update(_ref_keys(chunk))

    candidate_refs: dict[str, list[str]] = {}
    for cand in _read_jsonl(data_dir / "evidence_candidates.jsonl"):
        for ref in cand.get("source_refs") or []:
            for key in _ref_keys(ref):
                candidate_refs.setdefault(key, []).append(
                    str(cand.get("candidate_id", ""))
                )

    ledger_refs: dict[str, list[dict[str, Any]]] = {}
    ledger_ids: dict[str, list[str]] = {}
    for entry in _active_ledger(_read_jsonl(data_dir / "evidence_ledger.jsonl")):
        for ref in entry.get("source_refs") or []:
            for key in _ref_keys(ref):
                ledger_refs.setdefault(key, []).append(ref)
                ids = ledger_ids.setdefault(key, [])
                eid = str(entry.get("evidence_id", ""))
                if eid not in ids:
                    ids.append(eid)

    files: list[dict[str, Any]] = []
    for item in inventory:
        keys = _ref_keys({"source_file_id": item.get("file_id"),
                          "source_path": item.get("path")})
        # Look up by file id first; fall back to path so a re-ingested
        # artifact version still matches older candidates and ledger rows.
        evidence_ids = next((ledger_ids[k] for k in keys if k in ledger_ids), [])
        refs = next((ledger_refs[k] for k in keys if k in ledger_refs), [])
        candidates = next(
            (candidate_refs[k] for k in keys if k in candidate_refs), []
        )
        if evidence_ids:
            status = IN_LEDGER
        elif candidates:
            status = NOT_APPROVED
        elif any(k in chunked for k in keys):
            status = NOT_EXTRACTED
        else:
            status = NOT_CHUNKED
        metadata = item.get("metadata") or {}
        path = str(item.get("path") or "")
        files.append({
            "file_id": item.get("file_id"),
            "path": path,
            "host": item.get("host") or metadata.get("system"),
            "artifact_kind": metadata.get("artifact_kind"),
            "data_source_type": infer_data_source_type(path),
            "line_count": item.get("line_count"),
            "status": status,
            "status_label": STATUS_LABELS_JA[status],
            "candidate_count": len(set(candidates)),
            "evidence_ids": evidence_ids,
            "cited_line_count": _cited_lines(refs),
        })
    files.sort(key=lambda f: (str(f["host"] or ""), f["path"]))

    provided_hosts = {
        str(h).lower()
        for item in inventory
        for h in (item.get("host"), (item.get("metadata") or {}).get("system"))
        if h
    }
    missing_hosts = [
        {"host": h, "status": NOT_PROVIDED, "status_label": STATUS_LABELS_JA[NOT_PROVIDED]}
        for h in (manifest_hosts or [])
        if str(h).lower() not in provided_hosts
    ]

    summary = {status: 0 for status in STATUS_LABELS_JA}
    for f in files:
        summary[f["status"]] += 1
    summary[NOT_PROVIDED] = len(missing_hosts)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "files": files,
        "missing_hosts": missing_hosts,
    }


def load_source_coverage(
    case_dir: Path, manifest_hosts: list[str] | None = None
) -> dict[str, Any]:
    """Build the report from the case dir, reading manifest hosts if needed."""
    if manifest_hosts is None:
        manifest_hosts = _manifest_hosts(case_dir)
    return build_source_coverage(case_dir, manifest_hosts)


def _manifest_hosts(case_dir: Path) -> list[str]:
    path = case_dir / "manifest.yaml"
    if not path.exists():
        return []
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return []
    hosts = data.get("hosts") or []
    return [str(h) for h in hosts] if isinstance(hosts, list) else []


# Case-level gaps are not tied to one analysis result.
CASE_SCOPE_CLAIM_ID = "CASE-SCOPE"

_GAP_RULES: list[tuple[str, str, str, str, str]] = [
    # (status, gap_type, severity, description head, recommended action)
    (
        NOT_PROVIDED, "unavailable_logs", "major",
        "調査対象ホストのうち、提供資料にログ・アーティファクトが含まれない"
        "ホストがあります",
        "当該ホストの資料を追加取得するか、未提供である旨を調査上の制約として"
        "報告書に記載してください。",
    ),
    (
        NOT_CHUNKED, "logs_not_analyzed", "major",
        "取り込み済みファイルのうち、チャンク化されず解析対象になっていない"
        "ファイルがあります",
        "取り込みをやり直して解析対象に含めるか、解析しなかった理由を"
        "調査上の制約として記載してください。",
    ),
    (
        NOT_EXTRACTED, "logs_not_analyzed", "major",
        "提供されたファイルのうち、証拠となる記録が 1 件も抽出されていない"
        "ファイルがあります",
        "当該ファイルを証拠抽出の対象として再確認するか、関連する事象が"
        "含まれない(または解析対象外とした)旨を記載してください。",
    ),
    (
        NOT_APPROVED, "logs_not_analyzed", "minor",
        "記録は抽出されたものの、証拠として承認されたものが 1 件もない"
        "ファイルがあります",
        "却下・保留の判断が妥当かを確認し、報告書で当該ファイルに"
        "触れない理由を記載してください。",
    ),
]


def source_coverage_gap_specs(report: dict[str, Any]) -> list[dict[str, str]]:
    """Case-level gap specs (one per non-empty category) for check-gaps.

    Returns plain dicts with ``related_claim_id``, ``gap_type``,
    ``severity``, ``description`` and ``recommended_action``; the caller
    assigns ``gap_id`` and builds the Gap model.
    """
    specs: list[dict[str, str]] = []
    for status, gap_type, severity, head, action in _GAP_RULES:
        if status == NOT_PROVIDED:
            items = [str(h["host"]) for h in report.get("missing_hosts", [])]
        else:
            items = [f["path"] for f in report.get("files", [])
                     if f["status"] == status]
        if not items:
            continue
        listed = ", ".join(items[:10])
        if len(items) > 10:
            listed += f" ほか {len(items) - 10} 件"
        specs.append({
            "related_claim_id": CASE_SCOPE_CLAIM_ID,
            "gap_type": gap_type,
            "severity": severity,
            "description": (
                f"{head}({STATUS_LABELS_JA[status]} {len(items)} 件: {listed})。"
            ),
            "recommended_action": action,
        })
    return specs


def write_source_coverage(case_dir: Path, report: dict[str, Any]) -> Path:
    """Write the report to ``data/source_coverage.json`` (derived view)."""
    out = case_dir / "data" / SOURCE_COVERAGE_FILE
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    return out


def summary_line(report: dict[str, Any]) -> str:
    """One-line summary for ``status`` and CLI output."""
    s = report.get("summary", {})
    total = len(report.get("files", []))
    return (
        f"{s.get(IN_LEDGER, 0)}/{total} files in ledger; "
        f"not approved {s.get(NOT_APPROVED, 0)}, "
        f"not extracted {s.get(NOT_EXTRACTED, 0)}, "
        f"not chunked {s.get(NOT_CHUNKED, 0)}, "
        f"hosts not provided {s.get(NOT_PROVIDED, 0)}"
    )
