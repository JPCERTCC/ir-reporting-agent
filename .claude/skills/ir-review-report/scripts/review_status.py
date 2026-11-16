#!/usr/bin/env python3
"""Report exactly what stage an ir-review-report run is at and what to run next.

This is the single source of truth for "where am I / what do I run next" in a
review run directory. Agents lose track of the ~11-step pipeline as a
conversation grows (exact paths and flags scroll out of context), and start
writing one-off scripts to fill perceived gaps instead of rereading a long
SKILL.md. This script re-derives status from the artifacts already on disk
every time it is run, so nothing has to be remembered across turns: run it,
copy the "NEXT COMMAND" it prints, run that, and run this again.

It also appends one line per invocation to <review-dir>/run_log.jsonl, so a
gate that fails repeatedly is visible (attempt count) even after the
conversation that saw the earlier failures is gone. On a gate failure it also
(re)writes repair_instructions.json via make_repair_instructions.py so the
next concrete action is a file to read, not a wall of stderr to parse.

This script only reads existing artifacts and appends to run_log.jsonl /
repair_instructions.json. It does not fill results.json, write issues, or run
the SubAgent tasks — those steps still require the Agent's judgment.

Usage:
    python review_status.py --review-dir reviews/ReportA/20260921-190000_customer
"""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import review_io

SCRIPTS_DIR = Path(__file__).resolve().parent
SKILL_DIR_DEFAULT = SCRIPTS_DIR.parent


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _result_id(row: dict) -> str | None:
    return row.get("checklist_id") or row.get("id")


def infer_mode(review_dir: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    manifest = _load_json(review_dir / "run_manifest.json")
    if isinstance(manifest, dict) and manifest.get("review_mode") in {
        "customer", "reporter", "both",
    }:
        return str(manifest["review_mode"])
    results_data = _load_json(review_dir / "results.json")
    ids: set[str] = set()
    if isinstance(results_data, dict):
        for row in results_data.get("results", []):
            if isinstance(row, dict) and _result_id(row):
                ids.add(str(_result_id(row)))
    has_customer = any(i.startswith("CUS-") for i in ids)
    has_reporter = any(i.startswith("REP-") for i in ids)
    if has_customer and not has_reporter:
        return "customer"
    if has_reporter and not has_customer:
        return "reporter"
    return "both"


# The 4 claim_assessments.json arrays, per json_contracts.md — the single
# source of truth for these names. required must be non-empty; optional may
# be an empty list but should still exist as a key.
REQUIRED_CLAIM_ARRAYS = ["conclusion_inventory", "consistency_assessments", "claim_assessments"]
OPTIONAL_CLAIM_ARRAYS = ["recommendation_assessments"]
ALL_CLAIM_KEYS = REQUIRED_CLAIM_ARRAYS + OPTIONAL_CLAIM_ARRAYS


def diagnose_claims(claims: Any) -> str:
    """Explain exactly why claim_assessments.json failed the presence check.

    A bare "不足: claim_assessments.json (4配列)" message once cost an Agent
    10+ turns re-reading a syntactically-valid file it could not see was
    wrong: it had used "individual_claim_assessments" /
    "countermeasure_assessments" instead of the real field names
    "claim_assessments" / "recommendation_assessments". Naming the present
    keys and the expected keys side by side makes that instantly visible.
    """
    if not isinstance(claims, dict):
        return "claim_assessments.json が存在しないか、JSON object ではありません。"
    present_keys = sorted(claims.keys())
    missing_or_empty = [k for k in REQUIRED_CLAIM_ARRAYS if not claims.get(k)]
    unexpected_keys = [k for k in present_keys if k not in ALL_CLAIM_KEYS]
    lines = [
        f"claim_assessments.json の現在のトップレベルキー: {', '.join(present_keys) or '(なし)'}",
    ]
    if missing_or_empty:
        lines.append(
            "不足または空の必須配列: " + ", ".join(missing_or_empty)
        )
    if unexpected_keys:
        lines.append(
            "想定外のキーがあります（フィールド名を間違えている可能性）: "
            + ", ".join(unexpected_keys)
            + f"。正しいキー名は次の4つです（json_contracts.md が正本）: {', '.join(ALL_CLAIM_KEYS)}"
        )
    return "\n".join(lines)



class Stage:
    """One pipeline stage's status, printed as one line in the checklist."""

    def __init__(self, key: str, label: str):
        self.key = key
        self.label = label
        self.ok = False
        self.detail = ""
        self.next_command: str | None = None
        self.next_note: str | None = None

    def mark(self, ok: bool, detail: str, *, next_command: str | None = None,
             next_note: str | None = None) -> None:
        self.ok = ok
        self.detail = detail
        self.next_command = next_command
        self.next_note = next_note

    def line(self) -> str:
        box = "[x]" if self.ok else "[ ]"
        return f"{box} {self.label}: {self.detail}"


def append_log(review_dir: Path, event: dict[str, Any]) -> None:
    log_path = review_dir / "run_log.jsonl"
    event = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(), **event}
    line = json.dumps(event, ensure_ascii=False)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def count_recent_failures(review_dir: Path, gate: str) -> int:
    """Consecutive most-recent failures of `gate`, read from run_log.jsonl."""
    log_path = review_dir / "run_log.jsonl"
    if not log_path.exists():
        return 0
    streak = 0
    lines = log_path.read_text(encoding="utf-8").splitlines()
    for line in reversed(lines):
        try:
            event = json.loads(line)
        except Exception:
            continue
        if event.get("event") != "gate_result" or event.get("gate") != gate:
            continue
        if event.get("ok"):
            break
        streak += 1
    return streak


def _summarize_failure(out: str, limit: int = 400) -> str:
    """First failing lines of a gate's output, so run_log.jsonl records *why*."""
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return " | ".join(lines[:4])[:limit]


def _repair_targets(repair_path: Path) -> list[str]:
    data = _load_json(repair_path)
    repairs = data.get("repairs", []) if isinstance(data, dict) else []
    return sorted({
        str(r.get("target_file")) for r in repairs
        if isinstance(r, dict) and r.get("target_file")
    })


def run_gate(argv: list[str]) -> tuple[bool, str]:
    proc = subprocess.run(argv, capture_output=True, text=True)
    text = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    return proc.returncode == 0, text.strip()


VALIDATION_GATES = 4  # coverage, claim_assessments, absence_grounding, issues


def _passed(gate_name: str, idx: int, total: int) -> "Stage":
    stage = Stage(gate_name, f"品質ゲート {idx}/{total}: {gate_name}")
    stage.mark(True, "PASS")
    return stage


def _failed_validation(
    review_dir: Path, scripts: Path, failures: list[tuple[str, str, int]],
) -> "Stage":
    """One stage reporting every failing validation gate, with merged repairs."""
    names = [f[0] for f in failures]
    stage = Stage("validation", f"検証 FAIL: {', '.join(names)}")
    repairs: list[dict[str, Any]] = []
    for gate_name, out, attempts in failures:
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write(out)
            log_path = Path(fh.name)
        part = Path(tempfile.mkdtemp()) / "repairs.json"
        subprocess.run([
            sys.executable, str(scripts / "make_repair_instructions.py"),
            "--gate", gate_name, "--stdout", str(log_path),
            "--review-dir", str(review_dir), "--out", str(part),
            "--attempt", str(attempts),
        ], capture_output=True, text=True)
        log_path.unlink(missing_ok=True)
        data = _load_json(part)
        for repair in (data or {}).get("repairs", []) if isinstance(data, dict) else []:
            repairs.append({**repair, "gate": gate_name})
        part.unlink(missing_ok=True)
        part.parent.rmdir()
    for n, repair in enumerate(repairs, 1):
        repair["problem_id"] = f"RPR-{n:03d}"
    repair_path = review_dir / "repair_instructions.json"
    max_attempts = max(f[2] for f in failures)
    review_io.atomic_write_json(repair_path, {
        "schema_version": "1.0",
        "failed_gates": names,
        "failed_gate": names[0],
        "attempt": max_attempts,
        "review_dir": str(review_dir),
        "repairs": repairs,
    })
    append_log(review_dir, {
        "event": "repair_targets", "gates": names,
        "target_files": _repair_targets(repair_path),
    })
    body = "\n\n".join(f"--- {name} ---\n{out}" for name, out, _ in failures)
    note = (
        f"{body}\n\nrepair_instructions.json を書き出しました: {repair_path}"
        f"（上記 {len(failures)} 件の gate の修正指示をまとめています）。\n"
        f"同じ gate は直近 {max_attempts} 回連続で FAIL しています。"
        "指摘は一度にまとめて直してください。通すことだけを目的に、SubAgent の観測を"
        "捨てたり、根拠を付け替えたりしないでください。"
    )
    if max_attempts >= 3:
        note += (
            "\n同一原因で3回以上 FAIL しています。SKILL.md のルールにより、"
            "自己修正を続けず、失敗 gate・原因・次に修正するファイルをユーザーに報告して"
            "停止してください。"
        )
    stage.mark(False, "FAIL", next_note=note)
    return stage


MAX_DIGEST_ITEMS = 60


def _judgment_digest(
    worksheet: dict[str, Any], ids: list[str], spans: dict[str, str],
) -> str:
    """Compact per-item view of what SubAgents observed, for the items the Agent
    still has to judge. Without it the Agent reads the 100KB worksheet by
    writing throwaway "viewer" scripts (five in one real run); with it, this
    output is all that is needed to judge."""

    def clip(text: Any, n: int) -> str:
        t = " ".join(str(text or "").split())
        return t if len(t) <= n else t[: n - 1] + "…"

    by_id = {
        c.get("checklist_id"): c for c in worksheet.get("checklist_items", [])
        if isinstance(c, dict)
    }
    blocks: list[str] = []
    for cid in ids[:MAX_DIGEST_ITEMS]:
        c = by_id.get(cid)
        if not c:
            continue
        tags = []
        if c.get("unknown_allowed"):
            tags.append("unknown可")
        if "場合］" in str(c.get("item", "")):
            tags.append("条件付き")
        counts = c.get("candidate_verdict_counts") or {}
        summary = (
            "観測0件（全 chunk で記載が観測されなかった）" if not c.get("observation_count")
            else " ".join(f"{v}×{n}" for v, n in counts.items())
            + ("  ※食い違い" if c.get("conflicting") else "")
        )
        head = f"■ {cid} [{c.get('level', '-')}{'/' + '/'.join(tags) if tags else ''}] " \
               f"{clip(c.get('item'), 90)}"
        lines = [head, f"    観測: {summary}"]
        observations = c.get("observations") or []
        for o in observations[:4]:
            shown = [
                f"{sid}「{clip(spans.get(sid, ''), 60)}」"
                for sid in (o.get("source_span_ids") or [])[:2]
            ]
            lines.append(
                f"    - {o.get('chunk_id', '?')} {o.get('candidate_verdict', '?')}: "
                f"{clip(o.get('rationale'), 120)}" + (f"  [{' / '.join(shown)}]" if shown else "")
            )
        if len(observations) > 4:
            lines.append(f"    - …他 {len(observations) - 4} 件の観測")
        blocks.append("\n".join(lines))
    more = len(ids) - MAX_DIGEST_ITEMS
    if more > 0:
        blocks.append(f"（ほか {more} 件。この件数を判定したら review_status.py を再実行）")
    return "\n".join(blocks)


def check_pipeline(review_dir: Path, skill_dir: Path, mode: str) -> list[Stage]:
    scripts = skill_dir / "scripts"
    stages: list[Stage] = []

    # 1. normalized report text
    s = Stage("normalize", "報告書正規化")
    normalized = review_dir / "normalized.txt"
    if normalized.exists() and normalized.stat().st_size > 0:
        s.mark(True, str(normalized))
    else:
        s.mark(
            False, "normalized.txt が存在しません",
            next_command=(
                f'"$PYTHON" {scripts / "prepare_report.py"} '
                f'--report <report> --out {normalized}'
            ),
        )
    stages.append(s)
    if not s.ok:
        return stages

    # 2. source index
    s = Stage("source_index", "原文 span index")
    source_index_path = review_dir / "source_index.json"
    source_index = _load_json(source_index_path)
    if isinstance(source_index, dict) and source_index.get("spans"):
        s.mark(True, f"{len(source_index['spans'])} spans")
    elif source_index_path.exists():
        s.mark(
            False, "source_index.json が壊れているか spans が空です。削除して再生成してください",
            next_command=(
                f'rm {source_index_path} && "$PYTHON" {scripts / "build_source_index.py"} '
                f'--source {normalized} --out {source_index_path}'
            ),
        )
    else:
        s.mark(
            False, "source_index.json が存在しません",
            next_command=(
                f'"$PYTHON" {scripts / "build_source_index.py"} '
                f'--source {normalized} --out {source_index_path}'
            ),
        )
    stages.append(s)
    if not s.ok:
        return stages

    # 3. run manifest
    s = Stage("run_manifest", "run_manifest.json")
    manifest_path = review_dir / "run_manifest.json"
    manifest = _load_json(manifest_path)
    required_keys = {"run_id", "review_mode", "report_path", "model"}
    if isinstance(manifest, dict) and required_keys <= set(manifest):
        s.mark(True, f"review_mode={manifest.get('review_mode')}")
    else:
        s.mark(
            False,
            f"run_manifest.json に {sorted(required_keys)} が必要です",
            next_note=(
                f"{manifest_path} を Write ツールで作成してください"
                "（run_id, review_mode, report_path, model を含める）。"
            ),
        )
    stages.append(s)
    if not s.ok:
        return stages

    # 4. mechanical checks + results template
    s = Stage("templates", "機械チェック / results.json 雛形")
    mechanical_path = review_dir / "mechanical_checks.json"
    results_path = review_dir / "results.json"
    missing = [p.name for p in (mechanical_path, results_path) if not p.exists()]
    if not missing:
        s.mark(True, "mechanical_checks.json, results.json")
    else:
        cmds = []
        if "mechanical_checks.json" in missing:
            cmds.append(
                f'"$PYTHON" {scripts / "mechanical_checks.py"} --report {normalized} '
                f'> {mechanical_path}'
            )
        if "results.json" in missing:
            cmds.append(
                f'"$PYTHON" {scripts / "init_results_template.py"} --mode {mode} '
                f'--out {results_path}'
            )
        s.mark(False, f"不足: {', '.join(missing)}", next_command=" && ".join(cmds))
    stages.append(s)
    if not s.ok:
        return stages

    # 5. chunks + SubAgent tasks
    s = Stage("chunks_tasks", "chunk 化 / SubAgent task 作成")
    chunk_manifest_path = review_dir / "review_chunks" / "chunk_manifest.json"
    task_manifest_path = review_dir / "subagent_tasks" / "task_manifest.json"
    if chunk_manifest_path.exists() and task_manifest_path.exists():
        task_manifest = _load_json(task_manifest_path) or {}
        s.mark(True, f"{len(task_manifest.get('tasks', []))} tasks")
    else:
        s.mark(
            False, "review_chunks / subagent_tasks が未作成です",
            next_command=(
                f'"$PYTHON" {scripts / "create_review_chunks.py"} '
                f'--source-index {source_index_path} '
                f'--out-dir {review_dir / "review_chunks"} --mode {mode} && '
                f'"$PYTHON" {scripts / "create_subagent_tasks.py"} '
                f'--chunk-dir {review_dir / "review_chunks"} '
                f'--out-dir {review_dir / "subagent_tasks"} --mode {mode}'
            ),
        )
    stages.append(s)
    if not s.ok:
        return stages

    # 6/7. SubAgent observations + merge
    s = Stage("subagent_observations", "SubAgent 観測 + coverage 統合")
    task_manifest = _load_json(task_manifest_path) or {}
    tasks = task_manifest.get("tasks", [])
    pending: list[dict[str, str]] = []
    for task in tasks:
        chunk_id = str(task.get("chunk_id", "?"))
        # Locations are derived from review_dir, never from the current
        # directory: paths stored in the manifest are relative to wherever the
        # task creator happened to run, and resolving them from another
        # directory reported finished SubAgent work as "6/6 unprocessed".
        obs_path = review_dir / "subagent_observations" / f"{chunk_id}.json"
        shown_task = str(review_dir / "subagent_tasks" / f"{chunk_id}.json")
        obs = _load_json(obs_path)
        if obs is None and task.get("observation_output_path"):
            obs = _load_json(Path(str(task["observation_output_path"])))
        if not isinstance(obs, dict) or not obs.get("covered_span_ids"):
            pending.append({"chunk_id": chunk_id, "task_path": shown_task})

    merged_path = review_dir / "merged_observations.json"
    ledger_path = review_dir / "coverage_ledger.json"
    observations_dir = review_dir / "subagent_observations"
    worksheet_path = review_dir / "aggregation_worksheet.json"

    if pending:
        pending_desc = ", ".join(f"{p['chunk_id']}" for p in pending[:10])
        more = "" if len(pending) <= 10 else f" 他{len(pending) - 10}件"
        note_lines = [
            f"未完了の SubAgent task ({len(pending)}/{len(tasks)}): {pending_desc}{more}",
            "各 task_path に対して手順6の要領で SubAgent を起動してください:",
        ]
        for p in pending[:10]:
            note_lines.append(f"  - {p['chunk_id']}: {p['task_path']}")
        s.mark(False, f"{len(pending)}/{len(tasks)} chunk が未処理", next_note="\n".join(note_lines))
    elif tasks:
        ok, out = run_gate([
            sys.executable, str(scripts / "merge_subagent_observations.py"),
            "--observations-dir", str(observations_dir),
            "--chunk-manifest", str(chunk_manifest_path),
            "--out", str(merged_path),
            "--coverage-ledger", str(ledger_path),
            "--source-index", str(source_index_path),
        ])
        if ok:
            # Regenerate the grouped worksheet every time merge succeeds, so
            # it always reflects the current merged_observations.json. This
            # is pure mechanical grouping (see aggregate_observations.py's
            # docstring) — it does not decide any verdict.
            worksheet_ok, worksheet_out = run_gate([
                sys.executable, str(scripts / "aggregate_observations.py"),
                "--merged-observations", str(merged_path),
                "--results", str(results_path),
                "--out", str(worksheet_path),
            ])
            if worksheet_ok:
                s.mark(True, "coverage_complete")
            else:
                # Must not silently fall through: the next stage's guidance
                # depends on this file existing and being current. Report the
                # failure instead of pointing at a missing/stale worksheet.
                s.mark(
                    False,
                    "aggregation_worksheet.json の生成に失敗",
                    next_note=(
                        f"{worksheet_path} の生成が失敗しました。"
                        f"{merged_path} または {results_path} が壊れていないか"
                        f"確認してください。\n{worksheet_out}"
                    ),
                )
        else:
            ledger = _load_json(ledger_path) or {}
            uncovered = ledger.get("uncovered_span_ids", [])
            missing_chunks = [
                c.get("chunk_id") for c in ledger.get("chunks", [])
                if c.get("status") != "completed"
            ]
            s.mark(
                False,
                f"coverage 未完了 (uncovered spans={len(uncovered)}, "
                f"未完了 chunk={missing_chunks})",
                next_note=(
                    "対象 chunk の task_path を task_manifest.json で確認し、"
                    "その chunk だけ SubAgent を再起動してから、"
                    "このスクリプトを再実行してください。\n" + out
                ),
            )
    else:
        s.mark(False, "subagent_tasks が空です")
    stages.append(s)
    if not s.ok:
        return stages

    # 8. results.json filled
    s = Stage("results_filled", "results.json 判定")
    results = _load_json(results_path) or {}
    rows = results.get("results", [])
    if any(isinstance(r, dict) and r.get("verdict") is None for r in rows):
        # Put the spans SubAgents observed onto still-unjudged rows so that
        # keeping them costs nothing (see prefill_result_spans.py).
        pf_ok, pf_out = run_gate([
            sys.executable, str(scripts / "prefill_result_spans.py"),
            "--review-dir", str(review_dir),
        ])
        append_log(review_dir, {"event": "prefill_result_spans", "ok": pf_ok,
                                "summary": pf_out[:200]})
        results = _load_json(results_path) or {}
        rows = results.get("results", [])
    unfilled = [
        _result_id(r) for r in rows
        if isinstance(r, dict) and r.get("verdict") is None
        and r.get("evaluation_scope") != "out_of_scope"
    ]
    if rows and not unfilled:
        s.mark(True, f"{len(rows)}/{len(rows)} 項目判定済み")
    else:
        preview = ", ".join(str(i) for i in unfilled[:10])
        more = "" if len(unfilled) <= 10 else f" 他{len(unfilled) - 10}件"
        worksheet = _load_json(worksheet_path)
        auto_ids = []
        if isinstance(worksheet, dict):
            unfilled_set = set(unfilled)
            auto_ids = [
                c["checklist_id"] for c in worksheet.get("checklist_items", [])
                if c.get("checklist_id") in unfilled_set
                and (c.get("suggestion") or {}).get("auto_applicable")
            ]
        auto_note = (
            f" まず、SubAgent の観測が一致している {len(auto_ids)} 件（全員が同じ verdict、"
            "または観測0件で未記載）は次のコマンドで"
            "一括転記できます（既に判定済みの行は上書きしません）: "
            f"python {SCRIPTS_DIR / 'apply_suggested_results.py'} --review-dir {review_dir}"
            " --all-auto 。その後の残りが Agent の判定対象です。"
            " 項目文に「すべて/各/一貫」等を含む項目は自動転記されないので、全体について"
            "成り立つかを確認して判定してください。"
            if auto_ids else ""
        )
        judge_ids = [i for i in unfilled if i not in set(auto_ids)]
        spans: dict[str, str] = {}
        source_index = _load_json(source_index_path)
        if isinstance(source_index, dict):
            for sp in source_index.get("spans", []):
                if isinstance(sp, dict):
                    spans[str(sp.get("source_span_id") or sp.get("span_id") or sp.get("id"))] = str(
                        sp.get("text") or "")
        digest = (
            _judgment_digest(worksheet, judge_ids, spans) if isinstance(worksheet, dict) else ""
        )
        s.mark(
            False,
            f"{len(rows) - len(unfilled)}/{len(rows)} 項目判定済み。未判定: {preview}{more}",
            next_note=(
                (auto_note.strip() + "\n\n" if auto_note else "")
                + (
                    f"判断が必要な項目（{len(judge_ids)} 件）の SubAgent 観測を要約します。"
                    "この要約だけで判定できます（worksheet を開き直したり、表示・集計用の"
                    "スクリプトを書いたりしません）。各行の verdict / rationale / "
                    "source_span_ids（または absence_check_ids）を "
                    f"{results_path} に Edit で書いてください。食い違いは根拠 span を読み直して"
                    "決め、観測0件の項目は報告書を検索し直さず項目の性質から選びます"
                    "（判定ルール: references/review_model.md）。\n\n" + digest
                    if judge_ids else
                    "残りは自動転記で埋まります。上のコマンドを実行してから、再実行してください。"
                )
            ),
        )
    stages.append(s)
    if not s.ok:
        return stages

    # 9. issues + claim assessments exist.
    #
    # Both files start from a skeleton derived from the SubAgent observations
    # (what is mechanical is filled in; the Agent writes the judgment). The
    # stage only checks the files exist — every content problem is reported
    # together by the validation pass below, not one gate at a time.
    s = Stage("issues_claims", "issues.json / claim_assessments.json")
    issues_path = review_dir / "issues.json"
    claims_path = review_dir / "claim_assessments.json"
    created: list[str] = []
    for label, path, script in (
        ("issues.json", issues_path, "init_issues_skeleton.py"),
        ("claim_assessments.json", claims_path, "init_claims_skeleton.py"),
    ):
        if path.exists():
            continue
        extra = ["--skill-dir", str(skill_dir)] if script == "init_issues_skeleton.py" else []
        sk_ok, sk_out = run_gate([
            sys.executable, str(scripts / script),
            "--review-dir", str(review_dir), *extra,
        ])
        append_log(review_dir, {
            "event": script.removesuffix(".py"), "ok": sk_ok, "summary": sk_out[:300],
        })
        created.append(
            f"{label} の雛形を自動生成しました（SubAgent の観測から機械的に決まる部分は"
            f"入力済みで、`auto_filled` に一覧があります）。\n{sk_out}"
            if sk_ok else f"{label} の雛形生成に失敗しました。\n{sk_out}"
        )
    claims = _load_json(claims_path)
    # Only the shape is checked here (the four keys exist as lists, catching
    # misspelled field names); emptiness and content are the validators' job.
    claims_ok = isinstance(claims, dict) and all(
        isinstance(claims.get(k), list) for k in REQUIRED_CLAIM_ARRAYS
    )
    if created:
        s.mark(
            False, "雛形を生成しました。内容を確認・記入してください",
            next_note=(
                "\n\n".join(created)
                + "\n\n雛形の値は SubAgent 観測からの既定値です。各項目を観測と本文に照らして"
                "確認し、`【要記入】` を実際の判断で置き換えてください（Edit で該当箇所のみ。"
                "全面的な書き直しや修正用スクリプトは不要です）。終わったら review_status.py を"
                "再実行します。"
            ),
        )
    elif issues_path.exists() and claims_ok:
        # A file the Agent wrote from scratch never went through the skeleton,
        # so SubAgent observations were not carried into it. Say so every run.
        handwritten = [
            path.name for path in (issues_path, claims_path)
            if "auto_filled" not in path.read_text(encoding="utf-8", errors="replace")
        ]
        if handwritten:
            append_log(review_dir, {"event": "handwritten_files", "files": handwritten})
        s.mark(True, "作成済み" + (
            f"\n    警告: {', '.join(handwritten)} は雛形（auto_filled 付き）から作られて"
            "いません。SubAgent の観測（reported にすべき topic、open_questions、根拠 span）が"
            "反映されていない可能性があります。雛形から作り直すなら、このファイルを別の場所に"
            "退避してから review_status.py を再実行してください。"
            if handwritten else ""
        ))
    else:
        note = diagnose_claims(claims) if not claims_ok else ""
        s.mark(
            False, "claim_assessments.json の形式が不正です" if not claims_ok else "不足",
            next_note=note or None,
        )
    stages.append(s)
    if not s.ok:
        return stages

    # 10. quality gates.
    #
    # review_status.py is the *only* place that produces the derived
    # artifacts below (SKILL.md no longer has the Agent invoke each gate by
    # hand, and there is deliberately no second script that re-runs this
    # same gate list — that used to be check_review_completion.py, which was
    # removed because it duplicated this exact sequence and had to be
    # hand-synced with it every time a gate changed). So these gates write
    # their outputs directly into review_dir, not a scratch tempdir:
    # otherwise coverage_summary.json / issues_normalized.json / summary.json
    # / summary.md / final_review.md would never actually land in the review
    # directory, and check_review_run.py (which requires them there) would
    # fail every time. render_review.py always regenerates final_review.md
    # fresh from the current JSON, per the "hand-editing is forbidden" rule,
    # so there is no separate hand-edit-drift check to run here.
    coverage_summary = review_dir / "coverage_summary.json"
    issues_normalized = review_dir / "issues_normalized.json"
    summary = review_dir / "summary.json"
    summary_md = review_dir / "summary.md"
    final_review = review_dir / "final_review.md"

    gates: list[tuple[str, list[str]]] = [
        ("check_coverage.py", [
            sys.executable, str(scripts / "check_coverage.py"),
            "--skill-dir", str(skill_dir), "--mode", mode,
            "--results", str(results_path),
            "--summary-json", str(coverage_summary),
        ]),
        ("check_claim_assessments.py", [
            sys.executable, str(scripts / "check_claim_assessments.py"),
            "--assessments", str(claims_path),
            "--source-index", str(source_index_path),
            "--merged-observations", str(merged_path),
            "--issues", str(issues_path),
        ]),
        ("check_absence_grounding.py", [
            sys.executable, str(scripts / "check_absence_grounding.py"),
            "--results", str(results_path), "--worksheet", str(worksheet_path),
        ]),
        ("check_issues.py", [
            sys.executable, str(scripts / "check_issues.py"),
            "--issues", str(issues_path), "--results", str(results_path),
            "--skill-dir", str(skill_dir), "--mode", mode,
            "--out", str(issues_normalized), "--summary-out", str(summary),
            "--markdown-out", str(summary_md),
            "--source-index", str(source_index_path), "--strict-grounding",
        ]),
        ("render_review.py", [
            sys.executable, str(scripts / "render_review.py"),
            "--issues", str(issues_normalized), "--summary", str(summary),
            "--results", str(results_path), "--claim-assessments", str(claims_path),
            "--mechanical", str(mechanical_path), "--skill-dir", str(skill_dir),
            "--mode", mode, "--metadata", str(manifest_path), "--out", str(final_review),
        ]),
        ("check_review_doc.py", [
            sys.executable, str(scripts / "check_review_doc.py"),
            "--review", str(final_review),
            "--issues", str(issues_normalized), "--summary", str(summary),
            "--results", str(results_path), "--source", str(normalized),
        ]),
        ("check_review_run.py", [
            sys.executable, str(scripts / "check_review_run.py"),
            "--review-dir", str(review_dir),
        ]),
    ]

    # The first VALIDATION_GATES check what the Agent wrote. They are all run
    # every time and reported together: stopping at the first failing gate made
    # a review take one round trip per problem type (12 FAIL rounds in one real
    # run), and each round is a chance to "fix" by whatever passes. The
    # remaining gates render and re-check tool-generated output.
    # Weak assessments get their own issue and truthful issue_ids before anything
    # is validated (bookkeeping, not judgment — see link_assessment_issues.py).
    lk_ok, lk_out = run_gate([
        sys.executable, str(scripts / "link_assessment_issues.py"),
        "--review-dir", str(review_dir),
    ])
    append_log(review_dir, {"event": "link_assessment_issues", "ok": lk_ok,
                            "summary": lk_out[:300]})
    validation = gates[:VALIDATION_GATES]
    failures: list[tuple[str, str, int]] = []
    for idx, (gate_name, argv) in enumerate(validation, start=1):
        ok, out = run_gate(argv)
        append_log(review_dir, {
            "event": "gate_result", "gate": gate_name, "ok": ok,
            **({} if ok else {"summary": _summarize_failure(out)}),
        })
        if ok:
            stages.append(_passed(gate_name, idx, len(gates)))
        else:
            failures.append((gate_name, out, count_recent_failures(review_dir, gate_name)))
    if failures:
        stages.append(_failed_validation(review_dir, scripts, failures))
        return stages

    for idx, (gate_name, argv) in enumerate(gates[VALIDATION_GATES:], start=VALIDATION_GATES + 1):
        ok, out = run_gate(argv)
        append_log(review_dir, {
            "event": "gate_result", "gate": gate_name, "ok": ok,
            **({} if ok else {"summary": _summarize_failure(out)}),
        })
        if ok:
            stages.append(_passed(gate_name, idx, len(gates)))
            continue
        attempts = count_recent_failures(review_dir, gate_name)
        if gate_name == "check_review_run.py":
            stages.append(_failed_validation(
                review_dir, scripts, [(gate_name, out, attempts)],
            ))
            return stages
        stage = Stage(gate_name, f"品質ゲート {idx}/{len(gates)}: {gate_name}")
        stage.mark(False, "FAIL", next_note=(
            f"{out}\n\nこれは Agent が書いた JSON ではなく、ツールが生成する文書の検査です。"
            "入力の JSON（issues.json / results.json / claim_assessments.json）が原因でなければ、"
            "自己修正せず、この出力をそのままユーザーに報告してください。"
        ))
        stages.append(stage)
        return stages

    complete = Stage("complete", "完了")
    # final_review.md is authoritative; the HTML is a derived, easier-to-read
    # view regenerated from it every time. A failure here must not undo DONE
    # (all gates already passed) but must not be silent either.
    html_path = review_dir / "final_review.html"
    html_ok, html_out = run_gate([
        sys.executable, str(scripts / "render_review_html.py"),
        "--review", str(final_review), "--out", str(html_path),
    ])
    detail = f"final_review.md: {final_review}"
    if html_ok:
        detail += f"\n    閲覧用 HTML: {html_path}"
    else:
        detail += f"\n    閲覧用 HTML の生成に失敗（final_review.md は有効です）: {html_out}"
    complete.mark(True, detail)
    stages.append(complete)
    return stages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-dir", required=True, type=Path)
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR_DEFAULT)
    parser.add_argument("--mode", choices=("customer", "reporter", "both", "auto"), default="auto")
    args = parser.parse_args()

    review_io.mark_via_review_status()
    review_dir = args.review_dir.resolve()
    if not review_dir.exists() or not review_dir.is_dir():
        print(
            f"error: review directory not found: {args.review_dir} "
            f"(current directory: {Path.cwd()})",
            file=sys.stderr,
        )
        return 2

    mode = infer_mode(review_dir, args.mode)
    stages = check_pipeline(review_dir, args.skill_dir, mode)

    print(f"REVIEW STATUS: {review_dir} (mode={mode})")
    for stage in stages:
        print(stage.line())

    last = stages[-1]
    if last.ok and last.key == "complete":
        append_log(review_dir, {"event": "status", "stage": "complete", "ok": True})
        print("\nDONE: レビューは完了しています。final_review.md 以外の新規作業は不要です。")
        return 0

    append_log(review_dir, {"event": "status", "stage": last.key, "ok": False})
    print(f"\nNEXT STEP ({last.label}):")
    if last.next_command:
        print(last.next_command)
    if last.next_note:
        print(last.next_note)
    if not last.next_command and not last.next_note:
        print(last.detail)
    print(
        "\n※ 上の指示だけに従ってください。詰まっても、他のスクリプトを個別に実行したり、"
        "manifest やログ、生成済みの成果物を書き換えて先へ進めたりしません（それでは"
        "DONE になりません）。進めない場合は、状況をこの出力と一緒にユーザーに報告して"
        "止まってください。"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
