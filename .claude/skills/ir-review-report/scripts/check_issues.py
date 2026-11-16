#!/usr/bin/env python3
"""Validate review issues and generate the summary by code, not by LLM.

Every review finding must be a structured issue (see references/review_model.md)
with a category, severity, checklist IDs, verbatim quotes with locations, a
reason, and a suggested revision. This script:

  1. validates the issue schema — issues without a quote or location are
     rejected ("一般的に不足しています" 型の指摘を禁止)
  2. enforces severity policy — optional-item shortfalls (optional_enhancement)
     must be severity "low"; external_confirmation is never a quality defect
  3. assigns stable, content-derived issue IDs (ISS-<sha256[:8]>) and sorts
     issues deterministically so runs can be diffed (compare_runs.py)
  4. cross-checks issue.status against the checklist results verdicts
  5. requires every quality-defect checklist shortfall to have a structured
     issue (partial/not_met on mandatory/recommended/unspecified items must
     not disappear from the finding list)
  6. requires every unknown-verdict checklist item to have a structured
     external_confirmation issue (unknown verdicts must not disappear either —
     otherwise the summary can say "unknown: 11" and "external confirmation
     needed: 0" in the same document)
  7. emits the aggregate summary (counts, achievement, severity/category/
     section tallies, serious-findings headline) — the review document must
     copy these numbers verbatim; free-form totals are forbidden, so the
     summary can never contradict the issue list

Usage:
    python check_issues.py --issues <issues.json> --results <results.json>
        [--out <normalized-issues.json>] [--summary-out <summary.json>]
        [--markdown-out <summary.md>] [--mode customer|reporter|both|auto]
        [--meta key=value ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import review_io

CATEGORIES = {
    "evidence_integrity", "unsupported_claim", "certainty_inconsistency",
    "cross_section_inconsistency", "missing_required_item",
    "countermeasure_mapping", "format_or_usability", "external_confirmation",
    "optional_enhancement",
}
SEVERITIES = ["critical", "high", "medium", "low", "info"]
VERDICTS = {"met", "partial", "not_met", "unknown", "not_applicable"}
ISSUE_CLASSES = {"quality_defect", "external_confirmation", "optional_enhancement"}
# Serious-finding categories: their high/critical presence must be reflected
# in the headline (サマリーと個別指摘の矛盾禁止).
SERIOUS_CATEGORIES = {"unsupported_claim", "certainty_inconsistency"}
# Categories that are not quality defects by definition.
NON_DEFECT_CATEGORIES = {"external_confirmation", "optional_enhancement"}

# init_issues_skeleton.py leaves this marker in fields that need the Agent's
# judgment; an issue still containing it must never reach the final review.
SKELETON_PLACEHOLDER = "【要記入】"

REQUIRED_FIELDS = [
    "category", "severity", "checklist_ids", "reason", "suggested_revision",
]


def result_id(result: dict) -> str | None:
    return result.get("checklist_id") or result.get("id")


def issue_class(issue: dict) -> str:
    explicit = issue.get("issue_class")
    if explicit:
        return str(explicit)
    if issue.get("category") == "external_confirmation":
        return "external_confirmation"
    if issue.get("category") == "optional_enhancement":
        return "optional_enhancement"
    return "quality_defect"


def issue_status(issue: dict, results_by_id: dict[str, dict]) -> str | None:
    if issue.get("status") is not None:
        return issue.get("status")
    cids = issue.get("checklist_ids") or []
    verdicts = {
        (results_by_id.get(c) or {}).get("verdict")
        for c in cids
        if (results_by_id.get(c) or {}).get("verdict") is not None
    }
    if len(verdicts) == 1:
        return next(iter(verdicts))
    return None


def issue_location(issue: dict) -> str:
    if str(issue.get("primary_location", "")).strip():
        return str(issue["primary_location"]).strip()
    if issue.get("source_span_ids"):
        return ",".join(issue["source_span_ids"])
    if issue.get("absence_check_ids"):
        return ",".join(issue["absence_check_ids"])
    return ""


def issue_quotes(issue: dict) -> list[dict]:
    return issue.get("quotes") or issue.get("evidence_quotes") or []


def has_grounding(issue: dict) -> bool:
    return bool(issue_quotes(issue) or issue.get("source_span_ids") or issue.get("absence_check_ids"))


def stable_issue_id(issue: dict) -> str:
    seed = "|".join([
        issue.get("category", ""),
        ",".join(sorted(issue.get("checklist_ids", []))),
        issue_location(issue),
        str((issue_quotes(issue) or [{}])[0].get("text", ""))[:120],
        ",".join(issue.get("assessment_ids") or []),
        ",".join(issue.get("recommendation_ids") or []),
    ])
    return "ISS-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]


def load_checklist_items(skill_dir: Path, mode: str) -> list[dict]:
    parser = skill_dir / "scripts" / "parse_checklists.py"
    out = subprocess.run(
        [
            sys.executable,
            str(parser),
            "--skill-dir",
            str(skill_dir),
            "--mode",
            mode,
        ],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print(out.stderr, file=sys.stderr)
        raise SystemExit(2)
    return json.loads(out.stdout)["items"]


def infer_mode(results: list[dict], requested: str) -> str:
    if requested != "auto":
        return requested
    ids = {
        result_id(r) for r in results
        if isinstance(r, dict) and result_id(r)
    }
    has_customer = any(str(i).startswith("CUS-") for i in ids)
    has_reporter = any(str(i).startswith("REP-") for i in ids)
    if has_customer and not has_reporter:
        return "customer"
    if has_reporter and not has_customer:
        return "reporter"
    return "both"


def _span_text(span: dict) -> str:
    return str(span.get("text") or "").strip()


def _is_non_substantive_span(span: dict) -> bool:
    """Return True for source spans that cannot support a review finding.

    Source spans are allowed to be broad paragraphs or tables, but page markers,
    distribution labels, and other boilerplate must not be used as the only
    grounding for a concrete issue. This keeps strict grounding from degrading
    into "attach any valid span ID".
    """
    text = _span_text(span)
    compact = re.sub(r"\s+", " ", text).strip()
    lower = compact.lower()
    if not compact:
        return True
    if re.fullmatch(r"=+\s*\[?\s*page\s+\d+\s*\]?\s*=+", lower):
        return True
    boilerplate_terms = (
        "confidential",
        "limited external distribution",
        "all rights reserved",
        "page ",
    )
    has_boilerplate = any(term in lower for term in boilerplate_terms)
    has_values = bool(span.get("values"))
    has_cjk = bool(re.search(r"[\u3040-\u30ff\u3400-\u9fff]", compact))
    has_sentence = bool(re.search(r"[。.!?]|です|ます|した|されています|確認", compact))
    if has_boilerplate and not has_values and not has_sentence:
        return True
    if len(compact) < 20 and not has_values and not has_cjk:
        return True
    return False


def validate(
    issues: list[dict],
    items: list[dict],
    results_by_id: dict[str, dict],
    *,
    source_spans: dict[str, dict] | None = None,
    absence_check_ids: set[str] | None = None,
    strict_grounding: bool = False,
) -> list[str]:
    problems: list[str] = []
    known_ids = {i["id"] for i in items}
    level_of = {i["id"]: i.get("level", "-") for i in items}
    quality_shortfall_ids = {
        cid for cid, result in results_by_id.items()
        if cid in known_ids
        and result.get("evaluation_scope") != "out_of_scope"
        and result.get("verdict") in ("partial", "not_met")
        and level_of.get(cid) in ("必須", "推奨", "-")
    }
    covered_quality_shortfalls: set[str] = set()
    # results.json の unknown 判定も、品質欠陥と同じく issues.json に必ず対応 issue を
    # 作る(category: external_confirmation)。ここが抜けると「unknown が N 件あるのに
    # 報告書外の確認が必要: 0件」という矛盾したサマリーが生成されてしまう。
    unknown_verdict_ids = {
        cid for cid, result in results_by_id.items()
        if cid in known_ids
        and result.get("evaluation_scope") != "out_of_scope"
        and result.get("verdict") == "unknown"
    }
    covered_external_confirmations: set[str] = set()

    for idx, issue in enumerate(issues):
        label = issue.get("issue_id") or f"<index {idx}>"
        missing = [f for f in REQUIRED_FIELDS if f not in issue]
        if missing:
            problems.append(f"{label}: missing fields {missing}")
            continue
        if issue["category"] not in CATEGORIES:
            problems.append(
                f"{label}: category {issue['category']!r} not in {sorted(CATEGORIES)}"
            )
        if SKELETON_PLACEHOLDER in json.dumps(issue, ensure_ascii=False):
            problems.append(
                f"{label}: still contains {SKELETON_PLACEHOLDER} — "
                "issues.json の雛形の未記入フィールド(category / reason / suggested_revision 等)を"
                "実際の内容に置き換えてください"
                f"(対象 checklist_ids: {issue.get('checklist_ids')})"
            )
        cls = issue_class(issue)
        if cls not in ISSUE_CLASSES:
            problems.append(f"{label}: issue_class {cls!r} invalid")
        if issue["severity"] not in SEVERITIES:
            problems.append(f"{label}: severity {issue['severity']!r} invalid")
        status = issue_status(issue, results_by_id)
        if status is not None and status not in VERDICTS:
            problems.append(f"{label}: status {status!r} invalid")

        quotes = issue_quotes(issue)
        if not has_grounding(issue):
            problems.append(
                f"{label}: quotes is empty / grounding is empty — 原文span、未記載確認、逐語引用の"
                "いずれかがない指摘は出力できない"
            )
        if strict_grounding and not (issue.get("source_span_ids") or issue.get("absence_check_ids")):
            problems.append(
                f"{label}: strict grounding requires source_span_ids or absence_check_ids"
            )
        if source_spans is not None:
            unknown_spans = [s for s in issue.get("source_span_ids", []) if s not in source_spans]
            if unknown_spans:
                problems.append(f"{label}: unknown source_span_ids {unknown_spans}")
            weak_spans = [
                s for s in issue.get("source_span_ids", [])
                if s in source_spans and _is_non_substantive_span(source_spans[s])
            ]
            if weak_spans:
                problems.append(
                    f"{label}: non-substantive source_span_ids {weak_spans} "
                    "cannot be used as issue grounding"
                )
        if absence_check_ids is not None:
            unknown_absence = [
                a for a in issue.get("absence_check_ids", []) if a not in absence_check_ids
            ]
            if unknown_absence:
                problems.append(f"{label}: unknown absence_check_ids {unknown_absence}")
        for q in quotes:
            if not str(q.get("location", "")).strip() or not str(q.get("text", "")).strip():
                problems.append(f"{label}: quote missing location or text")
        if not issue_location(issue):
            problems.append(f"{label}: primary_location is empty")
        if not str(issue.get("reason", "")).strip():
            problems.append(f"{label}: reason is empty")

        cids = issue.get("checklist_ids") or []
        if not cids and not (issue.get("assessment_ids") or issue.get("recommendation_ids")):
            problems.append(
                f"{label}: checklist_ids is empty and no assessment/recommendation reference exists"
            )
        unknown = [c for c in cids if c not in known_ids]
        if unknown:
            problems.append(f"{label}: unknown checklist ids {unknown}")

        # 任意項目の不足を high/critical にしない
        if cls == "optional_enhancement" and issue["severity"] != "low":
            problems.append(
                f"{label}: optional_enhancement must be severity 'low' "
                f"(got {issue['severity']!r}) — 任意項目の不足は重大な品質問題にしない"
            )
        if any(level_of.get(c) == "任意" for c in cids) and \
                issue["severity"] in ("high", "critical"):
            problems.append(
                f"{label}: severity {issue['severity']} on 任意 checklist item(s) "
                f"{[c for c in cids if level_of.get(c) == '任意']}"
            )
        if cls == "quality_defect" and issue.get("category") not in NON_DEFECT_CATEGORIES:
            covered_quality_shortfalls.update(c for c in cids if c in quality_shortfall_ids)
        # unknown 判定の項目に紐づく指摘は external_confirmation として分離する
        if status == "unknown" and cls != "external_confirmation":
            problems.append(
                f"{label}: status unknown must use category external_confirmation "
                "(報告書外の確認事項は品質欠陥と分離する)"
            )
        if cls == "external_confirmation":
            covered_external_confirmations.update(c for c in cids if c in unknown_verdict_ids)
        if issue.get("source_observation_ids") is not None and not isinstance(
            issue.get("source_observation_ids"), list
        ):
            problems.append(f"{label}: source_observation_ids must be a list")
        if issue.get("category") == "missing_required_item" and status == "not_met":
            if not issue.get("absence_check_ids"):
                problems.append(
                    f"{label}: missing_required_item with status not_met requires "
                    "absence_check_ids (未記載指摘は、無関係な本文spanではなく未記載確認に接地する)"
                )
        # status と results の verdict の整合(サマリーと個別指摘の矛盾防止)
        for c in cids:
            verdict = (results_by_id.get(c) or {}).get("verdict")
            if verdict and status and verdict != status:
                problems.append(
                    f"{label}: status {status!r} contradicts results "
                    f"verdict {verdict!r} for {c}"
                )
    missing_quality_issues = sorted(quality_shortfall_ids - covered_quality_shortfalls)
    if missing_quality_issues:
        problems.append(
            "missing quality-defect issues for checklist verdicts "
            f"{missing_quality_issues} — results.json の partial/not_met "
            "判定(必須/推奨/未分類)は、対応する quality_defect の issues.json "
            "項目として必ず記録してください"
        )
    missing_external_confirmation_issues = sorted(
        unknown_verdict_ids - covered_external_confirmations
    )
    if missing_external_confirmation_issues:
        problems.append(
            "missing external_confirmation issues for checklist verdicts "
            f"{missing_external_confirmation_issues} — results.json の unknown "
            "判定は、対応する external_confirmation の issues.json 項目として "
            "必ず記録してください(報告書外の確認事項サマリーが 0 件のまま矛盾しないように)"
        )
    return problems


def _achievement(results: list[dict], level_of: dict, level: str) -> dict:
    counter = Counter(
        r.get("verdict") for r in results
        if level_of.get(result_id(r)) == level
    )
    met = counter.get("met", 0)
    denom = met + counter.get("partial", 0) + counter.get("not_met", 0)
    return {
        "met": met, "denominator": denom,
        "rate": round(met / denom, 3) if denom else None,
        "unknown_excluded": counter.get("unknown", 0),
        "not_applicable_excluded": counter.get("not_applicable", 0),
    }


def _achievement_all(results: list[dict]) -> dict:
    counter = Counter(
        r.get("verdict") for r in results
        if r.get("evaluation_scope") != "out_of_scope"
    )
    met = counter.get("met", 0)
    denom = met + counter.get("partial", 0) + counter.get("not_met", 0)
    return {
        "met": met,
        "denominator": denom,
        "rate": round(met / denom, 3) if denom else None,
        "unknown_excluded": counter.get("unknown", 0),
        "not_applicable_excluded": counter.get("not_applicable", 0),
    }


def build_summary(issues: list[dict], results: list[dict],
                  items: list[dict], meta: dict) -> dict:
    level_of = {i["id"]: i.get("level", "-") for i in items}
    section_of = {i["id"]: i.get("section", "") for i in items}

    verdicts = Counter(r.get("verdict") for r in results)
    must_stats = _achievement(results, level_of, "必須")

    defects = [
        i for i in issues
        if issue_class(i) == "quality_defect"
        and i.get("category") not in NON_DEFECT_CATEGORIES
    ]
    serious = sorted(
        (
            {"issue_id": i.get("issue_id"), "category": i.get("category"),
             "severity": i.get("severity"), "reason": i.get("reason", ""),
             "primary_location": issue_location(i)}
            for i in issues
            if i.get("category") in SERIOUS_CATEGORIES
            and i.get("severity") in ("critical", "high")
        ),
        key=lambda x: (
            SEVERITIES.index(x["severity"]) if x["severity"] in SEVERITIES else 9,
            str(x["issue_id"]),
        ),
    )
    headline = (
        "重大な指摘あり(根拠なし断定・確度不整合): "
        + "; ".join(s["issue_id"] for s in serious)
        if serious else
        "重大な過大主張・根拠なし断定は検出されませんでした"
    )

    by_section: Counter = Counter()
    for i in defects:
        for c in i.get("checklist_ids", []):
            section = section_of.get(c, "").split(" › ")[0] or "その他"
            by_section[section] += 1

    return {
        "verdict_counts": {k: verdicts.get(k, 0) for k in sorted(VERDICTS)},
        "overall_achievement": _achievement_all(results),
        "must_achievement": must_stats,
        "recommended_achievement": _achievement(results, level_of, "推奨"),
        "optional_achievement": _achievement(results, level_of, "任意"),
        "optional_enhancement_ids": sorted(
            i["issue_id"] for i in issues
            if issue_class(i) == "optional_enhancement"
        ),
        "external_confirmation_ids": sorted(
            i["issue_id"] for i in issues
            if issue_class(i) == "external_confirmation"
        ),
        "issue_counts": {
            "total": len(issues),
            "quality_defects": len(defects),
            "by_severity": {
                s: sum(1 for i in defects if i.get("severity") == s)
                for s in SEVERITIES
            },
            "by_category": {
                c: sum(1 for i in issues if i.get("category") == c)
                for c in sorted(CATEGORIES)
                if any(i.get("category") == c for i in issues)
            },
            "by_section": dict(sorted(by_section.items())),
            "optional_enhancements": sum(
                1 for i in issues if issue_class(i) == "optional_enhancement"
            ),
            "external_confirmations": sum(
                1 for i in issues if issue_class(i) == "external_confirmation"
            ),
        },
        "serious_findings": serious,
        "headline": headline,
        "run_metadata": meta,
    }


def to_markdown(summary: dict) -> str:
    """Render the summary lines the review document must transcribe verbatim.

    Everything a reviewer might want to state as a number in the executive
    summary is generated here — the review document may not introduce counts
    or distributions of its own (check_review_doc.py enforces transcription).
    """
    must = summary["must_achievement"]
    overall = summary.get("overall_achievement", must)
    counts = summary["issue_counts"]
    vc = summary["verdict_counts"]

    def pct(stats: dict) -> str:
        return f"{stats['rate'] * 100:.0f}%" if stats["rate"] is not None else "n/a"

    def ids(key: str) -> str:
        listed = summary.get(key) or []
        return f"({', '.join(listed)})" if listed else ""

    lines = [
        "## サマリー(コード集計)",
        "",
        f"- 全チェック項目の判定分布: met {vc['met']} / partial {vc['partial']} / "
        f"not_met {vc['not_met']} / unknown {vc['unknown']} / "
        f"not_applicable {vc['not_applicable']}",
        f"- 達成率(全体): {overall['met']}/{overall['denominator']} "
        f"({pct(overall)})"
        f"(分母から unknown {overall['unknown_excluded']} 件・"
        f"not_applicable {overall['not_applicable_excluded']} 件を除外)",
        f"- 品質上の指摘: {counts['quality_defects']} 件"
        f"(critical {counts['by_severity']['critical']} / "
        f"high {counts['by_severity']['high']} / "
        f"medium {counts['by_severity']['medium']} / "
        f"low {counts['by_severity']['low']})",
        f"- 改善提案(任意項目): {counts['optional_enhancements']} 件"
        f"{ids('optional_enhancement_ids')}",
        f"- 報告書外の確認が必要: {counts['external_confirmations']} 件"
        f"(品質欠陥とは別扱い){ids('external_confirmation_ids')}",
        f"- {summary['headline']}",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    review_io.require_via_review_status("check_issues.py")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--issues", required=True, type=Path)
    ap.add_argument("--results", required=True, type=Path)
    ap.add_argument("--skill-dir", type=Path,
                    default=Path(__file__).resolve().parent.parent)
    ap.add_argument(
        "--mode",
        choices=("customer", "reporter", "both", "auto"),
        default="auto",
        help="Checklist set expected in results.json",
    )
    ap.add_argument("--out", type=Path, help="Write normalized issues JSON")
    ap.add_argument("--summary-out", type=Path, help="Write summary JSON")
    ap.add_argument("--markdown-out", type=Path, help="Write summary Markdown")
    ap.add_argument("--source-index", type=Path,
                    help="source_index.json; validates source_span_ids")
    ap.add_argument("--absence-checks", type=Path,
                    help="absence_checks.json; validates absence_check_ids")
    ap.add_argument("--strict-grounding", action="store_true",
                    help="Require source_span_ids or absence_check_ids for every issue")
    ap.add_argument("--meta", action="append", default=[],
                    help="Run metadata key=value (model, temperature, seed, ...)")
    args = ap.parse_args()

    issues_data = json.loads(args.issues.read_text(encoding="utf-8"))
    issues = issues_data.get("issues", issues_data if isinstance(issues_data, list) else [])
    results_data = json.loads(args.results.read_text(encoding="utf-8"))
    results = results_data.get("results", results_data if isinstance(results_data, list) else [])
    results_by_id = {
        result_id(r): r for r in results
        if isinstance(r, dict) and result_id(r)
    }
    mode = infer_mode(results, args.mode)
    items = load_checklist_items(args.skill_dir, mode)

    source_spans = None
    if args.source_index:
        source_data = json.loads(args.source_index.read_text(encoding="utf-8"))
        source_spans = {
            str(s.get("source_span_id") or s.get("span_id") or s.get("id")): s
            for s in source_data.get("spans", [])
            if isinstance(s, dict)
            and (s.get("source_span_id") or s.get("span_id") or s.get("id"))
        }
    absence_check_ids = None
    if args.absence_checks:
        absence_data = json.loads(args.absence_checks.read_text(encoding="utf-8"))
        absence_check_ids = {
            str(a.get("absence_check_id") or a.get("id"))
            for a in absence_data.get("absence_checks", [])
            if isinstance(a, dict)
        }

    problems = validate(
        issues,
        items,
        results_by_id,
        source_spans=source_spans,
        absence_check_ids=absence_check_ids,
        strict_grounding=args.strict_grounding,
    )

    # Stable IDs + deterministic order (reproducible diffs across runs).
    for issue in issues:
        issue["issue_id"] = stable_issue_id(issue)
    ids = Counter(i["issue_id"] for i in issues)
    for dup, n in ids.items():
        if n > 1:
            problems.append(f"{dup}: {n} issues normalize to the same id — merge them")
    issues.sort(key=lambda i: (
        SEVERITIES.index(i["severity"]) if i.get("severity") in SEVERITIES else 9,
        i.get("category", ""), issue_location(i), i["issue_id"],
    ))

    meta = {}
    for kv in args.meta:
        key, _, value = kv.partition("=")
        meta[key] = value
    summary = build_summary(issues, results, items, meta)

    print(json.dumps({
        "issues": len(issues),
        "problems": problems,
        "headline": summary["headline"],
    }, ensure_ascii=False, indent=2))
    if problems:
        return 1
    if args.out:
        review_io.atomic_write_json(args.out, {"issues": issues})
    if args.summary_out:
        review_io.atomic_write_json(args.summary_out, summary)
    if args.markdown_out:
        review_io.atomic_write_text(args.markdown_out, to_markdown(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
