#!/usr/bin/env python3
"""Deterministic checks over the extracted Claim-to-Evidence model.

The review skill extracts the report's material assertions as structured
claims (see references/review_model.md). This script machine-checks what does
not need judgment:

  problems:
    - schema violations (missing fields, duplicate claim_id, bad certainty)
    - claims citing evidence IDs that are not defined in the report
      (requires --evidence-json from check_evidence_ids.py)
    - "confirmed" findings with no supporting evidence IDs
  warnings (reviewer should look; not automatically defects):
    - certainty conflicts: same subject+predicate+object asserted with
      different certainty in different places (章・表・サマリー・付録間)
    - summary stronger than body: the executive-summary zone asserts a
      higher certainty than any body location for the same assertion
    - appendix-only assertions: a finding that exists only in appendix /
      ATT&CK / IoC zones with no body counterpart (根拠のない具体化の疑い —
      ATT&CK technique assignments need a corresponding body fact)
    - highly_likely/possible findings with no evidence IDs
    - recommendations/containment not linked to any finding

Certainty is normalized to five levels (§確度の正規化):
  confirmed / highly_likely / possible / unknown / negative
Legacy aliases are accepted: probable→highly_likely, not_observed→negative.
`classify_certainty()` maps Japanese report phrasing onto these levels and is
importable for reuse and unit tests.

Claims must never be invented from outside the report: every claim carries a
verbatim quote and its location; this script only cross-checks what the agent
extracted.

Usage:
    python check_claims.py --claims <claims.json>
        [--evidence-json <check_evidence_ids output>]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REQUIRED_FIELDS = [
    "claim_id", "location", "subject", "predicate", "object",
    "certainty", "evidence_ids", "quote", "claim_type",
]
CERTAINTY = {"confirmed", "highly_likely", "possible", "unknown", "negative"}
CERTAINTY_ALIASES = {"probable": "highly_likely", "not_observed": "negative"}
# Strength ranking for "stronger than" comparisons. negative is a distinct
# polarity, not a strength level; conflicts involving it are always flagged.
STRENGTH = {"unknown": 0, "possible": 1, "highly_likely": 2, "confirmed": 3}

CLAIM_TYPES = {
    "finding", "limitation", "recommendation", "containment",
    "attribution", "context",
}
ZONES = {
    "summary", "body", "table", "timeline", "ioc", "attack_mapping", "appendix",
}
_APPENDIX_ZONES = {"appendix", "attack_mapping", "ioc"}

# Ordered: earlier patterns win (negative/unknown before confirmed, since
# 「確認されなかった」「確認できない」 contain 「確認」).
_CERTAINTY_PATTERNS: list[tuple[str, str]] = [
    ("negative",
     r"確認されなかった|確認されませんでした|痕跡は(?:確認され)?なかった|"
     r"検出されなかった|存在しなかった"),
    ("unknown",
     r"確認できな|断定できな|特定できな|判断できな|不明|確認できていな"),
    ("highly_likely",
     r"可能性が(?:極めて|非常に)?高い|強く疑われ|ほぼ確実"),
    ("possible",
     r"可能性がある|可能性があります|疑いがある|疑われる|示唆され|"
     r"とみられ|と考えられ|おそれがある"),
    ("confirmed",
     r"確認した|確認され|特定した|特定され|実行された|使用された|"
     r"判明した|記録され|検出された"),
]


def classify_certainty(text: str) -> str:
    """Map report phrasing to a normalized certainty level."""
    for level, pattern in _CERTAINTY_PATTERNS:
        if re.search(pattern, text):
            return level
    return "unknown"


def normalize_certainty(value: str) -> str:
    return CERTAINTY_ALIASES.get(value, value)


def derive_zone(location: dict) -> str:
    """Derive the document zone from a claim location (explicit zone wins)."""
    zone = location.get("zone")
    if zone in ZONES:
        return zone
    section = str(location.get("section", ""))
    if re.search(r"ATT&CK|attack", section, re.IGNORECASE):
        return "attack_mapping"
    if re.search(r"IoC|IOC|侵害指標", section):
        return "ioc"
    if re.search(r"付録|別紙|appendix", section, re.IGNORECASE):
        return "appendix"
    if re.search(r"タイムライン|timeline", section, re.IGNORECASE):
        return "timeline"
    if re.search(r"エグゼクティブ|サマリー|summary|概要", section, re.IGNORECASE):
        return "summary"
    if location.get("table"):
        return "table"
    return "body"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--claims", required=True, type=Path)
    ap.add_argument("--evidence-json", type=Path,
                    help="Output of check_evidence_ids.py for defined-ID cross-check")
    args = ap.parse_args()
    if not args.claims.exists():
        print(f"error: claims file not found: {args.claims}", file=sys.stderr)
        return 2

    data = json.loads(args.claims.read_text(encoding="utf-8"))
    claims = data.get("claims", data if isinstance(data, list) else [])

    defined_ids: set[str] | None = None
    if args.evidence_json:
        ev = json.loads(args.evidence_json.read_text(encoding="utf-8"))
        defined_ids = set(ev.get("defined_ids", []))

    problems: list[str] = []
    warnings: list[str] = []
    seen_ids: set[str] = set()
    declared_ids = {
        str(claim.get("claim_id"))
        for claim in claims
        if isinstance(claim, dict) and str(claim.get("claim_id", "")).strip()
    }

    for idx, claim in enumerate(claims):
        cid = claim.get("claim_id", f"<index {idx}>")
        missing = [f for f in REQUIRED_FIELDS if f not in claim]
        if missing:
            problems.append(f"{cid}: missing fields {missing}")
            continue
        if cid in seen_ids:
            problems.append(f"{cid}: duplicate claim_id")
        seen_ids.add(cid)

        claim["certainty"] = normalize_certainty(claim["certainty"])
        if claim["certainty"] not in CERTAINTY:
            problems.append(
                f"{cid}: certainty {claim['certainty']!r} not in {sorted(CERTAINTY)}"
            )
        if claim["claim_type"] not in CLAIM_TYPES:
            problems.append(
                f"{cid}: claim_type {claim['claim_type']!r} invalid "
                f"(allowed: {sorted(CLAIM_TYPES)})"
            )
        if not str(claim.get("quote", "")).strip():
            problems.append(f"{cid}: empty quote — claims must cite the report verbatim")

        related = claim.get("related_claim_ids") or []
        bad_related = [r for r in related if r not in declared_ids]
        if bad_related:
            problems.append(
                f"{cid}: related_claim_ids not found in claims: {bad_related}"
            )

        ev_ids = claim.get("evidence_ids") or []
        if defined_ids is not None:
            unknown_refs = [e for e in ev_ids if e not in defined_ids]
            if unknown_refs:
                problems.append(
                    f"{cid}: cites evidence not defined in the report: {unknown_refs}"
                )

        if claim["claim_type"] == "finding":
            if claim["certainty"] == "confirmed" and not ev_ids:
                problems.append(
                    f"{cid}: confirmed finding without supporting evidence_ids "
                    f"(quote: {str(claim['quote'])[:60]!r})"
                )
            elif claim["certainty"] in ("highly_likely", "possible") and not ev_ids:
                warnings.append(
                    f"{cid}: {claim['certainty']} finding without evidence_ids — "
                    "verify the report states its basis or limitation"
                )
        if claim["claim_type"] in ("recommendation", "containment"):
            if not ev_ids and not claim.get("related_claim_ids"):
                warnings.append(
                    f"{cid}: {claim['claim_type']} not linked to any finding/evidence "
                    "(調査結果と対策の対応を確認)"
                )

    # --- Cross-section analysis per assertion --------------------------------
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for claim in claims:
        if not all(f in claim for f in ("subject", "object", "certainty")):
            continue
        key = (
            str(claim["subject"]).strip().lower(),
            str(claim.get("predicate", "")).strip().lower(),
            str(claim["object"]).strip().lower(),
        )
        grouped[key].append(claim)

    conflicts = []
    for key, group in grouped.items():
        label = " / ".join(key)
        locs = [
            f'{c.get("claim_id")}@{(c.get("location") or {}).get("section", "?")}'
            f'[{c["certainty"]}]'
            for c in group
        ]
        certs = {c["certainty"] for c in group}
        if len(certs) > 1:
            conflicts.append({
                "assertion": label,
                "certainties": sorted(certs),
                "claims": locs,
            })
            warnings.append(
                f"certainty conflict on '{label}': {sorted(certs)} at {locs}"
            )

        zones = {derive_zone(c.get("location") or {}) for c in group}
        strengths_by_zone: dict[str, int] = defaultdict(int)
        for c in group:
            zone = derive_zone(c.get("location") or {})
            strengths_by_zone[zone] = max(
                strengths_by_zone[zone], STRENGTH.get(c["certainty"], 0)
            )
        body_zones = zones - _APPENDIX_ZONES - {"summary"}
        body_max = max(
            (strengths_by_zone[z] for z in body_zones), default=None
        )
        if "summary" in zones and body_max is not None:
            if strengths_by_zone["summary"] > body_max:
                warnings.append(
                    f"summary stronger than body on '{label}': "
                    f"エグゼクティブサマリーが詳細章より強い確度で記載 ({locs})"
                )
        finding_like = any(
            c.get("claim_type") in ("finding", "attribution") for c in group
        )
        if finding_like and zones and zones <= _APPENDIX_ZONES:
            warnings.append(
                f"appendix-only assertion '{label}': 本文に対応する記載がない "
                f"(付録/ATT&CK/IoC のみ; 根拠のない具体化の疑い) ({locs})"
            )
        # A material finding that lives only in the executive summary, with no
        # detailed-chapter / table / appendix counterpart, cannot be traced to
        # its basis — the executive summary should summarize the body, not
        # introduce claims of its own.
        if finding_like and zones == {"summary"}:
            warnings.append(
                f"summary-only assertion '{label}': エグゼクティブサマリーにのみ記載され、"
                f"本文・表・付録に対応する所見がない (要約が新規主張を導入している) ({locs})"
            )

    result = {
        "claims": len(claims),
        "problems": problems,
        "warnings": sorted(warnings),
        "certainty_conflicts": sorted(conflicts, key=lambda c: c["assertion"]),
        "summary": {
            "problem_count": len(problems),
            "warning_count": len(warnings),
        },
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
