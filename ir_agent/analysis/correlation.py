"""Correlation hint generation for the upstream analysis layer.

Implements the ``build-correlation-hints`` step: derives mechanical
correlation candidates from approved evidence and grounded field values.
Hints are material for the LLM correlation step and human reviewers,
never conclusions, and never require semantic understanding of the
evidence text.

Hint types (spec section 4.2):
- shared_entity: the same grounded value (IP, user, host, path, hash,
  domain, including derived values) appears in multiple evidence items.
  Value identity is the signal; no time window is applied.
- time_proximity: evidence sharing a host or account occurs within a
  configurable time window.
- same_attack_mapping: multiple evidence items carry the same ATT&CK
  technique candidate.
- same_artifact_context: evidence items originate from the same artifact.

Scale: values are put into an inverted index so only evidence sharing a
value is compared (near-linear); time proximity uses per-host/per-account
sorted sliding windows. No all-pairs comparison.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Optional
from uuid import uuid4

from ir_agent.analysis.coverage import infer_data_source_type
from ir_agent.analysis.field_grounding import normalize_timestamp
from ir_agent.models.correlation import CorrelationHint, FieldGroundingRecord
from ir_agent.models.evidence import EvidenceLedgerEntry


# Fields whose grounded values are entity-like and eligible for
# shared_entity hints. Derived fields (any name) are also eligible when the
# value shape is entity-like, which is ensured at extraction time.
_ENTITY_FIXED_FIELDS = {
    "host",
    "user",
    "src_ip",
    "dst_ip",
    "file_path",
    "registry_key",
    "url",
    "domain",
    "hash",
    "process_name",
}

# Values too generic to correlate on.
_TRIVIAL_VALUES = {
    "-",
    "0.0.0.0",
    "127.0.0.1",
    "::1",
    "localhost",
    "unknown",
    "n/a",
    "none",
    "null",
    "true",
    "false",
    "success",
    "failure",
}

DEFAULT_CONFIG: dict = {
    # Time windows in minutes (spec section 4.2); manifest can override.
    "same_host_user_minutes": 30,
    "process_network_minutes": 15,
    "post_logon_minutes": 60,
    "max_hints_per_evidence": 10,
}


class CorrelationHintBuilder:
    """Builds correlation hints from grounded values, never evidence semantics."""

    def __init__(self, config: Optional[dict] = None) -> None:
        self._config = {**DEFAULT_CONFIG, **(config or {})}

    def build_hints(
        self,
        ledger: list[EvidenceLedgerEntry],
        groundings: list[FieldGroundingRecord],
        attack_mappings: Optional[list[dict]] = None,
    ) -> list[CorrelationHint]:
        """Build all hint types and cap per-evidence hint counts.

        Args:
            ledger: Active (non-withdrawn) evidence ledger entries.
            groundings: Field grounding records for those entries.
            attack_mappings: Records with ``evidence_id`` and ``technique_id``
                keys (from attack_mappings.jsonl), optional.
        """
        active = [e for e in ledger if not e.withdrawn]
        by_id = {e.evidence_id: e for e in active}

        usable = [
            g for g in groundings
            if g.evidence_id in by_id
            and g.status in ("grounded", "partially_grounded")
            and g.normalized_value
            and g.normalized_value.lower() not in _TRIVIAL_VALUES
        ]

        hints: list[CorrelationHint] = []
        hints.extend(self._shared_entity_hints(by_id, usable))
        hints.extend(self._time_proximity_hints(by_id, usable))
        hints.extend(self._attack_mapping_hints(by_id, attack_mappings or []))
        hints.extend(self._artifact_context_hints(active))

        return self._cap_hints(hints)

    # --- shared_entity ---

    def _shared_entity_hints(
        self,
        by_id: dict[str, EvidenceLedgerEntry],
        groundings: list[FieldGroundingRecord],
    ) -> list[CorrelationHint]:
        # Inverted index: normalized value -> {evidence_id: (field, status)}
        index: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)
        for g in groundings:
            if g.kind == "fixed" and g.field not in _ENTITY_FIXED_FIELDS:
                continue
            if g.field == "timestamp":
                continue
            existing = index[g.normalized_value].get(g.evidence_id)
            # Keep the fully-grounded record when both statuses exist.
            if existing is None or (
                existing[1] != "grounded" and g.status == "grounded"
            ):
                index[g.normalized_value][g.evidence_id] = (g.field, g.status)

        hints: list[CorrelationHint] = []
        for value, members in index.items():
            if len(members) < 2:
                continue
            evidence_ids = sorted(members.keys())
            fields = sorted({field for field, _ in members.values()})
            has_partial = any(
                status != "grounded" for _, status in members.values()
            )

            source_files: set[str] = set()
            hosts: set[str] = set()
            ds_types: set[str] = set()
            for eid in evidence_ids:
                entry = by_id[eid]
                host = str((entry.observed_event or {}).get("host") or "")
                if host:
                    hosts.add(host.lower())
                for ref in entry.source_refs or []:
                    source_files.add(ref.source_file_id)
                    ds_types.add(infer_data_source_type(ref.source_path))

            # Same-value repetition inside one artifact is weak evidence of
            # correlation; cross-artifact / cross-host matches are strong.
            score = 0.6
            if len(source_files) >= 2:
                score += 0.2
            if len(hosts) >= 2 or len(ds_types) >= 2:
                score += 0.1
            if has_partial:
                score -= 0.2
            score = max(0.0, min(1.0, score))

            hints.append(
                CorrelationHint(
                    hint_id=f"HINT-{uuid4().hex[:8]}",
                    hint_type="shared_entity",
                    evidence_ids=evidence_ids,
                    fields=fields,
                    values=[value],
                    score=round(score, 2),
                    reason=(
                        f"複数証拠で同一値 '{value}' が観測されました"
                        f"（フィールド: {', '.join(fields)}）"
                    ),
                )
            )
        return hints

    # --- time_proximity ---

    def _time_proximity_hints(
        self,
        by_id: dict[str, EvidenceLedgerEntry],
        groundings: list[FieldGroundingRecord],
    ) -> list[CorrelationHint]:
        # Only timestamps that were grounded may anchor proximity hints.
        grounded_ts: dict[str, datetime] = {}
        for g in groundings:
            if g.field != "timestamp" or g.kind != "fixed":
                continue
            norm = normalize_timestamp(g.value)
            if not norm or not norm.endswith("Z"):
                continue
            try:
                grounded_ts[g.evidence_id] = datetime.strptime(
                    norm, "%Y-%m-%dT%H:%M:%SZ"
                )
            except ValueError:
                continue

        def observed(eid: str, key: str) -> str:
            return str((by_id[eid].observed_event or {}).get(key) or "").lower()

        # Group evidence by shared host and shared user.
        groups: dict[tuple[str, str], list[str]] = defaultdict(list)
        for eid in grounded_ts:
            host = observed(eid, "host")
            user = observed(eid, "user")
            if host:
                groups[("host", host)].append(eid)
            if user:
                groups[("user", user)].append(eid)

        hints: list[CorrelationHint] = []
        seen_pairs: set[tuple[str, str]] = set()
        for (dim, shared_value), eids in groups.items():
            if len(eids) < 2:
                continue
            eids_sorted = sorted(eids, key=lambda e: grounded_ts[e])
            for a, b in zip(eids_sorted, eids_sorted[1:]):
                pair = tuple(sorted((a, b)))
                if pair in seen_pairs:
                    continue
                window = self._window_minutes(by_id, a, b)
                delta = abs(
                    (grounded_ts[b] - grounded_ts[a]).total_seconds()
                ) / 60.0
                if delta > window:
                    continue
                seen_pairs.add(pair)
                label = "ホスト" if dim == "host" else "アカウント"
                hints.append(
                    CorrelationHint(
                        hint_id=f"HINT-{uuid4().hex[:8]}",
                        hint_type="time_proximity",
                        evidence_ids=list(pair),
                        fields=[dim, "timestamp"],
                        values=[shared_value],
                        score=0.6,
                        reason=(
                            f"同一{label} '{shared_value}' の証拠が "
                            f"{int(delta)}分以内に近接しています"
                            f"（窓: {int(window)}分）"
                        ),
                    )
                )
        return hints

    def _window_minutes(
        self, by_id: dict[str, EvidenceLedgerEntry], a: str, b: str
    ) -> float:
        """Pick the applicable time window for an evidence pair."""

        def observed(eid: str, key: str) -> str:
            return str((by_id[eid].observed_event or {}).get(key) or "").lower()

        # Logon-followed-by-activity gets the widest window.
        for eid in (a, b):
            event_type = observed(eid, "event_type")
            if any(k in event_type for k in ("logon", "login", "4624")):
                return float(self._config["post_logon_minutes"])

        # Process execution paired with network communication.
        def has_process(eid: str) -> bool:
            return bool(observed(eid, "process_name") or observed(eid, "command_line"))

        def has_network(eid: str) -> bool:
            return bool(observed(eid, "dst_ip") or observed(eid, "src_ip"))

        if (has_process(a) and has_network(b)) or (has_process(b) and has_network(a)):
            return float(self._config["process_network_minutes"])

        return float(self._config["same_host_user_minutes"])

    # --- same_attack_mapping ---

    def _attack_mapping_hints(
        self,
        by_id: dict[str, EvidenceLedgerEntry],
        attack_mappings: list[dict],
    ) -> list[CorrelationHint]:
        technique_index: dict[str, set[str]] = defaultdict(set)
        technique_names: dict[str, str] = {}

        for record in attack_mappings:
            eid = record.get("evidence_id")
            tid = record.get("technique_id")
            if eid in by_id and tid:
                technique_index[tid].add(eid)
                technique_names.setdefault(
                    tid, record.get("technique_name") or ""
                )
        for entry in by_id.values():
            for mapping in entry.attack_mapping_candidates or []:
                technique_index[mapping.technique_id].add(entry.evidence_id)
                technique_names.setdefault(
                    mapping.technique_id, mapping.technique_name
                )

        hints: list[CorrelationHint] = []
        for tid, eids in technique_index.items():
            if len(eids) < 2:
                continue
            name = technique_names.get(tid, "")
            hints.append(
                CorrelationHint(
                    hint_id=f"HINT-{uuid4().hex[:8]}",
                    hint_type="same_attack_mapping",
                    evidence_ids=sorted(eids),
                    fields=["technique_id"],
                    values=[tid],
                    score=0.5,
                    reason=(
                        f"複数証拠が同一 ATT&CK 候補 {tid}"
                        f"{f'（{name}）' if name else ''} を持ちます"
                    ),
                )
            )
        return hints

    # --- same_artifact_context ---

    def _artifact_context_hints(
        self, active: list[EvidenceLedgerEntry]
    ) -> list[CorrelationHint]:
        by_artifact: dict[str, set[str]] = defaultdict(set)
        paths: dict[str, str] = {}
        for entry in active:
            for ref in entry.source_refs or []:
                by_artifact[ref.source_file_id].add(entry.evidence_id)
                paths.setdefault(ref.source_file_id, ref.source_path)

        hints: list[CorrelationHint] = []
        for file_id, eids in by_artifact.items():
            if len(eids) < 2:
                continue
            hints.append(
                CorrelationHint(
                    hint_id=f"HINT-{uuid4().hex[:8]}",
                    hint_type="same_artifact_context",
                    evidence_ids=sorted(eids),
                    fields=["source_file_id"],
                    values=[paths.get(file_id, file_id)],
                    score=0.4,
                    reason=(
                        f"同一アーティファクト '{paths.get(file_id, file_id)}' "
                        "上で観測された証拠群です"
                    ),
                )
            )
        return hints

    # --- capping ---

    def _cap_hints(self, hints: list[CorrelationHint]) -> list[CorrelationHint]:
        """Keep at most N hints per evidence id, preferring higher scores."""
        limit = int(self._config["max_hints_per_evidence"])
        budgets: dict[str, int] = defaultdict(lambda: limit)
        kept: list[CorrelationHint] = []
        for hint in sorted(hints, key=lambda h: h.score, reverse=True):
            if all(budgets[eid] > 0 for eid in hint.evidence_ids):
                kept.append(hint)
                for eid in hint.evidence_ids:
                    budgets[eid] -= 1
        # Preserve deterministic ordering by type then score.
        kept.sort(key=lambda h: (h.hint_type, -h.score, h.evidence_ids))
        return kept
