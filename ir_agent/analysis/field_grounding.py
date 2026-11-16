"""Field grounding verification for the upstream analysis layer.

Implements the ``ground-evidence-fields`` step: verifies that the values the
LLM recorded in ``observed_event`` (timestamp, host, IPs, user, paths, ...)
actually appear in the evidence excerpts or artifact inventory, and extracts
derived entity values (``key=value`` pairs, IPs, hashes, Windows paths) from
``raw_summary`` and excerpts so they become comparable during correlation.

Normalization is used ONLY for comparison; original evidence text is never
modified. No case-specific field names, IPs, or hostnames are special-cased.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from ir_agent.models.correlation import (
    GROUNDING_TARGET_FIELDS,
    FieldGroundingRecord,
)
from ir_agent.models.evidence import EvidenceLedgerEntry


# --- Normalization helpers (comparison only; originals are preserved) ---

_DEFANG_DOT = re.compile(r"\[\.\]|\(\.\)|\{\.\}")

_IP_RE = re.compile(
    r"\b\d{1,3}(?:(?:\[\.\]|\(\.\)|\.)\d{1,3}){3}\b"
)
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b")
_KV_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_.-]{1,40})=(\"[^\"]{1,200}\"|'[^']{1,200}'|[^\s,;\"']{1,200})"
)
_WIN_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|]{2,260}")

# Timestamp formats commonly present in mixed-source IR artifacts.
_TZ_ABBREVIATIONS: dict[str, int] = {
    "JST": 9 * 60,
    "UTC": 0,
    "GMT": 0,
}

_TS_PATTERNS = [
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
]


def defang(value: str) -> str:
    """Return the value with defanged separators restored (comparison only)."""
    return _DEFANG_DOT.sub(".", value or "")


def normalize_timestamp(value: str) -> Optional[str]:
    """Normalize a timestamp string to UTC ISO 8601, or None if unparseable.

    Handles ISO 8601 with offsets, ``JST``/``UTC`` timezone abbreviations,
    and naive timestamps (kept as-is, marked with no offset applied).
    """
    if not value:
        return None
    text = str(value).strip()

    # Trailing timezone abbreviation, e.g. "2025-05-10 02:14:08 JST"
    offset_minutes: Optional[int] = None
    m = re.search(r"\s([A-Z]{3,4})$", text)
    if m and m.group(1) in _TZ_ABBREVIATIONS:
        offset_minutes = _TZ_ABBREVIATIONS[m.group(1)]
        text = text[: m.start()].strip()

    # Zulu suffix
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    for pattern in _TS_PATTERNS:
        try:
            dt = datetime.strptime(text, pattern)
        except ValueError:
            continue
        if dt.tzinfo is None:
            if offset_minutes is not None:
                from datetime import timedelta, timezone as tz

                dt = dt.replace(tzinfo=tz(timedelta(minutes=offset_minutes)))
            else:
                # Naive timestamp: comparable only against other naive values.
                return dt.strftime("%Y-%m-%dT%H:%M:%S")
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def normalize_path(value: str) -> str:
    """Normalize a filesystem path for comparison (separators + case)."""
    return (value or "").replace("\\", "/").lower().strip('"')


def looks_like_ip(value: str) -> bool:
    return bool(_IP_RE.fullmatch((value or "").strip()))


def normalize_value(field: str, value: str) -> Optional[str]:
    """Normalize a field value for comparison based on the field semantics."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if field == "timestamp":
        return normalize_timestamp(text) or text
    if field.endswith("ip") or looks_like_ip(text):
        return defang(text).lower()
    if field in ("file_path", "registry_key", "process_name", "command_line"):
        return normalize_path(text)
    if field in ("host", "user", "domain", "url"):
        return defang(text).lower()
    if field == "hash":
        return text.lower()
    return defang(text).lower()


def _normalize_freeform(text: str) -> str:
    """Normalize free text for containment comparison."""
    return normalize_path(defang(text or ""))


class FieldGroundingService:
    """Grounds observed_event fields against excerpts and artifact inventory.

    ``file_inventory`` records (keyed by ``file_id``) provide the
    authoritative ``host`` values for artifacts (spec section 4.1).
    """

    def __init__(self, file_inventory: Optional[list[dict]] = None) -> None:
        self._inventory_by_file_id: dict[str, dict] = {
            rec.get("file_id"): rec
            for rec in (file_inventory or [])
            if rec.get("file_id")
        }

    def ground_ledger(
        self, entries: list[EvidenceLedgerEntry]
    ) -> list[FieldGroundingRecord]:
        """Ground all active ledger entries."""
        records: list[FieldGroundingRecord] = []
        for entry in entries:
            if entry.withdrawn:
                continue
            records.extend(self.ground_entry(entry))
        return records

    def ground_entry(
        self, entry: EvidenceLedgerEntry
    ) -> list[FieldGroundingRecord]:
        """Ground one evidence entry's fixed fields and derived values."""
        now = datetime.now(timezone.utc).isoformat()
        records: list[FieldGroundingRecord] = []
        observed = entry.observed_event or {}

        for field in GROUNDING_TARGET_FIELDS:
            value = observed.get(field)
            records.append(self._ground_fixed_field(entry, field, value, now))

        records.extend(self._extract_derived_values(entry, now))
        return records

    # --- Fixed-field grounding ---

    def _ground_fixed_field(
        self,
        entry: EvidenceLedgerEntry,
        field: str,
        value,
        created_at: str,
    ) -> FieldGroundingRecord:
        base = dict(
            grounding_id=f"GRD-{uuid4().hex[:8]}",
            evidence_id=entry.evidence_id,
            candidate_id=(entry.promoted_from[0] if entry.promoted_from else None),
            field=field,
            kind="fixed",
            created_at=created_at,
        )

        if value is None or str(value).strip() == "":
            return FieldGroundingRecord(
                **base,
                value="",
                normalized_value=None,
                status="not_applicable",
                reason="フィールドが空のため検証対象外です",
            )

        text = str(value)
        normalized = normalize_value(field, text)

        # 1. Exact match in an excerpt
        match = self._find_in_excerpts(entry, text)
        if match is not None:
            source_ref_id, lines = match
            return FieldGroundingRecord(
                **base,
                value=text,
                normalized_value=normalized,
                status="grounded",
                matched_in="excerpt",
                source_ref_id=source_ref_id,
                source_lines=lines,
                reason="excerpt に同一表記の値が存在します",
            )

        # 2. Normalized match in an excerpt (defang / path / case / time)
        match = self._find_normalized_in_excerpts(entry, field, text, normalized)
        if match is not None:
            source_ref_id, lines = match
            return FieldGroundingRecord(
                **base,
                value=text,
                normalized_value=normalized,
                status="partially_grounded",
                matched_in="excerpt",
                source_ref_id=source_ref_id,
                source_lines=lines,
                reason="表記差異はありますが、正規化比較で excerpt 内の値と一致します",
            )

        # 3. Host authority from file_inventory
        if field == "host" and self._host_in_inventory(entry, text):
            return FieldGroundingRecord(
                **base,
                value=text,
                normalized_value=normalized,
                status="grounded",
                matched_in="file_inventory",
                reason="file_inventory の host 権威情報と一致します",
            )

        return FieldGroundingRecord(
            **base,
            value=text,
            normalized_value=normalized,
            status="not_grounded",
            reason="値が抜粋・アーティファクト情報に確認できません",
        )

    def _find_in_excerpts(
        self, entry: EvidenceLedgerEntry, needle: str
    ) -> Optional[tuple[str, list[int]]]:
        for ref in entry.source_refs or []:
            excerpt = ref.excerpt or ""
            if needle in excerpt:
                return (ref.source_ref_id, self._matched_lines(ref, needle))
        return None

    def _find_normalized_in_excerpts(
        self,
        entry: EvidenceLedgerEntry,
        field: str,
        original: str,
        normalized: Optional[str],
    ) -> Optional[tuple[str, list[int]]]:
        if not normalized:
            return None
        for ref in entry.source_refs or []:
            excerpt = ref.excerpt or ""
            norm_excerpt = _normalize_freeform(excerpt)
            if field == "timestamp":
                for ts in self._extract_timestamps(excerpt):
                    if normalize_timestamp(ts) == normalized:
                        return (ref.source_ref_id, self._matched_lines(ref, ts))
                # Also allow the naive local-time portion to match.
                naive = original.split("+")[0].replace("T", " ").strip()
                if naive and naive in excerpt:
                    return (ref.source_ref_id, self._matched_lines(ref, naive))
                continue
            if normalized in norm_excerpt:
                return (ref.source_ref_id, None)
        return None

    @staticmethod
    def _extract_timestamps(text: str) -> list[str]:
        pattern = re.compile(
            r"\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}"
            r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}|\s[A-Z]{3,4})?"
        )
        return pattern.findall(text or "")

    @staticmethod
    def _matched_lines(ref, needle: str) -> Optional[list[int]]:
        """Return absolute source line numbers of excerpt lines containing needle."""
        excerpt = ref.excerpt or ""
        try:
            start_line = int(ref.source_lines[0])
        except (TypeError, IndexError, ValueError):
            return None
        lines = [
            start_line + i
            for i, line in enumerate(excerpt.splitlines())
            if needle in line
        ]
        return lines or None

    def _host_in_inventory(self, entry: EvidenceLedgerEntry, host: str) -> bool:
        target = (host or "").strip().lower()
        for ref in entry.source_refs or []:
            record = self._inventory_by_file_id.get(ref.source_file_id)
            if record and str(record.get("host", "")).strip().lower() == target:
                return True
        return False

    # --- Derived entity value extraction (spec section 4.1) ---

    def _extract_derived_values(
        self, entry: EvidenceLedgerEntry, created_at: str
    ) -> list[FieldGroundingRecord]:
        """Extract key=value / IP / hash / Windows-path values from raw_summary
        and excerpts so non-fixed-field values participate in correlation.
        """
        observed = entry.observed_event or {}
        raw_summary = str(observed.get("raw_summary") or "")
        excerpt_texts = [
            (ref.source_ref_id, ref, ref.excerpt or "")
            for ref in (entry.source_refs or [])
        ]

        fixed_normalized: set[str] = set()
        for field in GROUNDING_TARGET_FIELDS:
            norm = normalize_value(field, str(observed.get(field) or ""))
            if norm:
                fixed_normalized.add(norm)

        derived: dict[tuple[str, str], FieldGroundingRecord] = {}

        def add(field: str, value: str, matched_in: str,
                source_ref_id: Optional[str], lines: Optional[list[int]],
                grounded_in_excerpt: bool) -> None:
            value = value.strip().strip('"').strip("'")
            if len(value) < 3:
                return
            norm = normalize_value(field, value)
            if not norm or norm in fixed_normalized:
                return
            key = (field, norm)
            existing = derived.get(key)
            # Prefer an excerpt-grounded record over a raw_summary-only one.
            if existing is not None and existing.status == "grounded":
                return
            derived[key] = FieldGroundingRecord(
                grounding_id=f"GRD-{uuid4().hex[:8]}",
                evidence_id=entry.evidence_id,
                candidate_id=(
                    entry.promoted_from[0] if entry.promoted_from else None
                ),
                field=field,
                value=value,
                normalized_value=norm,
                kind="derived",
                status="grounded" if grounded_in_excerpt else "not_grounded",
                matched_in=matched_in if grounded_in_excerpt else None,
                source_ref_id=source_ref_id,
                source_lines=lines,
                reason=(
                    "excerpt から抽出した派生値です"
                    if grounded_in_excerpt
                    else "raw_summary のみに存在し、excerpt では確認できません"
                ),
                created_at=created_at,
            )

        def scan(text: str, matched_in: str, source_ref_id, ref) -> None:
            grounded = matched_in == "excerpt"
            for m in _KV_RE.finditer(text):
                key_name, raw_value = m.group(1), m.group(2)
                lines = self._matched_lines(ref, raw_value) if ref else None
                add(key_name, raw_value, matched_in, source_ref_id, lines, grounded)
            for m in _IP_RE.finditer(text):
                lines = self._matched_lines(ref, m.group(0)) if ref else None
                add("ip", m.group(0), matched_in, source_ref_id, lines, grounded)
            for m in _HASH_RE.finditer(text):
                lines = self._matched_lines(ref, m.group(0)) if ref else None
                add("hash", m.group(0), matched_in, source_ref_id, lines, grounded)
            for m in _WIN_PATH_RE.finditer(text):
                lines = self._matched_lines(ref, m.group(0)) if ref else None
                add("file_path", m.group(0), matched_in, source_ref_id, lines, grounded)

        # Excerpts first so excerpt-grounded records win the dedup.
        for source_ref_id, ref, text in excerpt_texts:
            scan(text, "excerpt", source_ref_id, ref)

        # raw_summary values: grounded only if also present in an excerpt.
        if raw_summary:
            excerpt_norm = _normalize_freeform(
                "\n".join(t for _, _, t in excerpt_texts)
            )

            for m in _KV_RE.finditer(raw_summary):
                key_name, raw_value = m.group(1), m.group(2)
                norm = normalize_value(key_name, raw_value.strip('"').strip("'"))
                in_excerpt = bool(norm and norm in excerpt_norm)
                add(key_name, raw_value, "excerpt" if in_excerpt else "raw_summary",
                    None, None, in_excerpt)
            for m in _IP_RE.finditer(raw_summary):
                norm = normalize_value("ip", m.group(0))
                in_excerpt = bool(norm and norm in excerpt_norm)
                add("ip", m.group(0), "excerpt" if in_excerpt else "raw_summary",
                    None, None, in_excerpt)
            for m in _HASH_RE.finditer(raw_summary):
                norm = normalize_value("hash", m.group(0))
                in_excerpt = bool(norm and norm in excerpt_norm)
                add("hash", m.group(0), "excerpt" if in_excerpt else "raw_summary",
                    None, None, in_excerpt)

        return list(derived.values())


def grounding_rate(
    records: list[FieldGroundingRecord], fields: Optional[list[str]] = None
) -> float:
    """Rate of grounded / partially_grounded among applicable fixed fields."""
    applicable = [
        r for r in records
        if r.kind == "fixed"
        and r.status != "not_applicable"
        and (fields is None or r.field in fields)
    ]
    if not applicable:
        return 1.0
    grounded = sum(
        1 for r in applicable if r.status in ("grounded", "partially_grounded")
    )
    return grounded / len(applicable)
