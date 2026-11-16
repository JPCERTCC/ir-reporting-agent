"""Validation of LLM-proposed entity links and analysis groups.

Implements the ``validate-analysis-groups`` step: LLM output
(``entity_link_candidates.jsonl`` / ``analysis_group_candidates.jsonl``) is
untrusted data. This module verifies every member value against the
grounded field records and the approved evidence ledger, and converts the
proposals into validated intermediate data (``entity_links.jsonl`` /
``analysis_groups.jsonl``) that ``build-claims`` may consume.

Validation failures are recorded in ``validation_status`` / ``reasons``
rather than stopping processing, except where the spec mandates rejection
(nonexistent evidence, disallowed report_section, unknown ATT&CK id).
Human judgments (e.g. empty limitations) are never auto-filled; they are
flagged as warnings for CP2 review.
"""

from __future__ import annotations

import re
from typing import Optional

from ir_agent.models.correlation import (
    ALLOWED_REPORT_SECTIONS,
    AnalysisGroup,
    AnalysisGroupCandidate,
    CorrelationHint,
    EntityLink,
    EntityLinkCandidate,
    EntityLinkMember,
    FieldGroundingRecord,
)
from ir_agent.analysis.field_grounding import (
    defang,
    normalize_value,
    _normalize_freeform,
)
from ir_agent.models.enums import ClaimCategory
from ir_agent.models.evidence import EvidenceLedgerEntry

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Entity shapes checked inside claim_text (spec section 5.3). Hostnames and
# usernames are matched only against known grounded values to avoid false
# positives in Japanese prose.
_CLAIM_IP_RE = re.compile(r"\b\d{1,3}(?:(?:\[\.\]|\.)\d{1,3}){3}\b")
_CLAIM_HASH_RE = re.compile(
    r"\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b"
)
_CLAIM_WIN_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\s、。\"'<>|]{2,260}")


def build_allowed_techniques(
    ledger: list[EvidenceLedgerEntry],
    attack_mappings: Optional[list[dict]] = None,
) -> set[str]:
    """Allowed ATT&CK technique ids: those already present at evidence level.

    Report-stage steps must not invent new techniques (spec section 8.2),
    so the allowlist is the union of evidence-level mapping candidates and
    the built attack_mappings, plus the mapper's own indicator table.
    """
    allowed: set[str] = set()
    for entry in ledger:
        for mapping in entry.attack_mapping_candidates or []:
            allowed.add(mapping.technique_id)
    for record in attack_mappings or []:
        tid = record.get("technique_id")
        if tid:
            allowed.add(tid)
    try:
        from ir_agent.analysis.attack_mapper import _TECHNIQUE_INDICATORS

        for _, _, technique_id, _ in _TECHNIQUE_INDICATORS:
            allowed.add(technique_id)
    except ImportError:
        pass
    return allowed


class AnalysisGroupValidator:
    """Validates entity link and analysis group candidates against evidence."""

    def __init__(
        self,
        ledger: list[EvidenceLedgerEntry],
        groundings: list[FieldGroundingRecord],
        hints: Optional[list[CorrelationHint]] = None,
        allowed_techniques: Optional[set[str]] = None,
    ) -> None:
        self._active = {
            e.evidence_id: e for e in ledger if not e.withdrawn
        }
        self._hints = {h.hint_id: h for h in (hints or [])}
        self._allowed_techniques = allowed_techniques or set()

        # Grounded normalized values per evidence, and known fields.
        self._grounded_values: dict[str, set[str]] = {}
        self._known_fields: dict[str, set[str]] = {}
        for g in groundings:
            if g.status in ("grounded", "partially_grounded") and g.normalized_value:
                self._grounded_values.setdefault(g.evidence_id, set()).add(
                    g.normalized_value
                )
            self._known_fields.setdefault(g.evidence_id, set()).add(g.field)

    # --- Entity links ---

    def validate_entity_links(
        self, candidates: list[EntityLinkCandidate]
    ) -> list[EntityLink]:
        links: list[EntityLink] = []
        for cand in candidates:
            links.append(self._validate_entity_link(cand))
        return links

    def _validate_entity_link(self, cand: EntityLinkCandidate) -> EntityLink:
        valid_members: list[EntityLinkMember] = []
        excluded: list[EntityLinkMember] = []
        reasons: list[str] = []

        for member in cand.members:
            failure = self._member_failure(member)
            if failure:
                excluded.append(member)
                reasons.append(
                    f"member {member.evidence_id}/{member.field}="
                    f"{member.value}: {failure}"
                )
            else:
                valid_members.append(member)

        status = "valid"
        if not valid_members:
            status = "rejected"
            reasons.append("全 member が検証に失敗しました")
        else:
            # Normalize the canonical label per member field semantics so a
            # path/IP label matches its members regardless of notation.
            canonical_matches = any(
                normalize_value(m.field, cand.canonical_label)
                == normalize_value(m.field, m.value)
                for m in valid_members
            )
            if not canonical_matches:
                status = "rejected"
                reasons.append(
                    "canonical_label がどの member の値とも正規化一致しません"
                )
            elif excluded:
                status = "warning"
            elif len(valid_members) < 2:
                status = "warning"
                reasons.append("有効な member が1件のみで、リンクを構成しません")

        return EntityLink(
            entity_link_id=cand.entity_link_id,
            entity_type=cand.entity_type,
            canonical_label=cand.canonical_label,
            members=valid_members,
            excluded_members=excluded,
            link_reason=cand.link_reason,
            related_hint_ids=[
                h for h in cand.related_hint_ids if h in self._hints
            ],
            validation_status=status,
            validation_reasons=reasons,
            review_status=cand.review_status,
        )

    def _member_failure(self, member: EntityLinkMember) -> Optional[str]:
        entry = self._active.get(member.evidence_id)
        if entry is None:
            return "承認済み証拠台帳に存在しません"

        known_fields = self._known_fields.get(member.evidence_id, set())
        observed_fields = set((entry.observed_event or {}).keys())
        if member.field not in known_fields and member.field not in observed_fields:
            return "field が observed_event にも接地レコードにも存在しません"

        if not self._value_grounded(member.evidence_id, member.field, member.value):
            return "値が excerpt / field_grounding 上で接地していません"
        return None

    def _value_grounded(self, evidence_id: str, field: str, value: str) -> bool:
        norm = normalize_value(field, value)
        if norm and norm in self._grounded_values.get(evidence_id, set()):
            return True
        # Fall back to direct excerpt containment (normalized).
        entry = self._active.get(evidence_id)
        if entry is None or not norm:
            return False
        for ref in entry.source_refs or []:
            if norm in _normalize_freeform(ref.excerpt or ""):
                return True
        return False

    # --- Analysis groups ---

    def validate_groups(
        self,
        candidates: list[AnalysisGroupCandidate],
        entity_links: Optional[list[EntityLink]] = None,
    ) -> list[AnalysisGroup]:
        links_by_id = {
            l.entity_link_id: l
            for l in (entity_links or [])
            if l.validation_status != "rejected"
        }
        return [self._validate_group(c, links_by_id) for c in candidates]

    def _validate_group(
        self,
        cand: AnalysisGroupCandidate,
        links_by_id: dict[str, EntityLink],
    ) -> AnalysisGroup:
        reasons: list[str] = []
        status = "valid"

        def warn(message: str) -> None:
            nonlocal status
            if status != "rejected":
                status = "warning"
            reasons.append(message)

        def reject(message: str) -> None:
            nonlocal status
            status = "rejected"
            reasons.append(message)

        # Supporting evidence must exist, be approved, and not withdrawn.
        supporting = list(dict.fromkeys(cand.supporting_evidence))
        if not supporting:
            reject("supporting_evidence が空です")
        missing = [e for e in supporting if e not in self._active]
        if missing:
            reject(
                "存在しない、または承認済みでない証拠IDを含みます: "
                + ", ".join(missing)
            )

        # report_section must be a fixed allowed value.
        if cand.report_section not in ALLOWED_REPORT_SECTIONS:
            reject(
                f"report_section '{cand.report_section}' は許可値ではありません"
                f"（許可: {', '.join(ALLOWED_REPORT_SECTIONS)}）"
            )

        # claim_category must be a known category.
        category = cand.claim_category
        try:
            ClaimCategory(category)
        except ValueError:
            warn(
                f"claim_category '{category}' は不明のため "
                "interpretation として扱います"
            )
            category = ClaimCategory.INTERPRETATION.value

        # ATT&CK mappings: id must be allowed; supporting evidence must be a
        # subset of the group's supporting evidence.
        validated_mappings = []
        for mapping in cand.attack_mappings:
            if not _TECHNIQUE_ID_RE.match(mapping.technique_id or ""):
                reject(
                    f"ATT&CK technique_id '{mapping.technique_id}' の形式が不正です"
                )
                continue
            if (
                self._allowed_techniques
                and mapping.technique_id not in self._allowed_techniques
            ):
                reject(
                    f"ATT&CK technique_id '{mapping.technique_id}' は"
                    "許可リストに存在しません"
                )
                continue
            mapping = mapping.model_copy()
            outside = [
                e for e in mapping.supporting_evidence if e not in supporting
            ]
            if outside:
                warn(
                    f"ATT&CK {mapping.technique_id} の supporting_evidence に"
                    f"グループ外の証拠が含まれるため除外しました: {', '.join(outside)}"
                )
                mapping.supporting_evidence = [
                    e for e in mapping.supporting_evidence if e in supporting
                ]
            if not mapping.supporting_evidence:
                mapping.supporting_evidence = list(supporting)
            validated_mappings.append(mapping)

        # Entity link references must exist and be validated.
        valid_link_ids = [
            lid for lid in cand.related_entity_link_ids if lid in links_by_id
        ]
        dropped_links = set(cand.related_entity_link_ids) - set(valid_link_ids)
        if dropped_links:
            warn(
                "検証済みでないエンティティリンク参照を除外しました: "
                + ", ".join(sorted(dropped_links))
            )
        valid_hint_ids = [h for h in cand.related_hint_ids if h in self._hints]

        # Key entities in claim_text must be grounded in supporting evidence
        # or referenced entity links.
        if status != "rejected":
            ungrounded = self._ungrounded_claim_entities(
                cand.claim_text, supporting, valid_link_ids, links_by_id
            )
            if ungrounded:
                warn(
                    "claim_text 内の値が supporting evidence に接地していません: "
                    + ", ".join(sorted(ungrounded))
                )

        # Empty limitations: never auto-filled — flagged for CP2 (spec 5.3).
        if not cand.limitations:
            warn("limitations が空。制約の有無を CP2 で確認")

        return AnalysisGroup(
            analysis_group_id=cand.analysis_group_id,
            title=cand.title,
            report_section=cand.report_section,
            claim_text=cand.claim_text,
            claim_category=category,
            supporting_evidence=supporting,
            related_entity_link_ids=valid_link_ids,
            related_hint_ids=valid_hint_ids,
            attack_mappings=validated_mappings,
            limitations=list(cand.limitations),
            group_basis=cand.group_basis,
            validation_status=status,
            validation_reasons=reasons,
            review_status=cand.review_status,
        )

    def _ungrounded_claim_entities(
        self,
        claim_text: str,
        supporting: list[str],
        link_ids: list[str],
        links_by_id: dict[str, EntityLink],
    ) -> set[str]:
        """Extract IPs / hashes / Windows paths from claim_text and check
        each against the grounded values of the supporting evidence and
        referenced entity links."""
        grounded: set[str] = set()
        for eid in supporting:
            grounded |= self._grounded_values.get(eid, set())
        for lid in link_ids:
            link = links_by_id.get(lid)
            if link:
                for member in link.members:
                    norm = normalize_value(member.field, member.value)
                    if norm:
                        grounded.add(norm)

        ungrounded: set[str] = set()
        text = claim_text or ""
        for pattern, field in (
            (_CLAIM_IP_RE, "ip"),
            (_CLAIM_HASH_RE, "hash"),
            (_CLAIM_WIN_PATH_RE, "file_path"),
        ):
            for m in pattern.finditer(text):
                token = m.group(0)
                norm = normalize_value(field, token)
                if not norm:
                    continue
                if norm in grounded:
                    continue
                # Paths may be quoted partially; accept containment matches.
                if field == "file_path" and any(
                    norm in g or g in norm for g in grounded
                ):
                    continue
                ungrounded.add(defang(token))
        return ungrounded
