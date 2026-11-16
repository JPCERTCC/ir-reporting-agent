"""Unit tests for group-based claim building (upstream-analysis spec 5.4/7/8)."""

import pytest

from ir_agent.analysis.claim_builder import ClaimBuilder, EvidenceCoverageError
from ir_agent.models.base import SourceReference
from ir_agent.models.correlation import (
    AnalysisGroup,
    CorrelationHint,
    EntityLink,
    EntityLinkMember,
    GroupAttackMapping,
)
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.events import ATTCKMapping
from ir_agent.models.evidence import EvidenceLedgerEntry
from ir_agent.steering.manifest import ExpressionPolicy


def _entry(
    evidence_id: str,
    host: str,
    file_id: str,
    path: str | None = None,
    interpretation_confidence: ConfidenceLevel = ConfidenceLevel.POSSIBLE,
    attack: list[ATTCKMapping] | None = None,
) -> EvidenceLedgerEntry:
    return EvidenceLedgerEntry(
        evidence_id=evidence_id,
        promoted_from=["cand"],
        approval_timestamp="2025-01-01T00:00:00Z",
        approved_by="analyst",
        source_refs=[
            SourceReference(
                source_ref_id=f"ref-{file_id}",
                source_file_id=file_id,
                source_path=path or f"{host}/{file_id}.log",
                source_lines=(1, 3),
                excerpt="excerpt",
                excerpt_sha256="x",
            )
        ],
        observed_event={"host": host},
        observed_fact=f"fact {evidence_id}",
        interpretation=f"interp {evidence_id}",
        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
        interpretation_confidence=interpretation_confidence,
        attack_mapping_candidates=attack or [],
    )


def _group(**overrides) -> AnalysisGroup:
    defaults = dict(
        analysis_group_id="AGRP-001",
        title="統合分析結果",
        report_section="3.2",
        claim_text="AD01において資格情報関連の操作が記録されました。",
        claim_category="interpretation",
        supporting_evidence=["EV-001", "EV-002"],
        related_entity_link_ids=["ENTL-001"],
        related_hint_ids=[],
        limitations=["単一時点の記録であり継続性は確認できません"],
        group_basis="同一IP・近接時刻の一致",
        validation_status="valid",
    )
    defaults.update(overrides)
    return AnalysisGroup(**defaults)


def _link(evidence_ids: list[str]) -> EntityLink:
    return EntityLink(
        entity_link_id="ENTL-001",
        entity_type="ip_address",
        canonical_label="10.8.14.23",
        members=[
            EntityLinkMember(evidence_id=eid, field="src_ip", value="10.8.14.23")
            for eid in evidence_ids
        ],
        validation_status="valid",
    )


@pytest.fixture()
def two_host_ledger() -> list[EvidenceLedgerEntry]:
    return [
        _entry("EV-001", "vpn-tokyo-01", "f-vpn", path="VPN/vpn.log"),
        _entry("EV-002", "AD01", "f-ad", path="AD01/security.evtx.txt"),
    ]


class TestGroupClaims:
    def test_group_claim_carries_section_text_and_provenance(self, two_host_ledger):
        builder = ClaimBuilder()
        claims = builder.build_claims_from_groups(
            [_group()], two_host_ledger, ExpressionPolicy(), [],
            entity_links=[_link(["EV-001", "EV-002"])],
        )
        grouped = [c for c in claims if c.analysis_group_id == "AGRP-001"]
        assert len(grouped) == 1
        claim = grouped[0]
        assert claim.report_section == "3.2"
        assert claim.claim_text.startswith("AD01において")
        assert claim.group_basis == "同一IP・近接時刻の一致"
        assert claim.related_entity_link_ids == ["ENTL-001"]
        assert set(claim.supporting_evidence) == {"EV-001", "EV-002"}
        assert "単一時点の記録であり継続性は確認できません" in claim.limitations

    def test_rejected_group_produces_no_claim(self, two_host_ledger):
        builder = ClaimBuilder()
        claims = builder.build_claims_from_groups(
            [_group(validation_status="rejected")],
            two_host_ledger,
            ExpressionPolicy(),
            [],
        )
        assert not [c for c in claims if c.analysis_group_id]
        # The evidence still appears via fallback single-evidence claims.
        covered = {e for c in claims for e in c.supporting_evidence}
        assert covered == {"EV-001", "EV-002"}

    def test_ungrouped_evidence_gets_single_claims(self, two_host_ledger):
        ledger = two_host_ledger + [_entry("EV-003", "FS01", "f-fs")]
        builder = ClaimBuilder()
        claims = builder.build_claims_from_groups(
            [_group()], ledger, ExpressionPolicy(), [],
            entity_links=[_link(["EV-001", "EV-002"])],
        )
        covered = {e for c in claims for e in c.supporting_evidence}
        assert "EV-003" in covered

    def test_every_approved_evidence_appears_in_a_claim(self, two_host_ledger):
        ledger = two_host_ledger + [
            _entry("EV-003", "FS01", "f-fs"),
            _entry("EV-004", "CLIENT-001", "f-cl"),
        ]
        builder = ClaimBuilder()
        claims = builder.build_claims_from_groups(
            [_group()], ledger, ExpressionPolicy(), [],
        )
        covered = {e for c in claims for e in c.supporting_evidence}
        assert covered == {"EV-001", "EV-002", "EV-003", "EV-004"}


class TestGroupConfidence:
    def test_verified_link_allows_corroboration(self, two_host_ledger):
        builder = ClaimBuilder()
        claims = builder.build_claims_from_groups(
            [_group()], two_host_ledger, ExpressionPolicy(), [],
            entity_links=[_link(["EV-001", "EV-002"])],
        )
        claim = next(c for c in claims if c.analysis_group_id)
        assert "ENTL-001" in claim.confidence_basis

    def test_confidence_capped_one_level_above_weakest_interpretation(self):
        # Both possible; even with corroboration the claim must not exceed
        # probable (possible + 1).
        ledger = [
            _entry("EV-001", "hostA", "f-a",
                   interpretation_confidence=ConfidenceLevel.POSSIBLE),
            _entry("EV-002", "hostB", "f-b",
                   interpretation_confidence=ConfidenceLevel.POSSIBLE),
        ]
        builder = ClaimBuilder()
        claims = builder.build_claims_from_groups(
            [_group()], ledger, ExpressionPolicy(), [],
            entity_links=[_link(["EV-001", "EV-002"])],
        )
        claim = next(c for c in claims if c.analysis_group_id)
        assert claim.confidence_level in (
            ConfidenceLevel.POSSIBLE,
            ConfidenceLevel.PROBABLE,
        )

    def test_no_link_no_corroboration_boost(self):
        ledger = [
            _entry("EV-001", "hostA", "f-a"),
            _entry("EV-002", "hostB", "f-b"),
        ]
        builder = ClaimBuilder()
        # No entity links / hints given: corroboration must not apply.
        claims = builder.build_claims_from_groups(
            [_group(related_entity_link_ids=[])],
            ledger,
            ExpressionPolicy(),
            [],
        )
        claim = next(c for c in claims if c.analysis_group_id)
        assert "Corroboration" not in claim.confidence_basis

    def test_same_source_evidence_not_independent(self):
        # Same file, same host: strict independence fails even with a link.
        ledger = [
            _entry("EV-001", "hostA", "f-same"),
            _entry("EV-002", "hostA", "f-same"),
        ]
        builder = ClaimBuilder()
        claims = builder.build_claims_from_groups(
            [_group()], ledger, ExpressionPolicy(), [],
            entity_links=[_link(["EV-001", "EV-002"])],
        )
        claim = next(c for c in claims if c.analysis_group_id)
        assert "Corroboration" not in claim.confidence_basis


class TestAttackPropagation:
    def test_group_mapping_merged_with_evidence_candidates(self, two_host_ledger):
        t1003 = ATTCKMapping(
            tactic="Credential Access",
            technique_id="T1003.003",
            technique_name="OS Credential Dumping: NTDS",
            confidence=ConfidenceLevel.POSSIBLE,
        )
        ledger = [
            _entry("EV-001", "vpn-tokyo-01", "f-vpn"),
            _entry("EV-002", "AD01", "f-ad", attack=[t1003]),
        ]
        group = _group(attack_mappings=[
            GroupAttackMapping(
                technique_id="T1003.003",
                technique_name="OS Credential Dumping: NTDS",
                tactic="Credential Access",
                supporting_evidence=["EV-002"],
                mapping_reason="NTDS.dit のコピー操作",
            )
        ])
        builder = ClaimBuilder()
        claims = builder.build_claims_from_groups(
            [group], ledger, ExpressionPolicy(), [],
        )
        claim = next(c for c in claims if c.analysis_group_id)
        t_ids = [m.technique_id for m in claim.attack_mappings]
        assert t_ids.count("T1003.003") == 1
        mapping = next(
            m for m in claim.attack_mappings if m.technique_id == "T1003.003"
        )
        assert "EV-002" in mapping.supporting_evidence

    def test_mapping_confidence_capped_by_interpretation(self):
        overconfident = ATTCKMapping(
            tactic="Discovery",
            technique_id="T1082",
            technique_name="System Information Discovery",
            confidence=ConfidenceLevel.CONFIRMED,
        )
        ledger = [
            _entry(
                "EV-001", "hostA", "f-a",
                interpretation_confidence=ConfidenceLevel.POSSIBLE,
                attack=[overconfident],
            )
        ]
        builder = ClaimBuilder()
        claims = builder.build_claims(ledger, [], ExpressionPolicy(), [])
        mapping = claims[0].attack_mappings[0]
        assert mapping.confidence == ConfidenceLevel.POSSIBLE

    def test_single_evidence_claims_propagate_candidates(self):
        t1082 = ATTCKMapping(
            tactic="Discovery",
            technique_id="T1082",
            technique_name="System Information Discovery",
            confidence=ConfidenceLevel.POSSIBLE,
        )
        ledger = [_entry("EV-001", "hostA", "f-a", attack=[t1082])]
        builder = ClaimBuilder()
        claims = builder.build_claims(ledger, [], ExpressionPolicy(), [])
        assert claims[0].attack_mappings
        assert claims[0].attack_mappings[0].technique_id == "T1082"


class TestCoverageReconciliation:
    def test_missing_evidence_raises(self, two_host_ledger, monkeypatch):
        builder = ClaimBuilder()
        # Force the fallback path to drop evidence to prove the check fires.
        monkeypatch.setattr(
            ClaimBuilder, "build_claims", lambda self, *a, **k: []
        )
        with pytest.raises(EvidenceCoverageError) as exc:
            builder.build_claims_from_groups(
                [], two_host_ledger, ExpressionPolicy(), [],
            )
        assert set(exc.value.missing_evidence_ids) == {"EV-001", "EV-002"}
