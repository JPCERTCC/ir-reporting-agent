"""Unit tests for analysis group / entity link validation (spec 4.3/4.4/5.3)."""

from ir_agent.analysis.field_grounding import FieldGroundingService
from ir_agent.analysis.group_validator import (
    AnalysisGroupValidator,
    build_allowed_techniques,
)
from ir_agent.models.base import SourceReference
from ir_agent.models.correlation import (
    AnalysisGroupCandidate,
    EntityLinkCandidate,
    EntityLinkMember,
    GroupAttackMapping,
)
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.events import ATTCKMapping
from ir_agent.models.evidence import EvidenceLedgerEntry


def _entry(
    evidence_id: str,
    observed_event: dict,
    excerpt: str,
    file_id: str,
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
                source_path=f"logs/{file_id}.log",
                source_lines=(1, 5),
                excerpt=excerpt,
                excerpt_sha256="x",
            )
        ],
        observed_event=observed_event,
        observed_fact="fact",
        interpretation="interp",
        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
        interpretation_confidence=ConfidenceLevel.POSSIBLE,
        attack_mapping_candidates=attack or [],
    )


def _fixture():
    t1003 = ATTCKMapping(
        tactic="Credential Access",
        technique_id="T1003.003",
        technique_name="OS Credential Dumping: NTDS",
        confidence=ConfidenceLevel.POSSIBLE,
    )
    vpn = _entry(
        "EV-001",
        {"host": "vpn-tokyo-01",
         "raw_summary": "login ok tunnel_ip=10.8.14.23"},
        "sslvpn-login result=success tunnel_ip=10.8.14.23",
        "f-vpn",
    )
    ad = _entry(
        "EV-002",
        {"host": "AD01", "src_ip": "10.8.14.23"},
        "EventID=4624 SourceNetworkAddress=10.8.14.23",
        "f-ad",
        attack=[t1003],
    )
    ledger = [vpn, ad]
    groundings = FieldGroundingService().ground_ledger(ledger)
    validator = AnalysisGroupValidator(
        ledger=ledger,
        groundings=groundings,
        hints=[],
        allowed_techniques=build_allowed_techniques(ledger),
    )
    return validator


def _link(members: list[EntityLinkMember], canonical="10.8.14.23"):
    return EntityLinkCandidate(
        entity_link_id="ENTL-001",
        entity_type="ip_address",
        canonical_label=canonical,
        members=members,
        link_reason="VPN割当IPとログオン元IPの一致",
    )


class TestEntityLinkValidation:
    def test_grounded_members_pass(self):
        validator = _fixture()
        link = _link([
            EntityLinkMember(evidence_id="EV-001", field="tunnel_ip", value="10.8.14.23"),
            EntityLinkMember(evidence_id="EV-002", field="src_ip", value="10.8.14.23"),
        ])
        result = validator.validate_entity_links([link])[0]
        assert result.validation_status == "valid"
        assert len(result.members) == 2

    def test_unknown_evidence_member_is_excluded(self):
        validator = _fixture()
        link = _link([
            EntityLinkMember(evidence_id="EV-999", field="src_ip", value="10.8.14.23"),
            EntityLinkMember(evidence_id="EV-002", field="src_ip", value="10.8.14.23"),
        ])
        result = validator.validate_entity_links([link])[0]
        assert len(result.excluded_members) == 1
        assert result.validation_status == "warning"

    def test_all_members_failed_is_rejected(self):
        validator = _fixture()
        link = _link([
            EntityLinkMember(evidence_id="EV-999", field="src_ip", value="10.8.14.23"),
        ])
        result = validator.validate_entity_links([link])[0]
        assert result.validation_status == "rejected"

    def test_fabricated_value_is_excluded(self):
        validator = _fixture()
        link = _link([
            EntityLinkMember(evidence_id="EV-001", field="tunnel_ip", value="10.9.9.9"),
            EntityLinkMember(evidence_id="EV-002", field="src_ip", value="10.8.14.23"),
        ])
        result = validator.validate_entity_links([link])[0]
        assert len(result.excluded_members) == 1

    def test_canonical_label_must_match_a_member(self):
        validator = _fixture()
        link = _link(
            [
                EntityLinkMember(
                    evidence_id="EV-002", field="src_ip", value="10.8.14.23"
                )
            ],
            canonical="203.0.113.1",
        )
        result = validator.validate_entity_links([link])[0]
        assert result.validation_status == "rejected"


def _group(**overrides) -> AnalysisGroupCandidate:
    defaults = dict(
        analysis_group_id="AGRP-001",
        title="VPN経由の内部侵入",
        report_section="3.1",
        claim_text="外部IPからのVPN接続後、10.8.14.23からAD01へのログオンが記録されました。",
        claim_category="interpretation",
        supporting_evidence=["EV-001", "EV-002"],
        limitations=["VPN機器の認証ログのみでは操作内容は確認できません"],
        group_basis="VPN割当IPとAD01ログオン元IPの一致",
    )
    defaults.update(overrides)
    return AnalysisGroupCandidate(**defaults)


class TestGroupValidation:
    def test_valid_group_passes(self):
        validator = _fixture()
        result = validator.validate_groups([_group()])[0]
        assert result.validation_status == "valid"

    def test_nonexistent_evidence_rejected(self):
        validator = _fixture()
        result = validator.validate_groups(
            [_group(supporting_evidence=["EV-404"])]
        )[0]
        assert result.validation_status == "rejected"

    def test_disallowed_report_section_rejected(self):
        validator = _fixture()
        result = validator.validate_groups(
            [_group(report_section="analysis")]
        )[0]
        assert result.validation_status == "rejected"

    def test_unknown_attack_technique_rejected(self):
        validator = _fixture()
        result = validator.validate_groups([
            _group(attack_mappings=[
                GroupAttackMapping(
                    technique_id="T9999",
                    technique_name="Invented",
                    tactic="Impact",
                    supporting_evidence=["EV-002"],
                )
            ])
        ])[0]
        assert result.validation_status == "rejected"

    def test_known_attack_technique_kept(self):
        validator = _fixture()
        result = validator.validate_groups([
            _group(attack_mappings=[
                GroupAttackMapping(
                    technique_id="T1003.003",
                    technique_name="OS Credential Dumping: NTDS",
                    tactic="Credential Access",
                    supporting_evidence=["EV-002"],
                )
            ])
        ])[0]
        assert result.validation_status == "valid"
        assert result.attack_mappings[0].technique_id == "T1003.003"

    def test_mapping_evidence_outside_group_is_trimmed_with_warning(self):
        validator = _fixture()
        result = validator.validate_groups([
            _group(
                supporting_evidence=["EV-001"],
                attack_mappings=[
                    GroupAttackMapping(
                        technique_id="T1003.003",
                        technique_name="OS Credential Dumping: NTDS",
                        tactic="Credential Access",
                        supporting_evidence=["EV-002"],
                    )
                ],
            )
        ])[0]
        assert result.validation_status == "warning"
        assert result.attack_mappings[0].supporting_evidence == ["EV-001"]

    def test_ungrounded_ip_in_claim_text_warns(self):
        validator = _fixture()
        result = validator.validate_groups([
            _group(claim_text="192.0.2.99 から侵入されました。")
        ])[0]
        assert result.validation_status == "warning"
        assert any("192.0.2.99" in r for r in result.validation_reasons)

    def test_empty_limitations_warns_but_is_not_autofilled(self):
        validator = _fixture()
        result = validator.validate_groups([_group(limitations=[])])[0]
        assert result.validation_status == "warning"
        assert result.limitations == []
        assert any("limitations が空" in r for r in result.validation_reasons)
