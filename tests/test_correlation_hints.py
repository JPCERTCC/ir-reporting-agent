"""Unit tests for correlation hint generation (upstream-analysis spec 4.2/5.2)."""

from ir_agent.analysis.correlation import CorrelationHintBuilder
from ir_agent.analysis.field_grounding import FieldGroundingService
from ir_agent.models.base import SourceReference
from ir_agent.models.correlation import FieldGroundingRecord
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.events import ATTCKMapping
from ir_agent.models.evidence import EvidenceLedgerEntry


def _entry(
    evidence_id: str,
    observed_event: dict,
    excerpt: str,
    file_id: str,
    path: str = "logs/test.log",
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
                source_path=path,
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


def _ground(entries: list[EvidenceLedgerEntry]) -> list[FieldGroundingRecord]:
    return FieldGroundingService().ground_ledger(entries)


class TestSharedEntity:
    def test_vpn_tunnel_ip_matches_ad_source_ip(self):
        """The flagship pivot: derived tunnel_ip == fixed src_ip (spec 4.1)."""
        vpn = _entry(
            "EV-001",
            {
                "host": "vpn-tokyo-01",
                "raw_summary": "SSL-VPN login success, tunnel_ip=10.8.14.23",
            },
            'sslvpn-login user="S\\svc" result=success tunnel_ip=10.8.14.23',
            "file-vpn",
            "VPN/vpn.log",
        )
        ad = _entry(
            "EV-002",
            {"host": "AD01", "src_ip": "10.8.14.23"},
            "EventID=4624 AccountName=S\\Admin SourceNetworkAddress=10.8.14.23",
            "file-ad01",
            "AD01/security.evtx.txt",
        )
        hints = CorrelationHintBuilder().build_hints([vpn, ad], _ground([vpn, ad]))
        shared = [
            h for h in hints
            if h.hint_type == "shared_entity" and "10.8.14.23" in h.values
        ]
        assert shared, "tunnel_ip / src_ip pivot must produce a shared_entity hint"
        assert set(shared[0].evidence_ids) == {"EV-001", "EV-002"}
        # Cross-artifact, cross-host match scores high.
        assert shared[0].score >= 0.8

    def test_no_hint_for_single_evidence_value(self):
        only = _entry(
            "EV-001",
            {"src_ip": "198.51.100.10"},
            "conn from 198.51.100.10",
            "file-a",
        )
        hints = CorrelationHintBuilder().build_hints([only], _ground([only]))
        assert not [h for h in hints if h.hint_type == "shared_entity"]

    def test_ungrounded_values_produce_no_hints(self):
        # dst_ip values never appear in the excerpts -> not grounded.
        a = _entry("EV-001", {"dst_ip": "203.0.113.5"}, "nothing here", "f-a")
        b = _entry("EV-002", {"dst_ip": "203.0.113.5"}, "nothing here", "f-b")
        hints = CorrelationHintBuilder().build_hints([a, b], _ground([a, b]))
        assert not [
            h for h in hints
            if h.hint_type == "shared_entity" and "203.0.113.5" in h.values
        ]

    def test_shared_entity_has_no_time_window(self):
        # Days apart: value identity alone must still link the evidence.
        a = _entry(
            "EV-001",
            {"timestamp": "2025-05-01T00:00:00+09:00", "file_path": "C:\\Tmp\\UIAnimation.xml"},
            "2025-05-01 00:00:00 JST created C:\\Tmp\\UIAnimation.xml",
            "f-a",
            "FS01/mft.csv",
        )
        b = _entry(
            "EV-002",
            {"timestamp": "2025-06-01T00:00:00+09:00", "file_path": "C:\\Tmp\\UIAnimation.xml"},
            "2025-06-01 00:00:00 JST accessed C:\\Tmp\\UIAnimation.xml",
            "f-b",
            "CLIENT-001/edr.json",
        )
        hints = CorrelationHintBuilder().build_hints([a, b], _ground([a, b]))
        shared = [
            h for h in hints
            if h.hint_type == "shared_entity"
            and "c:/tmp/uianimation.xml" in h.values
        ]
        assert shared


class TestTimeProximity:
    def test_same_host_within_window(self):
        a = _entry(
            "EV-001",
            {"host": "AD01", "timestamp": "2025-05-10T03:02:14+09:00"},
            "2025-05-10 03:02:14 JST EventID=1",
            "f-a",
        )
        b = _entry(
            "EV-002",
            {"host": "AD01", "timestamp": "2025-05-10T03:20:00+09:00"},
            "2025-05-10 03:20:00 JST EventID=2",
            "f-b",
        )
        hints = CorrelationHintBuilder().build_hints([a, b], _ground([a, b]))
        prox = [h for h in hints if h.hint_type == "time_proximity"]
        assert prox and set(prox[0].evidence_ids) == {"EV-001", "EV-002"}

    def test_outside_window_produces_no_hint(self):
        a = _entry(
            "EV-001",
            {"host": "AD01", "timestamp": "2025-05-10T03:00:00+09:00"},
            "2025-05-10 03:00:00 JST EventID=1",
            "f-a",
        )
        b = _entry(
            "EV-002",
            {"host": "AD01", "timestamp": "2025-05-10T09:00:00+09:00"},
            "2025-05-10 09:00:00 JST EventID=2",
            "f-b",
        )
        hints = CorrelationHintBuilder().build_hints([a, b], _ground([a, b]))
        assert not [h for h in hints if h.hint_type == "time_proximity"]

    def test_window_override_from_config(self):
        a = _entry(
            "EV-001",
            {"host": "AD01", "timestamp": "2025-05-10T03:00:00+09:00"},
            "2025-05-10 03:00:00 JST EventID=1",
            "f-a",
        )
        b = _entry(
            "EV-002",
            {"host": "AD01", "timestamp": "2025-05-10T09:00:00+09:00"},
            "2025-05-10 09:00:00 JST EventID=2",
            "f-b",
        )
        builder = CorrelationHintBuilder(
            config={"same_host_user_minutes": 60 * 12}
        )
        hints = builder.build_hints([a, b], _ground([a, b]))
        assert [h for h in hints if h.hint_type == "time_proximity"]


class TestAttackAndArtifactContext:
    def test_same_attack_mapping_hint(self):
        mapping = ATTCKMapping(
            tactic="Discovery",
            technique_id="T1082",
            technique_name="System Information Discovery",
            confidence=ConfidenceLevel.POSSIBLE,
        )
        a = _entry("EV-001", {"host": "A"}, "whoami", "f-a", attack=[mapping])
        b = _entry("EV-002", {"host": "B"}, "systeminfo", "f-b", attack=[mapping])
        hints = CorrelationHintBuilder().build_hints([a, b], _ground([a, b]))
        atk = [h for h in hints if h.hint_type == "same_attack_mapping"]
        assert atk and atk[0].values == ["T1082"]

    def test_same_artifact_context_hint(self):
        a = _entry("EV-001", {"host": "A"}, "line one", "f-shared")
        b = _entry("EV-002", {"host": "A"}, "line two", "f-shared")
        hints = CorrelationHintBuilder().build_hints([a, b], _ground([a, b]))
        assert [h for h in hints if h.hint_type == "same_artifact_context"]


class TestHintCap:
    def test_per_evidence_hint_cap(self):
        # One evidence sharing many values with many others; cap at 3.
        entries = []
        hub_event = {"host": "HUB"}
        for i in range(8):
            hub_event[f"v{i}"] = None  # keep observed_event simple
        hub_excerpt = " ".join(f"val{i}=203.0.113.{i}" for i in range(8))
        entries.append(_entry("EV-HUB", {"host": "HUB"}, hub_excerpt, "f-hub"))
        for i in range(8):
            entries.append(
                _entry(
                    f"EV-{i:03d}",
                    {"src_ip": f"203.0.113.{i}"},
                    f"conn from 203.0.113.{i}",
                    f"f-{i}",
                )
            )
        builder = CorrelationHintBuilder(config={"max_hints_per_evidence": 3})
        hints = builder.build_hints(entries, _ground(entries))
        hub_hints = [h for h in hints if "EV-HUB" in h.evidence_ids]
        assert len(hub_hints) <= 3
