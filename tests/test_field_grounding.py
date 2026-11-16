"""Unit tests for the field grounding layer (upstream-analysis spec 4.1/5.1)."""

from ir_agent.analysis.field_grounding import (
    FieldGroundingService,
    defang,
    grounding_rate,
    normalize_path,
    normalize_timestamp,
    normalize_value,
)
from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceLedgerEntry


VPN_EXCERPT = (
    '2025-05-10 02:14:08 JST sslvpn-login user="SAMPLE\\svc-backup" '
    "srcip=89[.]233[.]109[.]69 result=success tunnel_ip=10.8.14.23\n"
    '2025-05-10 02:14:11 JST sslvpn-tunnel user="SAMPLE\\svc-backup" '
    "srcip=89[.]233[.]109[.]69 action=tunnel-up"
)


def _make_entry(
    evidence_id: str = "EV-001",
    observed_event: dict | None = None,
    excerpt: str = VPN_EXCERPT,
    file_id: str = "file-vpn-001",
    path: str = "VPN/vpn.log",
) -> EvidenceLedgerEntry:
    return EvidenceLedgerEntry(
        evidence_id=evidence_id,
        promoted_from=["cand-001"],
        approval_timestamp="2025-01-01T00:00:00Z",
        approved_by="analyst",
        source_refs=[
            SourceReference(
                source_ref_id=f"ref-{file_id}",
                source_file_id=file_id,
                source_path=path,
                source_lines=(2, 3),
                excerpt=excerpt,
                excerpt_sha256="abc",
            )
        ],
        observed_event=observed_event or {},
        observed_fact="fact",
        interpretation="interp",
        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
        interpretation_confidence=ConfidenceLevel.POSSIBLE,
    )


class TestNormalization:
    def test_jst_and_offset_are_same_instant(self):
        assert (
            normalize_timestamp("2025-05-10 02:14:08 JST")
            == normalize_timestamp("2025-05-10T02:14:08+09:00")
            == "2025-05-09T17:14:08Z"
        )

    def test_unparseable_timestamp_returns_none(self):
        assert normalize_timestamp("first Monday of May") is None

    def test_defanged_ip_matches_plain(self):
        assert defang("207[.]148[.]90[.]45") == "207.148.90.45"
        assert normalize_value("src_ip", "207[.]148[.]90[.]45") == "207.148.90.45"

    def test_path_separator_and_case_insensitive(self):
        assert normalize_path("C:\\Windows\\Temp\\UIAnimation.XML") == (
            "c:/windows/temp/uianimation.xml"
        )


class TestFixedFieldGrounding:
    def test_exact_value_is_grounded(self):
        entry = _make_entry(observed_event={"user": "SAMPLE\\svc-backup"})
        records = FieldGroundingService().ground_entry(entry)
        rec = next(r for r in records if r.field == "user" and r.kind == "fixed")
        assert rec.status == "grounded"
        assert rec.matched_in == "excerpt"

    def test_defanged_ip_partially_grounded_when_plain_in_excerpt(self):
        excerpt = "2025-05-10 03:02:14 JST connection from 89.233.109.69"
        entry = _make_entry(
            observed_event={"src_ip": "89[.]233[.]109[.]69"}, excerpt=excerpt
        )
        records = FieldGroundingService().ground_entry(entry)
        rec = next(r for r in records if r.field == "src_ip" and r.kind == "fixed")
        assert rec.status == "partially_grounded"

    def test_timestamp_with_offset_grounds_against_jst_excerpt(self):
        entry = _make_entry(
            observed_event={"timestamp": "2025-05-10T02:14:08+09:00"}
        )
        records = FieldGroundingService().ground_entry(entry)
        rec = next(
            r for r in records if r.field == "timestamp" and r.kind == "fixed"
        )
        assert rec.status in ("grounded", "partially_grounded")

    def test_value_absent_from_excerpt_is_not_grounded(self):
        entry = _make_entry(observed_event={"dst_ip": "203.0.113.99"})
        records = FieldGroundingService().ground_entry(entry)
        rec = next(r for r in records if r.field == "dst_ip" and r.kind == "fixed")
        assert rec.status == "not_grounded"

    def test_empty_field_is_not_applicable(self):
        entry = _make_entry(observed_event={"hash": None})
        records = FieldGroundingService().ground_entry(entry)
        rec = next(r for r in records if r.field == "hash" and r.kind == "fixed")
        assert rec.status == "not_applicable"

    def test_host_grounded_via_file_inventory(self):
        inventory = [{"file_id": "file-vpn-001", "host": "vpn-tokyo-01"}]
        entry = _make_entry(observed_event={"host": "vpn-tokyo-01"})
        records = FieldGroundingService(file_inventory=inventory).ground_entry(
            entry
        )
        rec = next(r for r in records if r.field == "host" and r.kind == "fixed")
        assert rec.status == "grounded"
        assert rec.matched_in == "file_inventory"

    def test_matched_lines_are_absolute(self):
        entry = _make_entry(observed_event={"user": "SAMPLE\\svc-backup"})
        records = FieldGroundingService().ground_entry(entry)
        rec = next(r for r in records if r.field == "user" and r.kind == "fixed")
        # Excerpt starts at source line 2; the user appears on both lines.
        assert rec.source_lines == [2, 3]


class TestDerivedValues:
    def test_tunnel_ip_extracted_as_derived_and_grounded(self):
        entry = _make_entry(
            observed_event={
                "src_ip": "89[.]233[.]109[.]69",
                "raw_summary": "SSL-VPN login success, tunnel_ip=10.8.14.23",
            }
        )
        records = FieldGroundingService().ground_entry(entry)
        derived = [r for r in records if r.kind == "derived"]
        tunnel = [r for r in derived if r.normalized_value == "10.8.14.23"]
        assert tunnel, "tunnel_ip derived value must be extracted"
        assert any(r.status == "grounded" for r in tunnel)
        assert any(r.field == "tunnel_ip" for r in tunnel)

    def test_raw_summary_only_value_is_not_grounded(self):
        entry = _make_entry(
            excerpt="2025-05-10 02:14:08 JST login ok",
            observed_event={"raw_summary": "seen beacon to 198.51.100.7"},
        )
        records = FieldGroundingService().ground_entry(entry)
        rec = next(
            r for r in records
            if r.kind == "derived" and r.normalized_value == "198.51.100.7"
        )
        assert rec.status == "not_grounded"

    def test_derived_values_do_not_duplicate_fixed_fields(self):
        entry = _make_entry(
            observed_event={"src_ip": "89[.]233[.]109[.]69"}
        )
        records = FieldGroundingService().ground_entry(entry)
        derived_ips = [
            r for r in records
            if r.kind == "derived" and r.normalized_value == "89.233.109.69"
        ]
        assert derived_ips == []


class TestGroundingRate:
    def test_rate_counts_only_applicable_fixed_fields(self):
        entry = _make_entry(
            observed_event={"user": "SAMPLE\\svc-backup", "dst_ip": "203.0.113.9"}
        )
        records = FieldGroundingService().ground_entry(entry)
        rate = grounding_rate(records, fields=["user", "dst_ip"])
        assert rate == 0.5
