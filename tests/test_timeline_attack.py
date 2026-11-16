"""Unit tests for TimelineBuilder and ATTCKMapper.

Validates:
- Requirement 9.2: Timestamps normalized to UTC while preserving original
- Requirement 9.5: Conflict detection for causally related events
- Requirement 9.7: Timeline uses only event_time timestamps
- Requirement 10.3: ATT&CK mapping covers all 12 tactics
"""

import pytest

from ir_agent.analysis.attack_mapper import ATTACK_TACTICS, ATTCKMapper
from ir_agent.analysis.timeline import TimelineBuilder
from ir_agent.models.analysis import TimelineEntry
from ir_agent.models.base import SourceReference, TimeRange
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceCandidate, EvidenceLedgerEntry
from ir_agent.steering.manifest import CaseManifest

# --- Fixtures ---


@pytest.fixture
def timeline_builder() -> TimelineBuilder:
    """Create a TimelineBuilder instance."""
    return TimelineBuilder()


@pytest.fixture
def attack_mapper() -> ATTCKMapper:
    """Create an ATTCKMapper instance."""
    return ATTCKMapper()


@pytest.fixture
def sample_manifest() -> CaseManifest:
    """Create a sample CaseManifest for timeline tests."""
    return CaseManifest(
        case_id="CASE-TEST-001",
        case_name="Timeline Test Case",
        scope="Test investigation",
        hosts=["host01", "host02"],
        time_range=TimeRange(
            start="2025-05-01T00:00:00Z",
            end="2025-05-31T23:59:59Z",
        ),
        report_timezone="Asia/Tokyo",
    )


def _make_source_ref(ref_id: str = "SR-001") -> SourceReference:
    """Helper to create a SourceReference."""
    return SourceReference(
        source_ref_id=ref_id,
        source_file_id="FI-001",
        source_path="host01/syslog.log",
        source_lines=(10, 12),
        excerpt="sample log line",
        excerpt_sha256="abc123def456",
    )


def _make_ledger_entry(
    evidence_id: str,
    observed_event: dict,
    observed_fact: str = "A process was executed",
    withdrawn: bool = False,
) -> EvidenceLedgerEntry:
    """Helper to create an EvidenceLedgerEntry."""
    return EvidenceLedgerEntry(
        evidence_id=evidence_id,
        promoted_from=["CAND-001"],
        approval_timestamp="2025-05-15T10:00:00Z",
        approved_by="analyst01",
        source_refs=[_make_source_ref()],
        observed_event=observed_event,
        observed_fact=observed_fact,
        interpretation="Possible malicious execution",
        observed_fact_confidence=ConfidenceLevel.CONFIRMED,
        interpretation_confidence=ConfidenceLevel.PROBABLE,
        withdrawn=withdrawn,
    )


# --- Tests for Requirement 9.7: Only event_time timestamps ---


class TestTimelineUsesOnlyEventTime:
    """Tests that TimelineBuilder only uses event_time timestamps (Req 9.7)."""

    def test_event_time_included_in_timeline(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        """Events with event_time timestamps appear in the timeline."""
        entry = _make_ledger_entry(
            evidence_id="EV-001",
            observed_event={
                "timestamps": [
                    {
                        "original_value": "2025-05-10T14:30:00+09:00",
                        "timestamp_type": "event_time",
                        "confidence": "confirmed",
                    }
                ],
                "host": "host01",
            },
        )
        timeline = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(timeline) == 1
        assert timeline[0].evidence_id == "EV-001"

    def test_collection_time_excluded_from_timeline(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        """Events with only collection_time timestamps are excluded (Req 9.7)."""
        entry = _make_ledger_entry(
            evidence_id="EV-002",
            observed_event={
                "timestamps": [
                    {
                        "original_value": "2025-05-10T14:30:00Z",
                        "timestamp_type": "collection_time",
                        "confidence": "confirmed",
                    }
                ],
                "host": "host01",
            },
        )
        timeline = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(timeline) == 0

    def test_file_modified_time_excluded_from_timeline(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        """Events with only file_modified_time timestamps are excluded (Req 9.7)."""
        entry = _make_ledger_entry(
            evidence_id="EV-003",
            observed_event={
                "timestamps": [
                    {
                        "original_value": "2025-05-09T08:00:00Z",
                        "timestamp_type": "file_modified_time",
                        "confidence": "probable",
                    }
                ],
                "host": "host01",
            },
        )
        timeline = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(timeline) == 0

    def test_analysis_time_excluded_from_timeline(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        """Events with only analysis_time timestamps are excluded (Req 9.7)."""
        entry = _make_ledger_entry(
            evidence_id="EV-004",
            observed_event={
                "timestamps": [
                    {
                        "original_value": "2025-05-15T10:00:00Z",
                        "timestamp_type": "analysis_time",
                        "confidence": "confirmed",
                    }
                ],
                "host": "host01",
            },
        )
        timeline = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(timeline) == 0

    def test_mixed_timestamps_only_event_time_used(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        """When entry has multiple timestamp types, only event_time produces entries."""
        entry = _make_ledger_entry(
            evidence_id="EV-005",
            observed_event={
                "timestamps": [
                    {
                        "original_value": "2025-05-10T14:30:00Z",
                        "timestamp_type": "event_time",
                        "confidence": "confirmed",
                    },
                    {
                        "original_value": "2025-05-11T09:00:00Z",
                        "timestamp_type": "collection_time",
                        "confidence": "confirmed",
                    },
                    {
                        "original_value": "2025-05-12T10:00:00Z",
                        "timestamp_type": "file_modified_time",
                        "confidence": "probable",
                    },
                ],
                "host": "host01",
            },
        )
        timeline = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(timeline) == 1
        assert timeline[0].timestamp_type == "event_time"


# --- Tests for Requirement 9.2: Timestamp normalization to UTC ---


class TestTimestampNormalizationToUTC:
    """Tests that timestamps are normalized to UTC while preserving originals (Req 9.2)."""

    def test_jst_timestamp_normalized_to_utc(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        """A JST (+09:00) timestamp is normalized to UTC."""
        entry = _make_ledger_entry(
            evidence_id="EV-010",
            observed_event={
                "timestamps": [
                    {
                        "original_value": "2025-05-10T14:30:00+09:00",
                        "timestamp_type": "event_time",
                        "confidence": "confirmed",
                    }
                ],
                "host": "host01",
            },
        )
        timeline = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(timeline) == 1
        # 14:30 JST = 05:30 UTC
        assert "05:30:00" in timeline[0].event_time

    def test_original_timestamp_preserved(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        """The original timestamp string is preserved in the timeline entry."""
        original = "2025-05-10T14:30:00+09:00"
        entry = _make_ledger_entry(
            evidence_id="EV-011",
            observed_event={
                "timestamps": [
                    {
                        "original_value": original,
                        "timestamp_type": "event_time",
                        "confidence": "confirmed",
                    }
                ],
                "host": "host01",
            },
        )
        timeline = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(timeline) == 1
        assert timeline[0].original_timestamp == original

    def test_pre_normalized_utc_used_directly(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        """If normalized_utc is already provided, it's used directly."""
        original = "2025/05/10 14:30:00 JST"
        normalized = "2025-05-10T05:30:00.000000Z"
        entry = _make_ledger_entry(
            evidence_id="EV-012",
            observed_event={
                "timestamps": [
                    {
                        "original_value": original,
                        "normalized_utc": normalized,
                        "timestamp_type": "event_time",
                        "confidence": "confirmed",
                    }
                ],
                "host": "host01",
            },
        )
        timeline = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(timeline) == 1
        assert timeline[0].event_time == normalized
        assert timeline[0].original_timestamp == original

    def test_utc_timestamp_unchanged(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        """A UTC timestamp remains as UTC after normalization."""
        entry = _make_ledger_entry(
            evidence_id="EV-013",
            observed_event={
                "timestamps": [
                    {
                        "original_value": "2025-05-10T05:30:00Z",
                        "timestamp_type": "event_time",
                        "confidence": "confirmed",
                    }
                ],
                "host": "host01",
            },
        )
        timeline = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(timeline) == 1
        assert "05:30:00" in timeline[0].event_time

    def test_display_timezone_set_from_manifest(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        """The display_timezone field is set from the manifest's report_timezone."""
        entry = _make_ledger_entry(
            evidence_id="EV-014",
            observed_event={
                "timestamps": [
                    {
                        "original_value": "2025-05-10T05:30:00Z",
                        "timestamp_type": "event_time",
                        "confidence": "confirmed",
                    }
                ],
            },
        )
        timeline = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(timeline) == 1
        assert timeline[0].display_timezone == "Asia/Tokyo"


# --- Tests for Requirement 9.5: Conflict detection ---


class TestConflictDetection:
    """Tests for TimelineBuilder.detect_conflicts (Req 9.5)."""

    def test_same_evidence_different_timestamps_detected(
        self, timeline_builder: TimelineBuilder
    ):
        """Conflict flagged when same evidence has different timestamps."""
        entries = [
            TimelineEntry(
                entry_id="TE-001",
                evidence_id="EV-020",
                event_time="2025-05-10T05:00:00Z",
                original_timestamp="2025-05-10T14:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="Process execution on host01",
                host="host01",
                confidence=ConfidenceLevel.CONFIRMED,
                timestamp_type="event_time",
            ),
            TimelineEntry(
                entry_id="TE-002",
                evidence_id="EV-020",
                event_time="2025-05-10T06:00:00Z",
                original_timestamp="2025-05-10T15:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="Process execution on host01",
                host="host01",
                confidence=ConfidenceLevel.CONFIRMED,
                timestamp_type="event_time",
            ),
        ]
        conflicts = timeline_builder.detect_conflicts(entries)
        assert len(conflicts) >= 1
        assert conflicts[0]["conflict_type"] == "same_evidence_different_timestamps"

    def test_near_simultaneous_different_evidence_detected(
        self, timeline_builder: TimelineBuilder
    ):
        """Conflict flagged for near-simultaneous events from different evidence."""
        entries = [
            TimelineEntry(
                entry_id="TE-003",
                evidence_id="EV-021",
                event_time="2025-05-10T05:00:00.000000Z",
                original_timestamp="2025-05-10T14:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="File created on host01",
                host="host01",
                confidence=ConfidenceLevel.PROBABLE,
                timestamp_type="event_time",
            ),
            TimelineEntry(
                entry_id="TE-004",
                evidence_id="EV-022",
                event_time="2025-05-10T05:00:00.500000Z",
                original_timestamp="2025-05-10T14:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="Process started on host01",
                host="host01",
                confidence=ConfidenceLevel.PROBABLE,
                timestamp_type="event_time",
            ),
        ]
        conflicts = timeline_builder.detect_conflicts(entries)
        assert len(conflicts) >= 1
        assert conflicts[0]["conflict_type"] == "near_simultaneous_different_evidence"

    def test_no_conflict_for_different_hosts(
        self, timeline_builder: TimelineBuilder
    ):
        """No conflict for near-simultaneous events on different hosts."""
        entries = [
            TimelineEntry(
                entry_id="TE-005",
                evidence_id="EV-023",
                event_time="2025-05-10T05:00:00.000000Z",
                original_timestamp="2025-05-10T14:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="Event on host01",
                host="host01",
                confidence=ConfidenceLevel.PROBABLE,
                timestamp_type="event_time",
            ),
            TimelineEntry(
                entry_id="TE-006",
                evidence_id="EV-024",
                event_time="2025-05-10T05:00:00.500000Z",
                original_timestamp="2025-05-10T14:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="Event on host02",
                host="host02",
                confidence=ConfidenceLevel.PROBABLE,
                timestamp_type="event_time",
            ),
        ]
        conflicts = timeline_builder.detect_conflicts(entries)
        assert len(conflicts) == 0

    def test_no_conflict_for_well_separated_events(
        self, timeline_builder: TimelineBuilder
    ):
        """No conflict for events that are well-separated in time."""
        entries = [
            TimelineEntry(
                entry_id="TE-007",
                evidence_id="EV-025",
                event_time="2025-05-10T05:00:00Z",
                original_timestamp="2025-05-10T14:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="Earlier event on host01",
                host="host01",
                confidence=ConfidenceLevel.PROBABLE,
                timestamp_type="event_time",
            ),
            TimelineEntry(
                entry_id="TE-008",
                evidence_id="EV-026",
                event_time="2025-05-10T06:00:00Z",
                original_timestamp="2025-05-10T15:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="Later event on host01",
                host="host01",
                confidence=ConfidenceLevel.PROBABLE,
                timestamp_type="event_time",
            ),
        ]
        conflicts = timeline_builder.detect_conflicts(entries)
        assert len(conflicts) == 0

    def test_no_conflict_when_confirmed_confidence(
        self, timeline_builder: TimelineBuilder
    ):
        """No near-simultaneous conflict if either event is confirmed confidence."""
        entries = [
            TimelineEntry(
                entry_id="TE-009",
                evidence_id="EV-027",
                event_time="2025-05-10T05:00:00.000000Z",
                original_timestamp="2025-05-10T14:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="Event A on host01",
                host="host01",
                confidence=ConfidenceLevel.CONFIRMED,
                timestamp_type="event_time",
            ),
            TimelineEntry(
                entry_id="TE-010",
                evidence_id="EV-028",
                event_time="2025-05-10T05:00:00.500000Z",
                original_timestamp="2025-05-10T14:00:00+09:00",
                display_timezone="Asia/Tokyo",
                event_description="Event B on host01",
                host="host01",
                confidence=ConfidenceLevel.PROBABLE,
                timestamp_type="event_time",
            ),
        ]
        conflicts = timeline_builder.detect_conflicts(entries)
        assert len(conflicts) == 0

    def test_empty_timeline_no_conflicts(
        self, timeline_builder: TimelineBuilder
    ):
        """Empty timeline produces no conflicts."""
        conflicts = timeline_builder.detect_conflicts([])
        assert conflicts == []


class TestExcerptLineRows:
    """Multi-line evidence keeps one timeline row per timestamped log line."""

    def _entry(self, excerpt: str) -> EvidenceLedgerEntry:
        entry = _make_ledger_entry(
            "EV-030", {"host": "host01", "timestamp": "2025-05-10T05:00:00Z"})
        entry.source_refs[0].excerpt = excerpt
        return entry

    def test_each_timestamped_line_gets_a_row(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        entry = self._entry(
            "2025-05-10T05:00:00Z logon user=a\n"
            "continuation without a time\n"
            "2025-05-10T05:02:30Z special privileges user=a")
        rows = timeline_builder.build_timeline([entry], sample_manifest)
        assert [(r.event_time[:19], r.source_line) for r in rows] == [
            ("2025-05-10T05:00:00", 10), ("2025-05-10T05:02:30", 12)]
        assert "special privileges" in rows[1].source_text
        # Separate log lines of one evidence item are not a timestamp conflict.
        assert timeline_builder.detect_conflicts(rows) == []

    def test_naive_and_out_of_window_times_are_not_read(
        self, timeline_builder: TimelineBuilder, sample_manifest: CaseManifest
    ):
        entry = self._entry(
            "2025-05-10T05:00:00Z logon\n2025-05-10 06:00:00 local time\n"
            "2024-01-01T00:00:00Z old")
        rows = timeline_builder.build_timeline([entry], sample_manifest)
        assert len(rows) == 1 and rows[0].source_line == 10


class TestConflictGaps:
    def test_only_conflicts_needing_review_become_gaps(self):
        from types import SimpleNamespace

        from ir_agent.analysis.timeline import conflict_gap_specs

        claims = [SimpleNamespace(claim_id="CLM-1", supporting_evidence=["EV-1"])]
        conflicts = [
            {"evidence_ids": ["EV-1"], "host": "host01", "requires_review": True,
             "event_times": ["2025-05-10T05:00:00Z", "2025-05-10T06:00:00Z"]},
            {"evidence_ids": ["EV-2"], "host": "host01", "requires_review": True,
             "event_times": ["a", "b"]},
            {"evidence_ids": ["EV-1", "EV-3"], "requires_review": False},
        ]
        specs = conflict_gap_specs(conflicts, claims)
        assert [s["related_claim_id"] for s in specs] == ["CLM-1", "CASE-SCOPE"]
        assert specs[0]["gap_type"] == "contradictory_evidence"


# --- Tests for Requirement 10.3: ATT&CK all 12 tactics ---


class TestATTCKMapperTacticCoverage:
    """Tests that ATTCKMapper covers all 12 ATT&CK tactics (Req 10.3)."""

    def test_all_12_tactics_in_supported_list(self, attack_mapper: ATTCKMapper):
        """ATTCKMapper.supported_tactics contains all 12 required tactics."""
        expected_tactics = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ]
        for tactic in expected_tactics:
            assert tactic in attack_mapper.supported_tactics

    def test_supported_tactics_count(self, attack_mapper: ATTCKMapper):
        """ATTCKMapper has exactly 12 supported tactics."""
        assert len(attack_mapper.supported_tactics) == 12

    def test_attack_tactics_constant_has_12_entries(self):
        """Module-level ATTACK_TACTICS constant has all 12 entries."""
        assert len(ATTACK_TACTICS) == 12

    def test_initial_access_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning phishing maps to Initial Access tactic."""
        candidate = self._make_candidate(
            observed_fact="User received spearphishing email with malicious attachment",
            interpretation="Possible initial access via phishing",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Initial Access" in tactics

    def test_execution_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning powershell maps to Execution tactic."""
        candidate = self._make_candidate(
            observed_fact="powershell.exe executed encoded command",
            interpretation="Attacker used PowerShell for execution",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Execution" in tactics

    def test_persistence_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning registry run key maps to Persistence tactic."""
        candidate = self._make_candidate(
            observed_fact="New registry run key added for autorun on boot",
            interpretation="Persistence mechanism established",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Persistence" in tactics

    def test_privilege_escalation_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning UAC bypass maps to Privilege Escalation."""
        candidate = self._make_candidate(
            observed_fact="UAC bypass technique detected via access token manipulation",
            interpretation="Privilege escalation attempted",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Privilege Escalation" in tactics

    def test_defense_evasion_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning obfuscation maps to Defense Evasion."""
        candidate = self._make_candidate(
            observed_fact="PowerShell command uses base64 encoded payload",
            interpretation="Obfuscation to evade detection",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Defense Evasion" in tactics

    def test_credential_access_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning mimikatz maps to Credential Access."""
        candidate = self._make_candidate(
            observed_fact="mimikatz executed to dump credentials from lsass",
            interpretation="Credential dumping via mimikatz",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Credential Access" in tactics

    def test_discovery_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning network scan maps to Discovery."""
        candidate = self._make_candidate(
            observed_fact="nmap network scan detected on internal subnet",
            interpretation="Attacker performing network enumeration",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Discovery" in tactics

    def test_lateral_movement_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning psexec maps to Lateral Movement."""
        candidate = self._make_candidate(
            observed_fact="PsExec used for remote execution on host02",
            interpretation="Lateral movement using PsExec",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Lateral Movement" in tactics

    def test_collection_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning archive creation maps to Collection."""
        candidate = self._make_candidate(
            observed_fact="Data archived to zip file before transfer",
            interpretation="Attacker collecting data for exfiltration",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Collection" in tactics

    def test_command_and_control_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning C2 beacon maps to Command and Control."""
        candidate = self._make_candidate(
            observed_fact="HTTP beacon callback detected to external IP",
            interpretation="Command and control communication established",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Command and Control" in tactics

    def test_exfiltration_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning data exfiltration maps to Exfiltration."""
        candidate = self._make_candidate(
            observed_fact="Large data upload to external cloud storage mega.nz",
            interpretation="Data exfiltration to cloud storage",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Exfiltration" in tactics

    def test_impact_mapping(self, attack_mapper: ATTCKMapper):
        """Evidence mentioning ransomware maps to Impact."""
        candidate = self._make_candidate(
            observed_fact="Ransomware deployed, files encrypted across network",
            interpretation="Impact via ransomware encryption",
        )
        mappings = attack_mapper.map_evidence_candidate(candidate, {})
        tactics = [m.tactic for m in mappings]
        assert "Impact" in tactics

    @staticmethod
    def _make_candidate(
        observed_fact: str,
        interpretation: str,
    ) -> EvidenceCandidate:
        """Helper to create an EvidenceCandidate for ATT&CK mapping tests."""
        return EvidenceCandidate(
            candidate_id="CAND-TEST-001",
            source_refs=[
                SourceReference(
                    source_ref_id="SR-001",
                    source_file_id="FI-001",
                    source_path="host01/syslog.log",
                    source_lines=(1, 5),
                    excerpt="test excerpt",
                    excerpt_sha256="abc123",
                )
            ],
            observed_event={},
            observed_fact=observed_fact,
            interpretation=interpretation,
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.PROBABLE,
        )
