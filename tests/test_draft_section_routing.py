"""Chapter-3 routing: an ATT&CK mapping is reported in its tactic's section."""

from __future__ import annotations

from ir_agent.reporting import report_template
from ir_agent.reporting.draft_lint import SECTION_HEADINGS, check_carry_over

CLAIM = {
    "claim_id": "CLM-1",
    "report_section": "3.7",
    "supporting_evidence": ["EV-007", "EV-008"],
    "attack_mappings": [
        {"tactic": "Persistence", "supporting_evidence": ["EV-007"]},
        {"tactic": "Defense Evasion", "supporting_evidence": ["EV-008"]},
        {"tactic": "Execution", "supporting_evidence": ["EV-008"]},
    ],
}


def _draft(sections: dict[str, str]) -> str:
    return "\n\n".join(f"{h}\n\n{sections.get(sec, '')}" for sec, h in SECTION_HEADINGS.items())


def test_cross_section_mappings_skip_own_and_auxiliary_tactics():
    assert report_template.cross_section_mappings(CLAIM) == {"3.4": ["EV-007"]}
    assert report_template.cross_section_mappings({**CLAIM, "report_section": "context"}) == {}


def test_mapping_not_cited_in_its_section_fails():
    draft = _draft({"3.7": "ログ削除が確認されました（証拠ID: EV-007, EV-008）。"})
    failures = check_carry_over(draft, {"approved_claims": [CLAIM]})
    assert len(failures) == 1 and "3.4" in failures[0] and "EV-007" in failures[0]


def test_mapping_cited_in_its_section_passes():
    draft = _draft({"3.4": "アカウントの作成が確認されました（証拠ID: EV-007）。",
                    "3.7": "ログ削除が確認されました（証拠ID: EV-008）。"})
    assert check_carry_over(draft, {"approved_claims": [CLAIM]}) == []
