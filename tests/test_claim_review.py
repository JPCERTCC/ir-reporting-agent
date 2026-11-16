"""Unit tests for ClaimReviewService.

Validates Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7:
- Generate Claim_Review_Document in Markdown (12.1)
- Include all claim fields with headings in review_language (12.2)
- Approved claims marked as approved (12.3)
- Rejected claims excluded from report (12.4)
- Edited claims preserve original and store edited version (12.5)
- Only approved claims used in report generation (12.6)
- Pending/rejected/superseded claims excluded (12.7)
"""

import json
from pathlib import Path

import pytest

from ir_agent.analysis.claim_review import (
    ClaimDecision,
    ClaimDecisionStatus,
    ClaimReviewService,
)
from ir_agent.models.analysis import Claim
from ir_agent.models.enums import ClaimCategory, ConfidenceLevel
from ir_agent.models.events import ATTCKMapping


# --- Fixtures ---


def _make_claim(
    claim_id: str = "CLM-001",
    claim_text: str = "Lateral movement was detected from host01 to host02",
    category: ClaimCategory = ClaimCategory.INTERPRETATION,
    confidence: ConfidenceLevel = ConfidenceLevel.PROBABLE,
    review_status: str = "pending",
) -> Claim:
    """Create a test Claim."""
    return Claim(
        claim_id=claim_id,
        report_section="analysis",
        claim_text=claim_text,
        claim_category=category,
        confidence_level=confidence,
        confidence_basis="Based on 2 independent sources with corroboration",
        supporting_evidence=["EV-001", "EV-002"],
        counter_evidence=["EV-003"],
        limitations=["Single host observation"],
        missing_evidence=["Firewall logs from host02"],
        recommended_expressions=["可能性が高い", "likely"],
        prohibited_expressions=["確認された", "confirmed"],
        review_status=review_status,
        attack_mappings=[
            ATTCKMapping(
                tactic="Lateral Movement",
                technique_id="T1021.002",
                technique_name="Remote Services: SMB/Windows Admin Shares",
                confidence=ConfidenceLevel.PROBABLE,
                mapping_reason="SMB connection observed",
            )
        ],
    )


@pytest.fixture
def service() -> ClaimReviewService:
    """Create a ClaimReviewService instance."""
    return ClaimReviewService()


@pytest.fixture
def sample_claims() -> list[Claim]:
    """Create a list of sample claims for testing."""
    return [
        _make_claim("CLM-001", "Lateral movement detected"),
        _make_claim(
            "CLM-002",
            "Data exfiltration via sftp",
            category=ClaimCategory.DATA_EXFILTRATION_ASSESSMENT,
            confidence=ConfidenceLevel.POSSIBLE,
        ),
    ]


# --- Test: Requirement 12.1 - Generate Claim Review Document ---


class TestGenerateClaimReviewDoc:
    """Tests for generate_claim_review_doc (Requirements 12.1, 12.2)."""

    def test_generates_markdown_file(
        self, service: ClaimReviewService, sample_claims: list[Claim], tmp_path: Path
    ):
        """Requirement 12.1: Generates a Markdown review document."""
        output_path = tmp_path / "reviews" / "claim_review_001.md"
        service.generate_claim_review_doc(sample_claims, output_path)

        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")
        assert content.startswith("# ")

    def test_japanese_headings_when_ja(
        self, service: ClaimReviewService, sample_claims: list[Claim], tmp_path: Path
    ):
        """Requirement 12.2: Section headings rendered in Japanese when review_language is 'ja'."""
        output_path = tmp_path / "claim_review.md"
        service.generate_claim_review_doc(sample_claims, output_path, review_language="ja")

        content = output_path.read_text(encoding="utf-8")

        # Japanese headings present
        assert "### 信頼度" in content
        assert "### 支持証拠" in content
        assert "### 制約・不足情報" in content
        assert "### 推奨表現" in content
        assert "### 禁止表現" in content
        assert "### 判定" in content

    def test_english_headings_when_en(
        self, service: ClaimReviewService, sample_claims: list[Claim], tmp_path: Path
    ):
        """Section headings rendered in English when review_language is 'en'."""
        output_path = tmp_path / "claim_review.md"
        service.generate_claim_review_doc(sample_claims, output_path, review_language="en")

        content = output_path.read_text(encoding="utf-8")

        assert "### Confidence" in content
        assert "### Supporting Evidence" in content
        assert "### Limitations" in content
        assert "### Recommended Expressions" in content
        assert "### Prohibited Expressions" in content
        assert "### Decision" in content

    def test_yaml_keys_remain_english(
        self, service: ClaimReviewService, sample_claims: list[Claim], tmp_path: Path
    ):
        """Requirement 12.2: YAML decision block keys remain in English."""
        output_path = tmp_path / "claim_review.md"
        service.generate_claim_review_doc(sample_claims, output_path, review_language="ja")

        content = output_path.read_text(encoding="utf-8")

        assert "item_id:" in content
        assert "item_type: claim" in content
        assert "decision: pending" in content
        assert "decision_reason:" in content
        assert "analyst_id:" in content

    def test_includes_all_claim_fields(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """Requirement 12.2: All required claim fields are included."""
        claim = _make_claim()
        output_path = tmp_path / "claim_review.md"
        service.generate_claim_review_doc([claim], output_path)

        content = output_path.read_text(encoding="utf-8")

        # Required fields from Requirement 12.2
        assert "CLM-001" in content
        assert "analysis" in content  # report_section
        assert "Lateral movement" in content  # claim_text
        assert "`probable`" in content  # confidence_level
        assert "`EV-001`" in content  # supporting_evidence
        assert "`EV-003`" in content  # counter_evidence
        assert "Single host observation" in content  # limitations
        assert "Firewall logs from host02" in content  # missing_evidence
        assert "可能性が高い" in content  # recommended_expressions
        assert "確認された" in content  # prohibited_expressions

    def test_includes_attack_mappings(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """ATT&CK mappings are included in the review document."""
        claim = _make_claim()
        output_path = tmp_path / "claim_review.md"
        service.generate_claim_review_doc([claim], output_path)

        content = output_path.read_text(encoding="utf-8")

        assert "T1021.002" in content
        assert "Lateral Movement" in content

    def test_each_claim_has_yaml_decision_block(
        self, service: ClaimReviewService, sample_claims: list[Claim], tmp_path: Path
    ):
        """Each claim has exactly one YAML decision block."""
        output_path = tmp_path / "claim_review.md"
        service.generate_claim_review_doc(sample_claims, output_path)

        content = output_path.read_text(encoding="utf-8")

        # Count YAML blocks
        yaml_block_count = content.count("```yaml")
        assert yaml_block_count == len(sample_claims)


# --- Test: Parse Claim Review Document ---


class TestParseClaimReviewDoc:
    """Tests for parse_claim_review_doc."""

    def test_parses_yaml_decision_blocks(
        self, service: ClaimReviewService, sample_claims: list[Claim], tmp_path: Path
    ):
        """Parses YAML decision blocks from generated document."""
        output_path = tmp_path / "claim_review.md"
        service.generate_claim_review_doc(sample_claims, output_path)

        decisions = service.parse_claim_review_doc(output_path)

        assert len(decisions) == 2
        assert all(isinstance(d, ClaimDecision) for d in decisions)
        assert decisions[0].item_id == "CLM-001"
        assert decisions[1].item_id == "CLM-002"

    def test_parses_modified_decisions(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """Parses decisions after analyst has edited the review document."""
        review_content = """# Claim レビュー

## CLM-001

### 判定

```yaml
item_id: CLM-001
item_type: claim
decision: approved
decision_reason: "Evidence is sufficient"
analyst_id: analyst-01
edited_claim_text: ""
downgraded_confidence: ""
```

---

## CLM-002

### 判定

```yaml
item_id: CLM-002
item_type: claim
decision: rejected
decision_reason: "Insufficient evidence"
analyst_id: analyst-01
edited_claim_text: ""
downgraded_confidence: ""
```
"""
        review_path = tmp_path / "claim_review.md"
        review_path.write_text(review_content, encoding="utf-8")

        decisions = service.parse_claim_review_doc(review_path)

        assert len(decisions) == 2
        assert decisions[0].decision == ClaimDecisionStatus.APPROVED
        assert decisions[0].decision_reason == "Evidence is sufficient"
        assert decisions[1].decision == ClaimDecisionStatus.REJECTED

    def test_parsing_is_language_agnostic(
        self, service: ClaimReviewService, sample_claims: list[Claim], tmp_path: Path
    ):
        """Parser extracts YAML blocks regardless of prose language."""
        # Generate in Japanese
        ja_path = tmp_path / "ja_review.md"
        service.generate_claim_review_doc(sample_claims, ja_path, review_language="ja")

        # Generate in English
        en_path = tmp_path / "en_review.md"
        service.generate_claim_review_doc(sample_claims, en_path, review_language="en")

        ja_decisions = service.parse_claim_review_doc(ja_path)
        en_decisions = service.parse_claim_review_doc(en_path)

        # Both should extract the same decision blocks
        assert len(ja_decisions) == len(en_decisions)
        assert ja_decisions[0].item_id == en_decisions[0].item_id

    def test_ignores_non_decision_yaml_blocks(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """Non-decision YAML blocks (without item_id/decision) are ignored."""
        review_content = """# Review

```yaml
some_other_key: value
not_a_decision: true
```

```yaml
item_id: CLM-001
item_type: claim
decision: approved
decision_reason: ""
analyst_id: ""
```
"""
        review_path = tmp_path / "review.md"
        review_path.write_text(review_content, encoding="utf-8")

        decisions = service.parse_claim_review_doc(review_path)

        assert len(decisions) == 1
        assert decisions[0].item_id == "CLM-001"

    def test_case_insensitive_decision_values(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """Decision values are accepted case-insensitively."""
        review_content = """# Review

```yaml
item_id: CLM-001
item_type: claim
decision: APPROVED
decision_reason: ""
analyst_id: ""
```
"""
        review_path = tmp_path / "review.md"
        review_path.write_text(review_content, encoding="utf-8")

        decisions = service.parse_claim_review_doc(review_path)

        assert decisions[0].decision == ClaimDecisionStatus.APPROVED


# --- Test: Apply Claim Decisions ---


class TestApplyClaimDecisions:
    """Tests for apply_claim_decisions (Requirements 12.3, 12.4, 12.5)."""

    def _write_claims_jsonl(self, claims: list[Claim], path: Path) -> None:
        """Write claims to a JSONL file for testing."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for claim in claims:
                f.write(claim.model_dump_json() + "\n")

    def _read_claims_jsonl(self, path: Path) -> list[Claim]:
        """Read claims from a JSONL file."""
        claims = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    claims.append(Claim.model_validate(json.loads(stripped)))
        return claims

    def test_approved_decision_sets_status(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """Requirement 12.3: Approved claim marked as approved."""
        claims_path = tmp_path / "claims.jsonl"
        self._write_claims_jsonl([_make_claim("CLM-001")], claims_path)

        decisions = [
            ClaimDecision(
                item_id="CLM-001",
                item_type="claim",
                decision=ClaimDecisionStatus.APPROVED,
                decision_reason="Sufficient evidence",
                analyst_id="analyst-01",
            )
        ]

        service.apply_claim_decisions(decisions, claims_path)

        updated = self._read_claims_jsonl(claims_path)
        assert updated[0].review_status == "approved"

    def test_rejected_decision_sets_status(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """Requirement 12.4: Rejected claim marked as rejected."""
        claims_path = tmp_path / "claims.jsonl"
        self._write_claims_jsonl([_make_claim("CLM-001")], claims_path)

        decisions = [
            ClaimDecision(
                item_id="CLM-001",
                item_type="claim",
                decision=ClaimDecisionStatus.REJECTED,
                decision_reason="Evidence too weak",
                analyst_id="analyst-01",
            )
        ]

        service.apply_claim_decisions(decisions, claims_path)

        updated = self._read_claims_jsonl(claims_path)
        assert updated[0].review_status == "rejected"

    def test_edited_decision_preserves_original(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """Requirement 12.5: Edited claim preserves original and stores edited version."""
        original_text = "Lateral movement was detected"
        claims_path = tmp_path / "claims.jsonl"
        self._write_claims_jsonl(
            [_make_claim("CLM-001", claim_text=original_text)], claims_path
        )

        decisions = [
            ClaimDecision(
                item_id="CLM-001",
                item_type="claim",
                decision=ClaimDecisionStatus.EDITED,
                decision_reason="Clarified wording",
                analyst_id="analyst-01",
                edited_claim_text="Lateral movement was observed from host01 to host02 via SMB",
            )
        ]

        service.apply_claim_decisions(decisions, claims_path)

        updated = self._read_claims_jsonl(claims_path)
        assert updated[0].original_claim_text == original_text
        assert updated[0].approved_claim_text == (
            "Lateral movement was observed from host01 to host02 via SMB"
        )
        assert updated[0].review_status == "edited"

    def test_downgraded_decision_changes_confidence(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """Downgraded decision changes confidence_level."""
        claims_path = tmp_path / "claims.jsonl"
        self._write_claims_jsonl(
            [_make_claim("CLM-001", confidence=ConfidenceLevel.PROBABLE)],
            claims_path,
        )

        decisions = [
            ClaimDecision(
                item_id="CLM-001",
                item_type="claim",
                decision=ClaimDecisionStatus.DOWNGRADED,
                decision_reason="Evidence is weaker than initially assessed",
                analyst_id="analyst-01",
                downgraded_confidence="possible",
            )
        ]

        service.apply_claim_decisions(decisions, claims_path)

        updated = self._read_claims_jsonl(claims_path)
        assert updated[0].confidence_level == ConfidenceLevel.POSSIBLE
        assert updated[0].review_status == "downgraded"

    def test_needs_more_context_sets_status(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """needs_more_context decision sets review_status."""
        claims_path = tmp_path / "claims.jsonl"
        self._write_claims_jsonl([_make_claim("CLM-001")], claims_path)

        decisions = [
            ClaimDecision(
                item_id="CLM-001",
                item_type="claim",
                decision=ClaimDecisionStatus.NEEDS_MORE_CONTEXT,
                decision_reason="Need firewall logs",
                analyst_id="analyst-01",
            )
        ]

        service.apply_claim_decisions(decisions, claims_path)

        updated = self._read_claims_jsonl(claims_path)
        assert updated[0].review_status == "needs_more_context"

    def test_unmatched_decisions_leave_claims_unchanged(
        self, service: ClaimReviewService, tmp_path: Path
    ):
        """Claims without matching decisions remain unchanged."""
        claims_path = tmp_path / "claims.jsonl"
        self._write_claims_jsonl([_make_claim("CLM-001")], claims_path)

        # Decision for a different claim
        decisions = [
            ClaimDecision(
                item_id="CLM-999",
                item_type="claim",
                decision=ClaimDecisionStatus.APPROVED,
                analyst_id="analyst-01",
            )
        ]

        service.apply_claim_decisions(decisions, claims_path)

        updated = self._read_claims_jsonl(claims_path)
        assert updated[0].review_status == "pending"


# --- Test: Get Approved Claims ---


class TestGetApprovedClaims:
    """Tests for get_approved_claims (Requirements 12.6, 12.7)."""

    def test_returns_only_approved_claims(self, tmp_path: Path):
        """Requirement 12.6: Only approved claims returned."""
        claims_path = tmp_path / "claims.jsonl"
        claims = [
            _make_claim("CLM-001", review_status="approved"),
            _make_claim("CLM-002", review_status="rejected"),
            _make_claim("CLM-003", review_status="pending"),
            _make_claim("CLM-004", review_status="approved"),
        ]

        with open(claims_path, "w", encoding="utf-8") as f:
            for claim in claims:
                f.write(claim.model_dump_json() + "\n")

        service = ClaimReviewService(claims_path=claims_path)
        approved = service.get_approved_claims()

        assert len(approved) == 2
        assert all(c.review_status == "approved" for c in approved)
        claim_ids = [c.claim_id for c in approved]
        assert "CLM-001" in claim_ids
        assert "CLM-004" in claim_ids

    def test_excludes_pending_rejected_and_downgraded(self, tmp_path: Path):
        """Requirement 12.7: Pending, rejected claims excluded."""
        claims_path = tmp_path / "claims.jsonl"
        claims = [
            _make_claim("CLM-001", review_status="pending"),
            _make_claim("CLM-002", review_status="rejected"),
            _make_claim("CLM-003", review_status="downgraded"),
            _make_claim("CLM-004", review_status="needs_more_context"),
        ]

        with open(claims_path, "w", encoding="utf-8") as f:
            for claim in claims:
                f.write(claim.model_dump_json() + "\n")

        service = ClaimReviewService(claims_path=claims_path)
        approved = service.get_approved_claims()

        assert len(approved) == 0

    def test_raises_if_no_claims_path(self):
        """Raises ValueError if claims_path not provided."""
        service = ClaimReviewService()

        with pytest.raises(ValueError, match="claims_path must be provided"):
            service.get_approved_claims()

    def test_returns_empty_for_nonexistent_file(self, tmp_path: Path):
        """Returns empty list if claims file doesn't exist."""
        claims_path = tmp_path / "nonexistent.jsonl"
        service = ClaimReviewService(claims_path=claims_path)

        approved = service.get_approved_claims()
        assert approved == []


# --- Test: Roundtrip (generate → parse → apply) ---


class TestRoundtrip:
    """Integration test: generate, edit, parse, apply full cycle."""

    def test_full_roundtrip(self, tmp_path: Path):
        """Full cycle: generate doc, simulate analyst edit, parse, apply decisions."""
        service = ClaimReviewService()
        claims = [
            _make_claim("CLM-001", "Lateral movement detected"),
            _make_claim("CLM-002", "Data exfiltration observed"),
        ]

        # Step 1: Generate review document
        review_path = tmp_path / "claim_review.md"
        service.generate_claim_review_doc(claims, review_path, review_language="ja")

        # Step 2: Simulate analyst editing the YAML blocks
        content = review_path.read_text(encoding="utf-8")
        content = content.replace(
            "item_id: CLM-001\nitem_type: claim\ndecision: pending",
            "item_id: CLM-001\nitem_type: claim\ndecision: approved",
        )
        content = content.replace(
            "item_id: CLM-002\nitem_type: claim\ndecision: pending",
            "item_id: CLM-002\nitem_type: claim\ndecision: rejected",
        )
        review_path.write_text(content, encoding="utf-8")

        # Step 3: Parse decisions
        decisions = service.parse_claim_review_doc(review_path)
        assert len(decisions) == 2
        assert decisions[0].decision == ClaimDecisionStatus.APPROVED
        assert decisions[1].decision == ClaimDecisionStatus.REJECTED

        # Step 4: Apply decisions to claims
        claims_path = tmp_path / "claims.jsonl"
        with open(claims_path, "w", encoding="utf-8") as f:
            for claim in claims:
                f.write(claim.model_dump_json() + "\n")

        service.apply_claim_decisions(decisions, claims_path)

        # Step 5: Verify results
        with open(claims_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        updated_claims = [Claim.model_validate(json.loads(line)) for line in lines]
        assert updated_claims[0].review_status == "approved"
        assert updated_claims[1].review_status == "rejected"
