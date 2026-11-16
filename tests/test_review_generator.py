"""Unit tests for ReviewDocumentGenerator.

Validates Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
- 7.1: Generate Review_Document in Markdown format using review_language
- 7.2: Present each candidate with required fields; YAML keys/enums in English
- 7.3: Analyst marks candidate as approved -> promote to ledger
- 7.4: Analyst marks candidate as rejected -> exclude from ledger
- 7.5: Analyst edits a candidate -> update before promotion
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ir_agent.evidence.review_generator import (
    ReviewDecision,
    ReviewDecisionStatus,
    ReviewDocumentGenerator,
)
from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceCandidate


def _make_source_ref(
    source_ref_id: str = "ref-001",
    source_file_id: str = "file-001",
    source_path: str = "/artifacts/host01/syslog.log",
    source_lines: tuple[int, int] = (10, 15),
    excerpt: str = "Jan 15 14:23:01 host01 sshd[1234]: Accepted publickey for admin",
    excerpt_sha256: str = "abc123def456",
) -> SourceReference:
    return SourceReference(
        source_ref_id=source_ref_id,
        source_file_id=source_file_id,
        source_path=source_path,
        source_lines=source_lines,
        excerpt=excerpt,
        excerpt_sha256=excerpt_sha256,
    )


def _make_candidate(
    candidate_id: str = "EC-001",
    source_refs: list[SourceReference] | None = None,
    observed_fact: str = "SSH login from external IP 203.0.113.5 to host01",
    interpretation: str = "Possible unauthorized external access",
    observed_fact_confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
    interpretation_confidence: ConfidenceLevel = ConfidenceLevel.PROBABLE,
) -> EvidenceCandidate:
    if source_refs is None:
        source_refs = [_make_source_ref()]
    return EvidenceCandidate(
        candidate_id=candidate_id,
        source_refs=source_refs,
        observed_event={"type": "ssh_login", "host": "host01"},
        observed_fact=observed_fact,
        interpretation=interpretation,
        observed_fact_confidence=observed_fact_confidence,
        interpretation_confidence=interpretation_confidence,
    )


@pytest.fixture
def generator() -> ReviewDocumentGenerator:
    return ReviewDocumentGenerator()


@pytest.fixture
def sample_candidates() -> list[EvidenceCandidate]:
    return [
        _make_candidate(candidate_id="EC-001"),
        _make_candidate(
            candidate_id="EC-002",
            source_refs=[
                _make_source_ref(
                    source_ref_id="ref-002",
                    source_file_id="file-002",
                    source_lines=(50, 55),
                    excerpt="Process cmd.exe spawned by winword.exe",
                )
            ],
            observed_fact="cmd.exe spawned by winword.exe on WS01",
            interpretation="Possible malicious macro execution",
            observed_fact_confidence=ConfidenceLevel.CONFIRMED,
            interpretation_confidence=ConfidenceLevel.POSSIBLE,
        ),
    ]


class TestGenerateReviewDoc:
    """Test generate_review_doc output structure."""

    def test_generates_markdown_file(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Req 7.1: Generate Review_Document in Markdown format."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert content.startswith("# ")

    def test_japanese_headings(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Req 7.2: Section headings rendered in Japanese when review_language='ja'."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "### 概要" in content
        assert "### 観測事実" in content
        assert "### 解釈" in content
        assert "### 信頼度" in content
        assert "### 制約・不足情報" in content
        assert "### 推奨表現" in content
        assert "### 禁止表現" in content
        assert "### 出典" in content
        assert "### 判定" in content

    def test_english_headings(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Section headings rendered in English when review_language='en'."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="en")
        content = output.read_text(encoding="utf-8")

        assert "### Summary" in content
        assert "### Observed Fact" in content
        assert "### Interpretation" in content
        assert "### Confidence" in content
        assert "### Decision" in content

    def test_yaml_block_keys_in_english(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Req 7.2: YAML decision block keys and enum values remain in English."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "item_id:" in content
        assert "item_type: evidence_candidate" in content
        assert "decision: pending" in content
        assert "decision_reason:" in content
        assert "analyst_id:" in content

    def test_candidate_id_in_output(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Req 7.2: Each candidate has candidate_id in the document."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "EC-001" in content
        assert "EC-002" in content

    def test_observed_fact_in_output(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Req 7.2: observed_fact text appears in the document."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "SSH login from external IP 203.0.113.5 to host01" in content
        assert "cmd.exe spawned by winword.exe on WS01" in content

    def test_interpretation_in_output(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Req 7.2: interpretation text appears in the document."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "Possible unauthorized external access" in content
        assert "Possible malicious macro execution" in content

    def test_confidence_levels_in_output(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Req 7.2: confidence levels shown in the document."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "observed_fact_confidence: confirmed" in content
        assert "interpretation_confidence: probable" in content
        assert "interpretation_confidence: possible" in content

    def test_source_info_in_output(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Req 7.2: source file and lines appear in the document."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "file-001" in content
        assert "10-15" in content
        assert "file-002" in content
        assert "50-55" in content

    def test_excerpt_in_output(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Req 7.2: source excerpt appears in the document."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "Accepted publickey for admin" in content

    def test_empty_candidates_list(
        self, generator: ReviewDocumentGenerator, tmp_path: Path
    ) -> None:
        """Empty candidates list produces a valid document with just the title."""
        output = tmp_path / "evidence_review.md"
        generator.generate_review_doc([], output, review_language="ja")
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "# エビデンス候補レビュー" in content

    def test_creates_parent_directories(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Output path parent directories are created if missing."""
        output = tmp_path / "nested" / "dir" / "review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        assert output.exists()


class TestParseReviewDoc:
    """Test parse_review_doc extracting YAML decision blocks."""

    def test_parse_pending_decisions(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Parse freshly generated doc with pending decisions."""
        output = tmp_path / "review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        decisions = generator.parse_review_doc(output)

        assert len(decisions) == 2
        assert decisions[0].item_id == "EC-001"
        assert decisions[0].decision == ReviewDecisionStatus.PENDING
        assert decisions[1].item_id == "EC-002"

    def test_parse_approved_decision(
        self, generator: ReviewDocumentGenerator, tmp_path: Path
    ) -> None:
        """Req 7.3: Parse an approved decision from the document."""
        doc_content = """# Review

## EC-001

### 判定

```yaml
item_id: EC-001
item_type: evidence_candidate
decision: approved
decision_reason: "Evidence is clear and well-sourced"
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        decisions = generator.parse_review_doc(review_path)

        assert len(decisions) == 1
        assert decisions[0].item_id == "EC-001"
        assert decisions[0].decision == ReviewDecisionStatus.APPROVED
        assert decisions[0].decision_reason == "Evidence is clear and well-sourced"
        assert decisions[0].analyst_id == "analyst-01"

    def test_parse_rejected_decision(
        self, generator: ReviewDocumentGenerator, tmp_path: Path
    ) -> None:
        """Req 7.4: Parse a rejected decision from the document."""
        doc_content = """# Review

```yaml
item_id: EC-002
item_type: evidence_candidate
decision: rejected
decision_reason: "Insufficient evidence for this claim"
analyst_id: analyst-02
```
"""
        review_path = tmp_path / "review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        decisions = generator.parse_review_doc(review_path)

        assert len(decisions) == 1
        assert decisions[0].decision == ReviewDecisionStatus.REJECTED
        assert decisions[0].decision_reason == "Insufficient evidence for this claim"

    def test_parse_edited_decision(
        self, generator: ReviewDocumentGenerator, tmp_path: Path
    ) -> None:
        """Req 7.5: Parse an edited decision from the document."""
        doc_content = """# Review

```yaml
item_id: EC-003
item_type: evidence_candidate
decision: edited
decision_reason: "Updated interpretation to be more specific"
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        decisions = generator.parse_review_doc(review_path)

        assert len(decisions) == 1
        assert decisions[0].decision == ReviewDecisionStatus.EDITED

    def test_parse_needs_more_context(
        self, generator: ReviewDocumentGenerator, tmp_path: Path
    ) -> None:
        """Parse a needs_more_context decision."""
        doc_content = """# Review

```yaml
item_id: EC-004
item_type: evidence_candidate
decision: needs_more_context
decision_reason: "Need additional log data from host02"
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        decisions = generator.parse_review_doc(review_path)

        assert len(decisions) == 1
        assert decisions[0].decision == ReviewDecisionStatus.NEEDS_MORE_CONTEXT

    def test_parse_ignores_prose(
        self, generator: ReviewDocumentGenerator, tmp_path: Path
    ) -> None:
        """Parser ignores all prose and only extracts YAML decision blocks."""
        doc_content = """# エビデンス候補レビュー

## EC-001

### 概要

- candidate_id: `EC-001`
- source_refs: file-001

### 観測事実

SSH login observed from external IP.

### 解釈

This is possibly an unauthorized access attempt.

### 判定

```yaml
item_id: EC-001
item_type: evidence_candidate
decision: approved
decision_reason: "Confirmed by analyst"
analyst_id: analyst-01
```

---

Some more Japanese prose here that should be completely ignored.
"""
        review_path = tmp_path / "review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        decisions = generator.parse_review_doc(review_path)

        assert len(decisions) == 1
        assert decisions[0].item_id == "EC-001"
        assert decisions[0].decision == ReviewDecisionStatus.APPROVED

    def test_parse_multiple_decisions(
        self, generator: ReviewDocumentGenerator, tmp_path: Path
    ) -> None:
        """Parse multiple decisions from a single document."""
        doc_content = """# Review

```yaml
item_id: EC-001
item_type: evidence_candidate
decision: approved
decision_reason: ""
analyst_id: analyst-01
```

Some prose in between...

```yaml
item_id: EC-002
item_type: evidence_candidate
decision: rejected
decision_reason: "Not relevant"
analyst_id: analyst-01
```

```yaml
item_id: EC-003
item_type: evidence_candidate
decision: edited
decision_reason: "Corrected interpretation"
analyst_id: analyst-02
```
"""
        review_path = tmp_path / "review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        decisions = generator.parse_review_doc(review_path)

        assert len(decisions) == 3
        assert decisions[0].decision == ReviewDecisionStatus.APPROVED
        assert decisions[1].decision == ReviewDecisionStatus.REJECTED
        assert decisions[2].decision == ReviewDecisionStatus.EDITED

    def test_parse_ignores_non_decision_yaml(
        self, generator: ReviewDocumentGenerator, tmp_path: Path
    ) -> None:
        """YAML blocks without item_id/decision are ignored."""
        doc_content = """# Review

```yaml
some_config: value
another_key: 123
```

```yaml
item_id: EC-001
item_type: evidence_candidate
decision: approved
decision_reason: ""
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        decisions = generator.parse_review_doc(review_path)

        assert len(decisions) == 1
        assert decisions[0].item_id == "EC-001"

    def test_parse_file_not_found(
        self, generator: ReviewDocumentGenerator, tmp_path: Path
    ) -> None:
        """FileNotFoundError raised when review file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            generator.parse_review_doc(tmp_path / "nonexistent.md")

    def test_parse_language_agnostic(
        self, generator: ReviewDocumentGenerator, tmp_path: Path
    ) -> None:
        """Parsing works regardless of surrounding language (Japanese or English)."""
        doc_content = """# エビデンス候補レビュー

## EC-001

### 判定

```yaml
item_id: EC-001
item_type: evidence_candidate
decision: approved
decision_reason: "確認済み"
analyst_id: analyst-01
```

---

## EC-002

### Decision

```yaml
item_id: EC-002
item_type: evidence_candidate
decision: rejected
decision_reason: "Not valid"
analyst_id: analyst-02
```
"""
        review_path = tmp_path / "review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        decisions = generator.parse_review_doc(review_path)

        assert len(decisions) == 2
        assert decisions[0].item_id == "EC-001"
        assert decisions[0].decision == ReviewDecisionStatus.APPROVED
        assert decisions[1].item_id == "EC-002"
        assert decisions[1].decision == ReviewDecisionStatus.REJECTED


class TestReviewDecisionModel:
    """Test the Pydantic ReviewDecision model validation."""

    def test_valid_decision(self) -> None:
        d = ReviewDecision(
            item_id="EC-001",
            item_type="evidence_candidate",
            decision=ReviewDecisionStatus.APPROVED,
            decision_reason="Looks good",
            analyst_id="analyst-01",
        )
        assert d.item_id == "EC-001"
        assert d.decision == ReviewDecisionStatus.APPROVED

    def test_case_insensitive_decision(self) -> None:
        """Decision values accepted case-insensitively."""
        d = ReviewDecision(
            item_id="EC-001",
            decision="Approved",  # type: ignore[arg-type]
        )
        assert d.decision == ReviewDecisionStatus.APPROVED

    def test_default_values(self) -> None:
        """Defaults are applied when fields omitted."""
        d = ReviewDecision(item_id="EC-001")
        assert d.item_type == "evidence_candidate"
        assert d.decision == ReviewDecisionStatus.PENDING
        assert d.decision_reason == ""
        assert d.analyst_id == ""

    def test_invalid_decision_value(self) -> None:
        """Invalid decision value raises validation error."""
        with pytest.raises(Exception):
            ReviewDecision(
                item_id="EC-001",
                decision="invalid_status",  # type: ignore[arg-type]
            )


class TestRoundtrip:
    """Test generate -> parse roundtrip."""

    def test_roundtrip_preserves_candidate_ids(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Generated doc can be parsed back to extract all candidate ids."""
        output = tmp_path / "review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        decisions = generator.parse_review_doc(output)

        item_ids = [d.item_id for d in decisions]
        assert "EC-001" in item_ids
        assert "EC-002" in item_ids

    def test_roundtrip_all_pending(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """All decisions in freshly generated doc are 'pending'."""
        output = tmp_path / "review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="ja")
        decisions = generator.parse_review_doc(output)

        for d in decisions:
            assert d.decision == ReviewDecisionStatus.PENDING

    def test_roundtrip_english_language(
        self, generator: ReviewDocumentGenerator, sample_candidates: list[EvidenceCandidate], tmp_path: Path
    ) -> None:
        """Roundtrip works with English review language."""
        output = tmp_path / "review.md"
        generator.generate_review_doc(sample_candidates, output, review_language="en")
        decisions = generator.parse_review_doc(output)

        assert len(decisions) == 2
        assert all(d.decision == ReviewDecisionStatus.PENDING for d in decisions)
