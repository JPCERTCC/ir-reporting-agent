"""Unit tests for GapReviewService.

Validates Requirements: 13.5, 13.6, 13.7, 13.8
- 13.5: Present gaps to Analyst for resolution before report generation
- 13.6: Block final report on unresolved critical gaps; allow with valid dispositions
- 13.7: Accepted-as-limitation gaps included in reports
- 13.8: Distinguish gap types (missing evidence, unavailable logs, etc.)
- 13.9: Generate Gap_Review_Document in Markdown with Japanese headings
- 13.10: YAML disposition block with item_id, item_type, disposition, etc.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ir_agent.analysis.gap_review import (
    GapDispositionDecision,
    GapReviewService,
)
from ir_agent.models.analysis import Gap


def _make_gap(
    gap_id: str = "GAP-001",
    related_claim_id: str = "CLM-001",
    gap_type: str = "missing_evidence",
    severity: str = "critical",
    description: str = "No firewall logs available for the time range of initial access",
    recommended_action: str = "Request firewall logs from network team",
    disposition: str | None = None,
    disposition_reason: str | None = None,
    dispositioned_by: str | None = None,
) -> Gap:
    return Gap(
        gap_id=gap_id,
        related_claim_id=related_claim_id,
        gap_type=gap_type,
        severity=severity,
        description=description,
        recommended_action=recommended_action,
        disposition=disposition,
        disposition_reason=disposition_reason,
        dispositioned_by=dispositioned_by,
    )


@pytest.fixture
def service() -> GapReviewService:
    return GapReviewService()


@pytest.fixture
def sample_gaps() -> list[Gap]:
    return [
        _make_gap(
            gap_id="GAP-001",
            related_claim_id="CLM-001",
            gap_type="missing_evidence",
            severity="critical",
            description="No firewall logs available for the time range of initial access",
            recommended_action="Request firewall logs from network team",
        ),
        _make_gap(
            gap_id="GAP-002",
            related_claim_id="CLM-003",
            gap_type="single_source",
            severity="major",
            description="Lateral movement claim based on single log source",
            recommended_action="Correlate with endpoint detection logs",
        ),
        _make_gap(
            gap_id="GAP-003",
            related_claim_id="CLM-005",
            gap_type="unavailable_logs",
            severity="minor",
            description="DNS logs not available for host02",
            recommended_action="Document as limitation",
        ),
    ]


class TestGenerateGapReviewDoc:
    """Test generate_gap_review_doc output structure."""

    def test_generates_markdown_file(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Generate a Markdown gap review document."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert content.startswith("# ")

    def test_impact_is_derived_not_placeholder(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")
        assert "ここに記載" not in content
        assert content.count("影響度 ") == len(sample_gaps)

    def test_japanese_headings(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Req 13.9: Section headings rendered in Japanese when review_language='ja'."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "### 説明" in content
        assert "### 関連Claim" in content
        assert "### 推奨対応" in content
        assert "### 影響" in content
        assert "### 判定" in content

    def test_english_headings(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Section headings rendered in English when review_language='en'."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="en")
        content = output.read_text(encoding="utf-8")

        assert "### Description" in content
        assert "### Related Claim" in content
        assert "### Recommended Action" in content
        assert "### Impact" in content
        assert "### Disposition" in content

    def test_yaml_block_keys_in_english(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Req 13.10: YAML disposition block keys and enum values remain in English."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "item_id:" in content
        assert "item_type: gap" in content
        assert "disposition:" in content
        assert "disposition_reason:" in content
        assert "analyst_id:" in content

    def test_gap_id_in_output(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Each gap's gap_id appears in the document."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "GAP-001" in content
        assert "GAP-002" in content
        assert "GAP-003" in content

    def test_gap_description_in_output(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Gap description text appears in the document."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "No firewall logs available" in content
        assert "Lateral movement claim based on single log source" in content

    def test_related_claim_in_output(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Related claim IDs appear in the document."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "CLM-001" in content
        assert "CLM-003" in content
        assert "CLM-005" in content

    def test_recommended_action_in_output(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Recommended actions appear in the document."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "Request firewall logs from network team" in content
        assert "Correlate with endpoint detection logs" in content

    def test_gap_type_and_severity_in_output(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Gap type and severity metadata appears in the document."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "missing_evidence" in content
        assert "single_source" in content
        assert "critical" in content
        assert "major" in content

    def test_empty_gaps_list(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Empty gaps list produces a valid document with just the title."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc([], output, review_language="ja")
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "# ギャップレビュー" in content

    def test_creates_parent_directories(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Output path parent directories are created if missing."""
        output = tmp_path / "nested" / "dir" / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        assert output.exists()

    def test_disposition_options_in_comment(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """YAML block includes disposition options as a comment for guidance."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        content = output.read_text(encoding="utf-8")

        assert "accepted_as_limitation: 制約として報告書に書く" in content
        assert "deferred_with_reason: 追加調査として推奨対策に回す" in content
        # legacy options with no distinct effect are no longer offered
        assert "mitigated_by_claim_downgrade" not in content
        assert "addressed_by_additional_evidence" not in content


class TestParseGapReviewDoc:
    """Test parse_gap_review_doc extracting YAML disposition blocks."""

    def test_parse_freshly_generated_doc(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Parse freshly generated doc with null dispositions."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        dispositions = service.parse_gap_review_doc(output)

        assert len(dispositions) == 3
        assert dispositions[0].item_id == "GAP-001"
        assert dispositions[0].disposition is None
        assert dispositions[1].item_id == "GAP-002"
        assert dispositions[2].item_id == "GAP-003"

    def test_parse_accepted_disposition(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Parse an accepted_as_limitation disposition."""
        doc_content = """# Gap Review

## GAP-001

### 判定

```yaml
item_id: GAP-001
item_type: gap
disposition: accepted_as_limitation
disposition_reason: "Firewall logs no longer available due to retention policy"
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 1
        assert dispositions[0].item_id == "GAP-001"
        assert dispositions[0].disposition == "accepted_as_limitation"
        assert "retention policy" in dispositions[0].disposition_reason
        assert dispositions[0].analyst_id == "analyst-01"

    def test_parse_mitigated_disposition(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Parse a mitigated_by_claim_downgrade disposition."""
        doc_content = """# Gap Review

```yaml
item_id: GAP-002
item_type: gap
disposition: mitigated_by_claim_downgrade
disposition_reason: "Claim downgraded from confirmed to probable"
analyst_id: analyst-02
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 1
        assert dispositions[0].disposition == "mitigated_by_claim_downgrade"

    def test_parse_out_of_scope_disposition(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Parse an out_of_scope_with_analyst_approval disposition."""
        doc_content = """# Gap Review

```yaml
item_id: GAP-003
item_type: gap
disposition: out_of_scope_with_analyst_approval
disposition_reason: "Host is not in scope for this investigation"
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 1
        assert dispositions[0].disposition == "out_of_scope_with_analyst_approval"

    def test_parse_deferred_disposition(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Parse a deferred_with_reason disposition."""
        doc_content = """# Gap Review

```yaml
item_id: GAP-004
item_type: gap
disposition: deferred_with_reason
disposition_reason: "Waiting for log collection from third party"
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 1
        assert dispositions[0].disposition == "deferred_with_reason"

    def test_parse_addressed_disposition(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Parse an addressed_by_additional_evidence disposition."""
        doc_content = """# Gap Review

```yaml
item_id: GAP-005
item_type: gap
disposition: addressed_by_additional_evidence
disposition_reason: "New evidence from IDS logs confirms the finding"
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 1
        assert dispositions[0].disposition == "addressed_by_additional_evidence"

    def test_parse_ignores_prose(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Parser ignores all prose and only extracts YAML disposition blocks."""
        doc_content = """# ギャップレビュー

## GAP-001

### 説明

ファイアウォールログが入手不可能です。

### 関連Claim

- claim_id: `CLM-001`

### 推奨対応

ネットワークチームにログを依頼してください。

### 影響

（このギャップが調査結果に与える影響をここに記載）

### 判定

```yaml
item_id: GAP-001
item_type: gap
disposition: accepted_as_limitation
disposition_reason: "確認済み"
analyst_id: analyst-01
```

---
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 1
        assert dispositions[0].item_id == "GAP-001"
        assert dispositions[0].disposition == "accepted_as_limitation"

    def test_parse_multiple_dispositions(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Parse multiple dispositions from a single document."""
        doc_content = """# Gap Review

```yaml
item_id: GAP-001
item_type: gap
disposition: accepted_as_limitation
disposition_reason: "Logs unavailable"
analyst_id: analyst-01
```

Some prose in between...

```yaml
item_id: GAP-002
item_type: gap
disposition: mitigated_by_claim_downgrade
disposition_reason: "Claim downgraded"
analyst_id: analyst-01
```

```yaml
item_id: GAP-003
item_type: gap
disposition: deferred_with_reason
disposition_reason: "Pending collection"
analyst_id: analyst-02
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 3
        assert dispositions[0].disposition == "accepted_as_limitation"
        assert dispositions[1].disposition == "mitigated_by_claim_downgrade"
        assert dispositions[2].disposition == "deferred_with_reason"

    def test_parse_ignores_non_disposition_yaml(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """YAML blocks without item_id/disposition are ignored."""
        doc_content = """# Gap Review

```yaml
some_config: value
another_key: 123
```

```yaml
item_id: GAP-001
item_type: gap
disposition: accepted_as_limitation
disposition_reason: ""
analyst_id: analyst-01
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 1
        assert dispositions[0].item_id == "GAP-001"

    def test_parse_file_not_found(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """FileNotFoundError raised when review file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            service.parse_gap_review_doc(tmp_path / "nonexistent.md")

    def test_parse_language_agnostic(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Parsing works regardless of surrounding language (Japanese or English)."""
        doc_content = """# ギャップレビュー

## GAP-001

### 判定

```yaml
item_id: GAP-001
item_type: gap
disposition: accepted_as_limitation
disposition_reason: "制限として受け入れ"
analyst_id: analyst-01
```

---

## GAP-002

### Disposition

```yaml
item_id: GAP-002
item_type: gap
disposition: deferred_with_reason
disposition_reason: "Pending further analysis"
analyst_id: analyst-02
```
"""
        review_path = tmp_path / "gap_review.md"
        review_path.write_text(doc_content, encoding="utf-8")
        dispositions = service.parse_gap_review_doc(review_path)

        assert len(dispositions) == 2
        assert dispositions[0].item_id == "GAP-001"
        assert dispositions[0].disposition == "accepted_as_limitation"
        assert dispositions[1].item_id == "GAP-002"
        assert dispositions[1].disposition == "deferred_with_reason"


class TestApplyGapDispositions:
    """Test apply_gap_dispositions updating gap JSONL file."""

    def _write_gaps_jsonl(self, gaps: list[Gap], path: Path) -> None:
        """Helper to write gaps to a JSONL file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for gap in gaps:
                f.write(gap.model_dump_json() + "\n")

    def test_apply_single_disposition(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Apply a single disposition to a gap."""
        gaps = [_make_gap(gap_id="GAP-001")]
        gaps_path = tmp_path / "gaps.jsonl"
        self._write_gaps_jsonl(gaps, gaps_path)

        dispositions = [
            GapDispositionDecision(
                item_id="GAP-001",
                item_type="gap",
                disposition="accepted_as_limitation",
                disposition_reason="Logs not available",
                analyst_id="analyst-01",
            )
        ]

        updated = service.apply_gap_dispositions(dispositions, gaps_path)

        assert len(updated) == 1
        assert updated[0].disposition == "accepted_as_limitation"
        assert updated[0].disposition_reason == "Logs not available"
        assert updated[0].dispositioned_by == "analyst-01"

    def test_apply_multiple_dispositions(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Apply multiple dispositions to multiple gaps."""
        gaps_path = tmp_path / "gaps.jsonl"
        self._write_gaps_jsonl(sample_gaps, gaps_path)

        dispositions = [
            GapDispositionDecision(
                item_id="GAP-001",
                item_type="gap",
                disposition="accepted_as_limitation",
                disposition_reason="Cannot obtain logs",
                analyst_id="analyst-01",
            ),
            GapDispositionDecision(
                item_id="GAP-002",
                item_type="gap",
                disposition="mitigated_by_claim_downgrade",
                disposition_reason="Claim downgraded",
                analyst_id="analyst-01",
            ),
            GapDispositionDecision(
                item_id="GAP-003",
                item_type="gap",
                disposition="deferred_with_reason",
                disposition_reason="Pending collection",
                analyst_id="analyst-02",
            ),
        ]

        updated = service.apply_gap_dispositions(dispositions, gaps_path)

        assert len(updated) == 3
        assert updated[0].disposition == "accepted_as_limitation"
        assert updated[1].disposition == "mitigated_by_claim_downgrade"
        assert updated[2].disposition == "deferred_with_reason"
        assert updated[2].dispositioned_by == "analyst-02"

    def test_apply_partial_dispositions(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Apply dispositions to only some gaps; others remain unchanged."""
        gaps_path = tmp_path / "gaps.jsonl"
        self._write_gaps_jsonl(sample_gaps, gaps_path)

        dispositions = [
            GapDispositionDecision(
                item_id="GAP-001",
                item_type="gap",
                disposition="accepted_as_limitation",
                disposition_reason="Accepted",
                analyst_id="analyst-01",
            ),
        ]

        updated = service.apply_gap_dispositions(dispositions, gaps_path)

        assert updated[0].disposition == "accepted_as_limitation"
        assert updated[1].disposition is None  # GAP-002 unchanged
        assert updated[2].disposition is None  # GAP-003 unchanged

    def test_apply_null_disposition_skipped(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Disposition with null value does not update the gap."""
        gaps = [_make_gap(gap_id="GAP-001")]
        gaps_path = tmp_path / "gaps.jsonl"
        self._write_gaps_jsonl(gaps, gaps_path)

        dispositions = [
            GapDispositionDecision(
                item_id="GAP-001",
                item_type="gap",
                disposition=None,
                disposition_reason="",
                analyst_id="",
            ),
        ]

        updated = service.apply_gap_dispositions(dispositions, gaps_path)

        assert updated[0].disposition is None

    def test_apply_persists_to_file(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Applied dispositions are persisted to the JSONL file."""
        gaps = [_make_gap(gap_id="GAP-001")]
        gaps_path = tmp_path / "gaps.jsonl"
        self._write_gaps_jsonl(gaps, gaps_path)

        dispositions = [
            GapDispositionDecision(
                item_id="GAP-001",
                item_type="gap",
                disposition="deferred_with_reason",
                disposition_reason="Will collect later",
                analyst_id="analyst-01",
            ),
        ]

        service.apply_gap_dispositions(dispositions, gaps_path)

        # Re-read from file to verify persistence
        with open(gaps_path, encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["disposition"] == "deferred_with_reason"
        assert data["disposition_reason"] == "Will collect later"
        assert data["dispositioned_by"] == "analyst-01"

    def test_apply_nonexistent_gap_id_ignored(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Dispositions for non-existent gap IDs are ignored without error."""
        gaps = [_make_gap(gap_id="GAP-001")]
        gaps_path = tmp_path / "gaps.jsonl"
        self._write_gaps_jsonl(gaps, gaps_path)

        dispositions = [
            GapDispositionDecision(
                item_id="GAP-999",  # doesn't exist
                item_type="gap",
                disposition="accepted_as_limitation",
                disposition_reason="Test",
                analyst_id="analyst-01",
            ),
        ]

        updated = service.apply_gap_dispositions(dispositions, gaps_path)

        assert len(updated) == 1
        assert updated[0].gap_id == "GAP-001"
        assert updated[0].disposition is None  # unchanged

    def test_apply_empty_file(
        self, service: GapReviewService, tmp_path: Path
    ) -> None:
        """Apply dispositions when gaps file doesn't exist returns empty list."""
        gaps_path = tmp_path / "gaps.jsonl"
        # Don't create the file - test nonexistence handling

        dispositions = [
            GapDispositionDecision(
                item_id="GAP-001",
                item_type="gap",
                disposition="accepted_as_limitation",
                disposition_reason="Test",
                analyst_id="analyst-01",
            ),
        ]

        updated = service.apply_gap_dispositions(dispositions, gaps_path)
        assert updated == []


class TestGapDispositionDecisionModel:
    """Test the Pydantic GapDispositionDecision model validation."""

    def test_valid_disposition(self) -> None:
        d = GapDispositionDecision(
            item_id="GAP-001",
            item_type="gap",
            disposition="accepted_as_limitation",
            disposition_reason="Logs not available",
            analyst_id="analyst-01",
        )
        assert d.item_id == "GAP-001"
        assert d.disposition == "accepted_as_limitation"

    def test_case_insensitive_disposition(self) -> None:
        """Disposition values accepted case-insensitively."""
        d = GapDispositionDecision(
            item_id="GAP-001",
            disposition="Accepted_As_Limitation",
        )
        assert d.disposition == "accepted_as_limitation"

    def test_null_disposition(self) -> None:
        """Null disposition is valid (not yet dispositioned)."""
        d = GapDispositionDecision(
            item_id="GAP-001",
            disposition=None,
        )
        assert d.disposition is None

    def test_empty_string_disposition_becomes_none(self) -> None:
        """Empty string disposition is normalized to None."""
        d = GapDispositionDecision(
            item_id="GAP-001",
            disposition="",
        )
        assert d.disposition is None

    def test_default_values(self) -> None:
        """Defaults are applied when fields omitted."""
        d = GapDispositionDecision(item_id="GAP-001")
        assert d.item_type == "gap"
        assert d.disposition is None
        assert d.disposition_reason == ""
        assert d.analyst_id == ""


class TestRoundtrip:
    """Test generate -> parse roundtrip."""

    def test_roundtrip_preserves_gap_ids(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Generated doc can be parsed back to extract all gap ids."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        dispositions = service.parse_gap_review_doc(output)

        item_ids = [d.item_id for d in dispositions]
        assert "GAP-001" in item_ids
        assert "GAP-002" in item_ids
        assert "GAP-003" in item_ids

    def test_roundtrip_all_null_disposition(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """All dispositions in freshly generated doc are null."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="ja")
        dispositions = service.parse_gap_review_doc(output)

        for d in dispositions:
            assert d.disposition is None

    def test_roundtrip_english_language(
        self, service: GapReviewService, sample_gaps: list[Gap], tmp_path: Path
    ) -> None:
        """Roundtrip works with English review language."""
        output = tmp_path / "gap_review.md"
        service.generate_gap_review_doc(sample_gaps, output, review_language="en")
        dispositions = service.parse_gap_review_doc(output)

        assert len(dispositions) == 3
        assert all(d.disposition is None for d in dispositions)
