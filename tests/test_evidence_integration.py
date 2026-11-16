"""Integration-level unit tests for the Evidence Layer.

Validates Requirements: 6.3, 6.4, 7.1, 7.2
- 6.3: Recalculate confidence produces rationale string (non-empty)
- 6.4: Merge preserves ALL source_refs from all input candidates
- 7.1: Review doc generation in Japanese has all 9 required headings
- 7.2: Review doc parser extracts YAML blocks regardless of prose language
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ir_agent.evidence.deduplicator import EvidenceDeduplicator
from ir_agent.evidence.review_generator import (
    ReviewDecision,
    ReviewDecisionStatus,
    ReviewDocumentGenerator,
    _SECTION_HEADINGS,
)
from ir_agent.models.base import SourceReference
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceCandidate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_source_ref(
    source_ref_id: str = "ref-001",
    source_file_id: str = "file-001",
    source_path: str = "/artifacts/host01/auth.log",
    source_lines: tuple[int, int] = (10, 20),
    excerpt: str = "Jan 15 10:00:01 host01 sshd[1234]: Accepted publickey for admin from 192.168.1.5",
    excerpt_sha256: str = "aaa111",
    parser_name: str | None = None,
) -> SourceReference:
    return SourceReference(
        source_ref_id=source_ref_id,
        source_file_id=source_file_id,
        source_path=source_path,
        source_lines=source_lines,
        excerpt=excerpt,
        excerpt_sha256=excerpt_sha256,
        parser_name=parser_name,
    )


def _make_candidate(
    candidate_id: str = "cand-001",
    source_refs: list[SourceReference] | None = None,
    observed_event: dict | None = None,
    observed_fact: str = "SSH login to host01 from external IP",
    interpretation: str = "Possible unauthorized access",
    observed_fact_confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
    interpretation_confidence: ConfidenceLevel = ConfidenceLevel.PROBABLE,
    from_normalized_event_ids: list[str] | None = None,
) -> EvidenceCandidate:
    if source_refs is None:
        source_refs = [_make_source_ref()]
    return EvidenceCandidate(
        candidate_id=candidate_id,
        source_refs=source_refs,
        observed_event=observed_event or {"type": "ssh_login"},
        observed_fact=observed_fact,
        interpretation=interpretation,
        observed_fact_confidence=observed_fact_confidence,
        interpretation_confidence=interpretation_confidence,
        from_normalized_event_ids=from_normalized_event_ids or [],
    )


# ---------------------------------------------------------------------------
# Test: Merge preserves ALL source_refs from all input candidates (Req 6.4)
# ---------------------------------------------------------------------------


class TestMergePreservesAllSourceRefs:
    """Validates Requirement 6.4: merge preserves all source references."""

    def test_merge_three_candidates_preserves_all_source_refs(self) -> None:
        """Merging 3+ candidates must preserve every source_ref from each."""
        ref_a = _make_source_ref(
            source_ref_id="ref-A",
            source_file_id="file-A",
            source_path="/artifacts/host01/auth.log",
            source_lines=(1, 10),
            excerpt="First source excerpt content for testing purposes" * 3,
            excerpt_sha256="hash-A",
            parser_name="syslog_parser",
        )
        ref_b = _make_source_ref(
            source_ref_id="ref-B",
            source_file_id="file-B",
            source_path="/artifacts/host02/access.log",
            source_lines=(50, 60),
            excerpt="Second source excerpt with different data for testing" * 3,
            excerpt_sha256="hash-B",
            parser_name="access_log_parser",
        )
        ref_c = _make_source_ref(
            source_ref_id="ref-C",
            source_file_id="file-C",
            source_path="/artifacts/host03/sysmon.evtx",
            source_lines=(100, 110),
            excerpt="Third source excerpt from sysmon event log data" * 3,
            excerpt_sha256="hash-C",
        )

        cand_a = _make_candidate(
            candidate_id="cand-A",
            source_refs=[ref_a],
            observed_fact="SSH login to host01 from external IP address 203.0.113.5",
            interpretation="Possible unauthorized access from external network",
        )
        cand_b = _make_candidate(
            candidate_id="cand-B",
            source_refs=[ref_b],
            observed_fact="SSH login to host01 from external IP address 203.0.113.5",
            interpretation="Possible unauthorized access from external network",
        )
        cand_c = _make_candidate(
            candidate_id="cand-C",
            source_refs=[ref_c],
            observed_fact="SSH login to host01 from external IP address 203.0.113.5",
            interpretation="Possible unauthorized access from external network",
        )

        deduplicator = EvidenceDeduplicator()
        merged = deduplicator.merge_candidates(
            ["cand-A", "cand-B", "cand-C"],
            [cand_a, cand_b, cand_c],
        )

        # All 3 source_refs must be present
        merged_ref_ids = {ref.source_ref_id for ref in merged.source_refs}
        assert merged_ref_ids == {"ref-A", "ref-B", "ref-C"}

        # All source_file_ids preserved
        merged_file_ids = {ref.source_file_id for ref in merged.source_refs}
        assert merged_file_ids == {"file-A", "file-B", "file-C"}

        # Source paths preserved
        merged_paths = {ref.source_path for ref in merged.source_refs}
        assert "/artifacts/host01/auth.log" in merged_paths
        assert "/artifacts/host02/access.log" in merged_paths
        assert "/artifacts/host03/sysmon.evtx" in merged_paths

    def test_merge_preserves_source_lines_and_excerpts(self) -> None:
        """Each merged source_ref retains its original source_lines and excerpt."""
        refs = [
            _make_source_ref(
                source_ref_id=f"ref-{i}",
                source_file_id=f"file-{i}",
                source_lines=(i * 10, i * 10 + 5),
                excerpt=f"Excerpt content number {i} with sufficient detail for testing" * 2,
                excerpt_sha256=f"hash-{i}",
            )
            for i in range(4)
        ]

        candidates = [
            _make_candidate(
                candidate_id=f"cand-{i}",
                source_refs=[refs[i]],
                observed_fact="Process cmd.exe executed on host01 with admin privileges",
                interpretation="Possible command execution via lateral movement",
            )
            for i in range(4)
        ]

        deduplicator = EvidenceDeduplicator()
        merged = deduplicator.merge_candidates(
            [f"cand-{i}" for i in range(4)],
            candidates,
        )

        assert len(merged.source_refs) == 4
        for i, ref in enumerate(merged.source_refs):
            assert ref.source_lines == (i * 10, i * 10 + 5)
            assert f"Excerpt content number {i}" in ref.excerpt


# ---------------------------------------------------------------------------
# Test: recalculate_confidence produces non-empty rationale (Req 6.3)
# ---------------------------------------------------------------------------


class TestRecalculateConfidenceRationale:
    """Validates Requirement 6.3: confidence recalculation records rationale."""

    def test_rationale_is_nonempty_single_source(self) -> None:
        """recalculate_confidence always produces a non-empty rationale string."""
        deduplicator = EvidenceDeduplicator()
        refs = [_make_source_ref(excerpt="short excerpt" * 5)]
        _, rationale = deduplicator.recalculate_confidence(refs)

        assert rationale  # non-empty
        assert isinstance(rationale, str)
        assert len(rationale) > 0

    def test_rationale_is_nonempty_multiple_sources(self) -> None:
        """Rationale is non-empty even with multiple independent sources."""
        deduplicator = EvidenceDeduplicator()
        refs = [
            _make_source_ref(
                source_ref_id=f"ref-{i}",
                source_file_id=f"file-{i}",
                parser_name="rule_parser" if i % 2 == 0 else None,
                excerpt="A reasonably long excerpt that provides context" * 3,
            )
            for i in range(5)
        ]
        _, rationale = deduplicator.recalculate_confidence(refs)

        assert rationale
        assert isinstance(rationale, str)
        assert len(rationale) > 0

    def test_rationale_contains_factor_details(self) -> None:
        """Rationale should contain details about the scoring factors."""
        deduplicator = EvidenceDeduplicator()
        refs = [
            _make_source_ref(
                source_ref_id="ref-1",
                source_file_id="file-1",
                parser_name="syslog_parser",
                excerpt="Detailed log entry showing process execution" * 4,
            ),
            _make_source_ref(
                source_ref_id="ref-2",
                source_file_id="file-2",
                excerpt="Another supporting observation from second file" * 4,
            ),
        ]
        _, rationale = deduplicator.recalculate_confidence(refs)

        # Rationale should mention independent_sources and reliability
        assert "independent_sources" in rationale
        assert "reliability" in rationale
        assert "total_score" in rationale

    def test_rationale_nonempty_with_empty_source_list(self) -> None:
        """Even with empty sources, rationale should be non-empty (edge case)."""
        deduplicator = EvidenceDeduplicator()
        _, rationale = deduplicator.recalculate_confidence([])

        assert rationale
        assert isinstance(rationale, str)
        assert len(rationale) > 0


# ---------------------------------------------------------------------------
# Test: Review doc generation in Japanese has all 9 required headings (Req 7.1)
# ---------------------------------------------------------------------------


class TestReviewDocJapaneseHeadings:
    """Validates Requirement 7.1: review doc in Japanese has correct headings."""

    # The 9 required headings as specified in the design and requirements
    REQUIRED_HEADING_KEYS = [
        "summary",
        "observed_fact",
        "interpretation",
        "confidence",
        "limitations",
        "recommended_expressions",
        "prohibited_expressions",
        "source",
        "decision",
    ]

    def test_japanese_review_doc_has_all_nine_headings(self, tmp_path: Path) -> None:
        """Generated Japanese review doc must contain all 9 section headings."""
        candidates = [
            _make_candidate(
                candidate_id="EC-TEST-001",
                observed_fact="ホスト host01 で不審なプロセス実行を確認",
                interpretation="外部からの不正アクセスの可能性",
            )
        ]

        generator = ReviewDocumentGenerator()
        output_path = tmp_path / "review.md"
        generator.generate_review_doc(candidates, output_path, review_language="ja")

        content = output_path.read_text(encoding="utf-8")
        ja_headings = _SECTION_HEADINGS["ja"]

        for key in self.REQUIRED_HEADING_KEYS:
            expected_heading = ja_headings[key]
            assert expected_heading in content, (
                f"Japanese heading '{expected_heading}' (key={key}) not found in review doc"
            )

    def test_japanese_headings_are_h3_level(self, tmp_path: Path) -> None:
        """All 9 section headings should appear as ### (h3) level headings."""
        candidates = [_make_candidate(candidate_id="EC-H3-001")]

        generator = ReviewDocumentGenerator()
        output_path = tmp_path / "review_h3.md"
        generator.generate_review_doc(candidates, output_path, review_language="ja")

        content = output_path.read_text(encoding="utf-8")
        ja_headings = _SECTION_HEADINGS["ja"]

        for key in self.REQUIRED_HEADING_KEYS:
            heading_text = ja_headings[key]
            # Should appear as "### <heading>"
            assert f"### {heading_text}" in content, (
                f"Heading '{heading_text}' not found as ### level in review doc"
            )

    def test_multiple_candidates_each_get_all_headings(self, tmp_path: Path) -> None:
        """Each candidate in a multi-candidate doc gets all 9 headings."""
        candidates = [
            _make_candidate(candidate_id=f"EC-MULTI-{i:03d}")
            for i in range(3)
        ]

        generator = ReviewDocumentGenerator()
        output_path = tmp_path / "review_multi.md"
        generator.generate_review_doc(candidates, output_path, review_language="ja")

        content = output_path.read_text(encoding="utf-8")
        ja_headings = _SECTION_HEADINGS["ja"]

        # Each heading should appear once per candidate (3 times total)
        for key in self.REQUIRED_HEADING_KEYS:
            heading_text = ja_headings[key]
            count = content.count(f"### {heading_text}")
            assert count == 3, (
                f"Heading '{heading_text}' appears {count} times, expected 3"
            )


# ---------------------------------------------------------------------------
# Test: Review doc parser extracts YAML blocks regardless of prose language (Req 7.2)
# ---------------------------------------------------------------------------


class TestReviewDocParserLanguageAgnostic:
    """Validates Requirement 7.2: parser extracts YAML regardless of prose language."""

    def test_parse_yaml_from_japanese_prose(self, tmp_path: Path) -> None:
        """Parser correctly extracts YAML decision blocks surrounded by Japanese prose."""
        japanese_doc = """\
# エビデンス候補レビュー

## EC-JA-001

### 概要

- candidate_id: `EC-JA-001`
- source_refs: file-001

### 観測事実

ホスト host01 においてSSHログインが確認されました。外部IPアドレス 203.0.113.5 からのアクセスです。

### 解釈

外部ネットワークからの不正アクセスの可能性があります。攻撃者がSSHキーを窃取した可能性を考慮する必要があります。

### 信頼度

- observed_fact_confidence: confirmed
- interpretation_confidence: probable

### 制約・不足情報

認証ログの一部が欠損しているため、アクセス元の完全な特定は困難です。

### 推奨表現

当該ホストへのSSHログインを確認した

### 禁止表現

攻撃者がSSHログインした

### 出典

- source_file_id: `file-001`
  - source_lines: 10-15
  - excerpt: `Jan 15 14:23:01 host01 sshd[1234]: Accepted publickey`

### 判定

```yaml
item_id: EC-JA-001
item_type: evidence_candidate
decision: approved
decision_reason: "ログデータとの整合性を確認"
analyst_id: "analyst-tanaka"
```

---

## EC-JA-002

### 概要

- candidate_id: `EC-JA-002`
- source_refs: file-002

### 観測事実

ファイルサーバFS01からsftp.exeによる大量データ転送を確認。

### 解釈

データ持ち出しの可能性。

### 信頼度

- observed_fact_confidence: confirmed
- interpretation_confidence: possible

### 制約・不足情報

転送先の特定に至っていません。

### 推奨表現

大量データ転送を観測した

### 禁止表現

データが流出した

### 出典

- source_file_id: `file-002`
  - source_lines: 200-210
  - excerpt: `sftp.exe 184734221 bytes transferred to external IP`

### 判定

```yaml
item_id: EC-JA-002
item_type: evidence_candidate
decision: rejected
decision_reason: "追加調査が必要"
analyst_id: "analyst-suzuki"
```

---
"""
        review_path = tmp_path / "japanese_review.md"
        review_path.write_text(japanese_doc, encoding="utf-8")

        generator = ReviewDocumentGenerator()
        decisions = generator.parse_review_doc(review_path)

        assert len(decisions) == 2

        # First decision
        assert decisions[0].item_id == "EC-JA-001"
        assert decisions[0].decision == ReviewDecisionStatus.APPROVED
        assert decisions[0].analyst_id == "analyst-tanaka"

        # Second decision
        assert decisions[1].item_id == "EC-JA-002"
        assert decisions[1].decision == ReviewDecisionStatus.REJECTED
        assert decisions[1].analyst_id == "analyst-suzuki"

    def test_parse_yaml_from_english_prose(self, tmp_path: Path) -> None:
        """Parser also works with English prose (language-agnostic)."""
        english_doc = """\
# Evidence Candidate Review

## EC-EN-001

### Summary

- candidate_id: `EC-EN-001`

### Observed Fact

SSH login observed from external IP.

### Decision

```yaml
item_id: EC-EN-001
item_type: evidence_candidate
decision: edited
decision_reason: "Adjusted interpretation wording"
analyst_id: "analyst-jones"
```

---
"""
        review_path = tmp_path / "english_review.md"
        review_path.write_text(english_doc, encoding="utf-8")

        generator = ReviewDocumentGenerator()
        decisions = generator.parse_review_doc(review_path)

        assert len(decisions) == 1
        assert decisions[0].item_id == "EC-EN-001"
        assert decisions[0].decision == ReviewDecisionStatus.EDITED
        assert decisions[0].analyst_id == "analyst-jones"

    def test_parse_ignores_non_decision_yaml_blocks(self, tmp_path: Path) -> None:
        """Parser ignores YAML blocks that don't have item_id/decision fields."""
        mixed_doc = """\
# エビデンス候補レビュー

## EC-MIX-001

### 概要

設定情報:

```yaml
config_version: 2
language: ja
```

### 判定

```yaml
item_id: EC-MIX-001
item_type: evidence_candidate
decision: needs_more_context
decision_reason: "追加情報の収集が必要"
analyst_id: "analyst-yamada"
```

---
"""
        review_path = tmp_path / "mixed_review.md"
        review_path.write_text(mixed_doc, encoding="utf-8")

        generator = ReviewDocumentGenerator()
        decisions = generator.parse_review_doc(review_path)

        # Only the decision block should be parsed, not the config block
        assert len(decisions) == 1
        assert decisions[0].item_id == "EC-MIX-001"
        assert decisions[0].decision == ReviewDecisionStatus.NEEDS_MORE_CONTEXT

    def test_roundtrip_generate_then_parse_japanese(self, tmp_path: Path) -> None:
        """Generate a Japanese review doc and parse it back - roundtrip test."""
        candidates = [
            _make_candidate(candidate_id="EC-RT-001"),
            _make_candidate(candidate_id="EC-RT-002"),
        ]

        generator = ReviewDocumentGenerator()
        output_path = tmp_path / "roundtrip_review.md"
        generator.generate_review_doc(candidates, output_path, review_language="ja")

        # Parse back
        decisions = generator.parse_review_doc(output_path)

        assert len(decisions) == 2
        assert decisions[0].item_id == "EC-RT-001"
        assert decisions[0].decision == ReviewDecisionStatus.PENDING
        assert decisions[1].item_id == "EC-RT-002"
        assert decisions[1].decision == ReviewDecisionStatus.PENDING
