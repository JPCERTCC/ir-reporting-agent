"""Prompt Injection Guard for the Governance Layer.

Creates safe LLM views for raw artifact content without modifying originals.
Detects injection patterns, flags suspected injections, and validates LLM
responses for contradictory instructions.

Requirements: 18.1, 18.2, 18.3, 18.7
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from ir_agent.models.base import SourceReference

logger = logging.getLogger(__name__)

# Boundary delimiters used to separate untrusted data from instructions
_BEGIN_BOUNDARY = "---BEGIN UNTRUSTED DATA---"
_END_BOUNDARY = "---END UNTRUSTED DATA---"

# Common prompt injection patterns (case-insensitive)
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?previous\s+instructions", "ignore_previous_instructions"),
    (r"ignore\s+(all\s+)?above\s+instructions", "ignore_above_instructions"),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions", "disregard_instructions"),
    (r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)", "forget_instructions"),
    (r"you\s+are\s+now\s+", "role_reassignment"),
    (r"act\s+as\s+(if\s+you\s+are|a|an)\s+", "role_reassignment"),
    (r"pretend\s+(you\s+are|to\s+be)\s+", "role_reassignment"),
    (r"^system\s*:", "system_role_injection"),
    (r"\[system\]", "system_role_injection"),
    (r"<\|?system\|?>", "system_role_injection"),
    (r"###\s*system", "system_role_injection"),
    (r"new\s+instructions?\s*:", "new_instructions"),
    (r"override\s+(previous\s+)?instructions", "override_instructions"),
    (r"execute\s+(the\s+following|this)\s+command", "command_execution"),
    (r"run\s+(the\s+following|this)\s+command", "command_execution"),
    (r"reveal\s+(your|the)\s+(system\s+)?prompt", "prompt_extraction"),
    (r"show\s+(me\s+)?(your|the)\s+(system\s+)?prompt", "prompt_extraction"),
    (r"output\s+(your|the)\s+(system\s+)?(prompt|instructions)", "prompt_extraction"),
    (r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions)", "prompt_extraction"),
    (r"modify\s+(your|the|agent)\s+(behavior|output|response)", "behavior_modification"),
    (r"change\s+(your|the|agent)\s+(behavior|output|response)", "behavior_modification"),
    (r"do\s+not\s+follow\s+(your|the|any)\s+(original|previous)?\s*instructions",
     "ignore_instructions"),
]


# Wording that describes how the tool handles artifact-embedded instructions.
# Such text is a processing note, not an incident observation: it must not
# become evidence, and it must not appear in the customer report.
PROCESSING_NOTE_TERMS = re.compile(
    r"プロンプトインジェクション|命令文風|命令文として|未信頼データ|指示として扱|"
    r"prompt[\s_-]*injection|untrusted data|embedded instruction",
    re.IGNORECASE,
)


def processing_note_hits(text: str) -> list[str]:
    """Processing-note wording found in ``text`` (deduplicated, in order)."""
    return list(dict.fromkeys(m.group(0) for m in PROCESSING_NOTE_TERMS.finditer(text)))


@dataclass
class InjectionFinding:
    """A detected injection pattern in artifact content."""

    pattern_type: str
    matched_text: str
    line_number: int
    start_pos: int
    end_pos: int


@dataclass
class InjectionFlag:
    """A flag indicating suspected prompt injection in a source reference."""

    source_ref_id: str
    source_file_id: str
    source_path: str
    findings: list[dict] = field(default_factory=list)
    flagged: bool = True


class PromptInjectionGuard:
    """Creates safe LLM views but NEVER modifies raw artifacts or source excerpts.

    This guard implements the following protections:
    - Wraps artifact content in data boundary delimiters for LLM processing
      (Requirement 18.1)
    - Creates safe processing views without modifying originals
      (Requirement 18.2)
    - Validates LLM responses for contradictory instructions
      (Requirement 18.3)
    - Flags suspected prompt injection while preserving evidence
      (Requirement 18.7)
    """

    def __init__(self) -> None:
        """Initialize the PromptInjectionGuard.

        Compiles injection patterns for efficient reuse across calls.
        """
        self._compiled_patterns: list[tuple[re.Pattern[str], str]] = [
            (re.compile(pattern, re.IGNORECASE | re.MULTILINE), pattern_type)
            for pattern, pattern_type in _INJECTION_PATTERNS
        ]
        self._flags: list[InjectionFlag] = []

    @property
    def flags(self) -> list[InjectionFlag]:
        """Return all injection flags recorded by this guard."""
        return list(self._flags)

    def create_safe_llm_view(self, source_ref: SourceReference) -> str:
        """Wrap content in data boundary delimiters for LLM processing.

        Creates a safe view that:
        - Wraps the excerpt in clear boundary markers
        - Preserves source line mapping (original line numbers annotated)
        - Does NOT modify the original SourceReference or its excerpt

        Args:
            source_ref: A SourceReference containing the excerpt to wrap.

        Returns:
            A string with the content wrapped in boundary delimiters,
            with source line numbers preserved in the output.
        """
        start_line, end_line = source_ref.source_lines
        lines = source_ref.excerpt.splitlines()

        # Build line-numbered view preserving original line mapping
        numbered_lines: list[str] = []
        for i, line in enumerate(lines):
            original_line_num = start_line + i
            numbered_lines.append(f"[L{original_line_num}] {line}")

        numbered_content = "\n".join(numbered_lines)

        safe_view = (
            f"{_BEGIN_BOUNDARY}\n"
            f"Source: {source_ref.source_path} "
            f"(lines {start_line}-{end_line}, file_id: {source_ref.source_file_id})\n"
            f"{numbered_content}\n"
            f"{_END_BOUNDARY}"
        )

        return safe_view

    def detect_injection_patterns(self, content: str) -> list[dict]:
        """Scan content for common prompt injection patterns.

        Checks the content against a library of known injection patterns
        including role reassignment, instruction override, system prompt
        extraction attempts, and command execution attempts.

        Args:
            content: The raw text content to scan for injection patterns.

        Returns:
            A list of dicts, each containing:
            - pattern_type: Category of injection pattern detected
            - matched_text: The actual text that matched
            - line_number: 1-based line number where the match was found
            - start_pos: Character start position within the line
            - end_pos: Character end position within the line
        """
        findings: list[dict] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines):
            for compiled_pattern, pattern_type in self._compiled_patterns:
                for match in compiled_pattern.finditer(line):
                    finding = {
                        "pattern_type": pattern_type,
                        "matched_text": match.group(0),
                        "line_number": line_idx + 1,
                        "start_pos": match.start(),
                        "end_pos": match.end(),
                    }
                    findings.append(finding)

        return findings

    def flag_suspected_injection(
        self, source_ref: SourceReference, findings: list[dict]
    ) -> None:
        """Mark content as suspected prompt injection without modifying the original.

        Flags the source reference as containing suspected injection patterns.
        The original artifact and evidence content is preserved intact —
        only metadata flags are added for downstream awareness.

        Args:
            source_ref: The SourceReference whose content contains suspected
                injection patterns.
            findings: The list of detected injection patterns from
                detect_injection_patterns().
        """
        injection_flag = InjectionFlag(
            source_ref_id=source_ref.source_ref_id,
            source_file_id=source_ref.source_file_id,
            source_path=source_ref.source_path,
            findings=findings,
            flagged=True,
        )
        self._flags.append(injection_flag)

        logger.warning(
            "Prompt injection suspected in %s (file_id=%s): %d pattern(s) detected",
            source_ref.source_path,
            source_ref.source_file_id,
            len(findings),
        )

    def validate_response(
        self, response: str, system_prompt: str
    ) -> tuple[bool, Optional[str]]:
        """Check an LLM response for contradictory instructions.

        Validates that the response does not contain instructions that
        contradict the system prompt or attempt to modify Agent behavior.

        Args:
            response: The LLM response text to validate.
            system_prompt: The original system prompt that governed the LLM call.

        Returns:
            A tuple of (is_valid, reason). If valid, returns (True, None).
            If invalid, returns (False, description_of_violation).
        """
        # Check for role reassignment or behavior modification in response
        response_lower = response.lower()

        # Patterns that indicate the LLM response is trying to inject instructions
        contradiction_patterns: list[tuple[str, str]] = [
            (r"ignore\s+(all\s+)?previous\s+instructions",
             "Response contains instruction to ignore previous instructions"),
            (r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions",
             "Response contains instruction to disregard instructions"),
            (r"you\s+(should|must|need\s+to)\s+(now\s+)?ignore",
             "Response attempts to override system behavior"),
            (r"new\s+instructions?\s*:",
             "Response contains new instructions block"),
            (r"override\s+(previous\s+)?instructions",
             "Response attempts to override instructions"),
            (r"do\s+not\s+follow\s+(your|the|any)\s+(original|previous)?\s*instructions",
             "Response instructs to not follow original instructions"),
            (r"system\s*:\s*you\s+are",
             "Response contains system role injection"),
        ]

        for pattern, reason in contradiction_patterns:
            if re.search(pattern, response_lower):
                logger.warning(
                    "LLM response validation failed: %s", reason
                )
                return False, reason

        # Check if the response references the system prompt content in a way
        # that suggests extraction
        if system_prompt:
            # If the response reproduces a significant portion of the system prompt
            # this could indicate prompt extraction
            system_prompt_words = system_prompt.split()
            if len(system_prompt_words) >= 10:
                # Check for 10+ consecutive words from system prompt in response
                for i in range(len(system_prompt_words) - 9):
                    phrase = " ".join(system_prompt_words[i : i + 10])
                    if phrase.lower() in response_lower:
                        reason = (
                            "Response appears to reproduce system prompt content"
                        )
                        logger.warning(
                            "LLM response validation failed: %s", reason
                        )
                        return False, reason

        return True, None

    def is_flagged(self, source_ref_id: str) -> bool:
        """Check if a source reference has been flagged for injection.

        Args:
            source_ref_id: The source_ref_id to check.

        Returns:
            True if the source reference has been flagged.
        """
        return any(f.source_ref_id == source_ref_id for f in self._flags)

    def get_flags_for_file(self, source_file_id: str) -> list[InjectionFlag]:
        """Get all injection flags for a given source file.

        Args:
            source_file_id: The file_id to look up.

        Returns:
            List of InjectionFlag instances for that file.
        """
        return [f for f in self._flags if f.source_file_id == source_file_id]

    def clear_flags(self) -> None:
        """Clear all recorded injection flags.

        Useful for testing or when re-processing content.
        """
        self._flags.clear()
