"""Entity Resolver for the Extraction Layer.

Resolves entities (hostnames, IP addresses, user accounts, file paths)
across multiple artifacts to canonical identifiers. Flags ambiguous
resolutions for analyst review and never silently merges entities.

Requirements: 24.1, 24.2, 24.3, 24.4, 24.5, 24.7, 24.8
"""

import re
from typing import Optional
from uuid import uuid4

from ir_agent.models.evidence import EntityResolutionEntry, EvidenceCandidate


# Entity type constants
ENTITY_TYPE_HOSTNAME = "hostname"
ENTITY_TYPE_IP = "ip_address"
ENTITY_TYPE_USER = "user"
ENTITY_TYPE_FILE_PATH = "file_path"

# Confidence thresholds
CONFIDENCE_EXACT = 1.0
CONFIDENCE_CASE_INSENSITIVE = 0.9
CONFIDENCE_PARTIAL = 0.7
AMBIGUITY_THRESHOLD = 0.8

# Patterns for entity extraction
_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_HOSTNAME_PATTERN = re.compile(
    r"\b(?:[A-Za-z][A-Za-z0-9\-]{0,62})\b"
)
_FILE_PATH_WINDOWS = re.compile(
    r"[A-Za-z]:\\(?:[^\\\/:*?\"<>|\r\n]+\\)*[^\\\/:*?\"<>|\r\n]*"
)
_FILE_PATH_UNIX = re.compile(
    r"/(?:[^\s/]+/)*[^\s/]+"
)
_USER_PATTERN = re.compile(
    r"(?:[A-Za-z][A-Za-z0-9._\-]{0,63})"
)

# Common hostname abbreviation mappings
_HOSTNAME_ABBREVIATIONS: dict[str, str] = {
    "ws": "workstation",
    "srv": "server",
    "dc": "domaincontroller",
    "db": "database",
    "app": "application",
    "web": "webserver",
    "fw": "firewall",
    "gw": "gateway",
    "lb": "loadbalancer",
    "fs": "fileserver",
}

# Common user account aliases
_USER_ALIASES: dict[str, str] = {
    "admin": "administrator",
    "sysadmin": "administrator",
    "root": "root",
    "system": "system",
    "local service": "localservice",
    "localservice": "localservice",
    "network service": "networkservice",
    "networkservice": "networkservice",
}


class EntityResolver:
    """Resolves entities across artifacts to canonical identifiers.

    Maintains an internal resolution table mapping observed values to
    canonical entity IDs. Flags ambiguous resolutions for analyst review
    and never silently merges entities.
    """

    def __init__(self) -> None:
        # Maps observed_value (lowercased) -> canonical_entity_id
        self._resolution_table: dict[str, str] = {}
        # Maps canonical_entity_id -> list of EntityResolutionEntry
        self._entries_by_canonical: dict[str, list[EntityResolutionEntry]] = {}
        # Maps observed_value (lowercased) -> EntityResolutionEntry
        self._entries_by_observed: dict[str, EntityResolutionEntry] = {}

    def resolve_entities(
        self, candidates: list[EvidenceCandidate]
    ) -> list[EntityResolutionEntry]:
        """Resolve entities across a list of evidence candidates.

        Identifies hostnames, IPs, users, and file paths in the observed
        events and facts, then resolves them to canonical IDs.

        Args:
            candidates: List of EvidenceCandidate objects to process.

        Returns:
            List of EntityResolutionEntry objects with resolution decisions.
        """
        entries: list[EntityResolutionEntry] = []

        for candidate in candidates:
            extracted = self._extract_entities_from_candidate(candidate)
            for entity_type, observed_value, source_file_id, source_lines in extracted:
                entry = self._resolve_single_entity(
                    entity_type=entity_type,
                    observed_value=observed_value,
                    source_file_id=source_file_id,
                    source_lines=source_lines,
                )
                entries.append(entry)

        return entries

    def get_canonical_id(self, observed_value: str) -> Optional[str]:
        """Look up the canonical entity ID for an observed value.

        Args:
            observed_value: The observed string representation of an entity.

        Returns:
            The canonical entity ID if resolved, None otherwise.
        """
        key = observed_value.strip().lower()
        return self._resolution_table.get(key)

    def _extract_entities_from_candidate(
        self, candidate: EvidenceCandidate
    ) -> list[tuple[str, str, str, tuple[int, int]]]:
        """Extract entity mentions from a candidate's observed data.

        Returns a deduplicated list of (entity_type, observed_value, source_file_id, source_lines).
        Entities from the observed_event dict take priority; text-based extraction
        supplements but does not duplicate.
        """
        results: list[tuple[str, str, str, tuple[int, int]]] = []
        seen: set[tuple[str, str]] = set()  # (entity_type, normalized_value)

        # Determine source info from the first source ref
        source_file_id = ""
        source_lines: tuple[int, int] = (0, 0)
        if candidate.source_refs:
            source_file_id = candidate.source_refs[0].source_file_id
            source_lines = candidate.source_refs[0].source_lines

        # First, extract from observed_event dict (high priority - explicit labels)
        self._extract_from_observed_event(
            candidate.observed_event, source_file_id, source_lines, results
        )
        # Track what we've already found
        for entity_type, value, _, _ in results:
            seen.add((entity_type, value.strip().lower()))

        # Then supplement with text-based extraction (avoid duplicates)
        text_sources = self._gather_text_from_candidate(candidate)
        for text in text_sources:
            # Extract IPs
            for match in _IP_PATTERN.finditer(text):
                key = (ENTITY_TYPE_IP, match.group().strip().lower())
                if key not in seen:
                    seen.add(key)
                    results.append(
                        (ENTITY_TYPE_IP, match.group(), source_file_id, source_lines)
                    )

            # Extract file paths (Windows)
            for match in _FILE_PATH_WINDOWS.finditer(text):
                key = (ENTITY_TYPE_FILE_PATH, match.group().strip().lower())
                if key not in seen:
                    seen.add(key)
                    results.append(
                        (ENTITY_TYPE_FILE_PATH, match.group(), source_file_id, source_lines)
                    )

            # Extract file paths (Unix)
            for match in _FILE_PATH_UNIX.finditer(text):
                value = match.group()
                # Filter out very short paths that are likely false positives
                if len(value) > 3 and "/" in value[1:]:
                    key = (ENTITY_TYPE_FILE_PATH, value.strip().lower())
                    if key not in seen:
                        seen.add(key)
                        results.append(
                            (ENTITY_TYPE_FILE_PATH, value, source_file_id, source_lines)
                        )

        return results

    def _gather_text_from_candidate(
        self, candidate: EvidenceCandidate
    ) -> list[str]:
        """Gather all text content from a candidate for entity extraction."""
        texts: list[str] = []
        texts.append(candidate.observed_fact)
        texts.append(candidate.interpretation)

        # Include excerpts from source references
        for ref in candidate.source_refs:
            if ref.excerpt:
                texts.append(ref.excerpt)

        return texts

    def _extract_from_observed_event(
        self,
        observed_event: dict,
        source_file_id: str,
        source_lines: tuple[int, int],
        results: list[tuple[str, str, str, tuple[int, int]]],
    ) -> None:
        """Extract entities from the observed_event dictionary.

        Looks at well-known keys to identify entity types.
        """
        # Keys that indicate hostnames
        hostname_keys = {"host", "hostname", "computer_name", "src_host", "dst_host"}
        # Keys that indicate IP addresses
        ip_keys = {"src_ip", "dst_ip", "ip", "ip_address", "source_ip", "dest_ip"}
        # Keys that indicate users
        user_keys = {"user", "username", "account", "account_name", "user_name"}
        # Keys that indicate file paths
        path_keys = {"file_path", "path", "file", "process_path", "image_path"}

        for key, value in observed_event.items():
            if not isinstance(value, str) or not value.strip():
                continue

            key_lower = key.lower()
            if key_lower in hostname_keys:
                results.append(
                    (ENTITY_TYPE_HOSTNAME, value, source_file_id, source_lines)
                )
            elif key_lower in ip_keys:
                results.append(
                    (ENTITY_TYPE_IP, value, source_file_id, source_lines)
                )
            elif key_lower in user_keys:
                results.append(
                    (ENTITY_TYPE_USER, value, source_file_id, source_lines)
                )
            elif key_lower in path_keys:
                results.append(
                    (ENTITY_TYPE_FILE_PATH, value, source_file_id, source_lines)
                )

    def _resolve_single_entity(
        self,
        entity_type: str,
        observed_value: str,
        source_file_id: str,
        source_lines: tuple[int, int],
    ) -> EntityResolutionEntry:
        """Resolve a single observed entity to a canonical ID.

        Applies matching rules based on entity type, assigns confidence,
        and flags ambiguous resolutions.
        """
        key = observed_value.strip().lower()

        # Check for an existing exact match
        if key in self._resolution_table:
            canonical_id = self._resolution_table[key]
            entry = EntityResolutionEntry(
                canonical_entity_id=canonical_id,
                observed_value=observed_value,
                source_file_id=source_file_id,
                source_lines=source_lines,
                resolution_confidence=CONFIDENCE_EXACT,
                resolution_reason=f"Exact match to existing canonical entity",
                review_status="approved",
            )
            self._entries_by_observed[key] = entry
            self._entries_by_canonical.setdefault(canonical_id, []).append(entry)
            return entry

        # Try to find a match with existing entities
        match_result = self._find_match(entity_type, observed_value)

        if match_result is not None:
            canonical_id, confidence, reason = match_result
            review_status = (
                "pending" if confidence < AMBIGUITY_THRESHOLD else "approved"
            )
            entry = EntityResolutionEntry(
                canonical_entity_id=canonical_id,
                observed_value=observed_value,
                source_file_id=source_file_id,
                source_lines=source_lines,
                resolution_confidence=confidence,
                resolution_reason=reason,
                review_status=review_status,
            )
        else:
            # Create a new canonical entity
            canonical_id = str(uuid4())
            entry = EntityResolutionEntry(
                canonical_entity_id=canonical_id,
                observed_value=observed_value,
                source_file_id=source_file_id,
                source_lines=source_lines,
                resolution_confidence=CONFIDENCE_EXACT,
                resolution_reason=f"New {entity_type} entity: first observation",
                review_status="approved",
            )

        # Update the resolution table
        self._resolution_table[key] = entry.canonical_entity_id
        self._entries_by_observed[key] = entry
        self._entries_by_canonical.setdefault(
            entry.canonical_entity_id, []
        ).append(entry)

        return entry

    def _find_match(
        self, entity_type: str, observed_value: str
    ) -> Optional[tuple[str, float, str]]:
        """Find a matching canonical entity for the observed value.

        Returns (canonical_id, confidence, reason) or None if no match.
        """
        if entity_type == ENTITY_TYPE_HOSTNAME:
            return self._match_hostname(observed_value)
        elif entity_type == ENTITY_TYPE_IP:
            return self._match_ip(observed_value)
        elif entity_type == ENTITY_TYPE_USER:
            return self._match_user(observed_value)
        elif entity_type == ENTITY_TYPE_FILE_PATH:
            return self._match_file_path(observed_value)
        return None

    def _match_hostname(
        self, observed_value: str
    ) -> Optional[tuple[str, float, str]]:
        """Match a hostname against known entities.

        Handles case-insensitive matching, abbreviation expansion
        (e.g., WS01 vs WORKSTATION01), and numeric suffix matching.
        """
        normalized = observed_value.strip().lower()

        for existing_key, canonical_id in self._resolution_table.items():
            existing_entry = self._entries_by_observed.get(existing_key)
            if existing_entry is None:
                continue

            # Case-insensitive exact match
            if normalized == existing_key:
                return (canonical_id, CONFIDENCE_EXACT, "Exact match (case-insensitive)")

            # Check abbreviation-based matching
            confidence = self._hostname_abbreviation_match(normalized, existing_key)
            if confidence is not None:
                return (
                    canonical_id,
                    confidence,
                    f"Hostname abbreviation match: '{observed_value}' ↔ '{existing_key}'",
                )

            # Substring/prefix match for hostnames
            if self._is_hostname_substring_match(normalized, existing_key):
                return (
                    canonical_id,
                    CONFIDENCE_PARTIAL,
                    f"Hostname partial match: '{observed_value}' ↔ '{existing_key}'",
                )

        return None

    def _hostname_abbreviation_match(
        self, name1: str, name2: str
    ) -> Optional[float]:
        """Check if two hostnames are abbreviation variants of each other.

        E.g., 'ws01' matches 'workstation01', 'srv02' matches 'server02'.
        Returns confidence score or None.
        """
        # Extract prefix and numeric suffix
        prefix1, suffix1 = self._split_hostname(name1)
        prefix2, suffix2 = self._split_hostname(name2)

        # If numeric suffixes don't match, they're different hosts
        if suffix1 != suffix2:
            return None

        # Check if one prefix is an abbreviation of the other
        expanded1 = _HOSTNAME_ABBREVIATIONS.get(prefix1, prefix1)
        expanded2 = _HOSTNAME_ABBREVIATIONS.get(prefix2, prefix2)

        if expanded1 == expanded2:
            return CONFIDENCE_CASE_INSENSITIVE  # High confidence abbreviation match
        return None

    def _split_hostname(self, hostname: str) -> tuple[str, str]:
        """Split a hostname into alphabetic prefix and numeric suffix."""
        match = re.match(r"^([a-z\-]+)(\d*)$", hostname)
        if match:
            return match.group(1), match.group(2)
        return hostname, ""

    def _is_hostname_substring_match(self, name1: str, name2: str) -> bool:
        """Check if one hostname is a meaningful substring of another."""
        if len(name1) < 3 or len(name2) < 3:
            return False
        # One must be a prefix of the other (ignoring numeric suffixes)
        prefix1, suffix1 = self._split_hostname(name1)
        prefix2, suffix2 = self._split_hostname(name2)
        if suffix1 != suffix2:
            return False
        if prefix1.startswith(prefix2) or prefix2.startswith(prefix1):
            return True
        return False

    def _match_ip(
        self, observed_value: str
    ) -> Optional[tuple[str, float, str]]:
        """Match an IP address against known entities.

        IP addresses use exact matching only since partial IP matching
        is unreliable and could merge different hosts.
        """
        normalized = observed_value.strip()
        for existing_key, canonical_id in self._resolution_table.items():
            if normalized == existing_key:
                return (canonical_id, CONFIDENCE_EXACT, "Exact IP match")
        return None

    def _match_user(
        self, observed_value: str
    ) -> Optional[tuple[str, float, str]]:
        """Match a user account against known entities.

        Handles case-insensitive matching and known aliases
        (e.g., 'admin' vs 'administrator').
        """
        normalized = observed_value.strip().lower()

        for existing_key, canonical_id in self._resolution_table.items():
            # Case-insensitive exact match
            if normalized == existing_key:
                return (canonical_id, CONFIDENCE_EXACT, "Exact match (case-insensitive)")

            # Check known aliases
            alias1 = _USER_ALIASES.get(normalized, normalized)
            alias2 = _USER_ALIASES.get(existing_key, existing_key)
            if alias1 == alias2:
                return (
                    canonical_id,
                    CONFIDENCE_CASE_INSENSITIVE,
                    f"User alias match: '{observed_value}' ↔ '{existing_key}'",
                )

            # Domain\user vs user matching
            user_from_domain = self._extract_user_from_domain(normalized)
            existing_from_domain = self._extract_user_from_domain(existing_key)

            if user_from_domain and user_from_domain == existing_key:
                return (
                    canonical_id,
                    CONFIDENCE_CASE_INSENSITIVE,
                    f"Domain user match: '{observed_value}' ↔ '{existing_key}'",
                )
            if existing_from_domain and existing_from_domain == normalized:
                return (
                    canonical_id,
                    CONFIDENCE_CASE_INSENSITIVE,
                    f"Domain user match: '{observed_value}' ↔ '{existing_key}'",
                )

            # Partial username match (substring)
            if (
                len(normalized) >= 4
                and len(existing_key) >= 4
                and (normalized in existing_key or existing_key in normalized)
            ):
                return (
                    canonical_id,
                    CONFIDENCE_PARTIAL,
                    f"User partial match: '{observed_value}' ↔ '{existing_key}'",
                )

        return None

    def _extract_user_from_domain(self, value: str) -> Optional[str]:
        """Extract username from domain\\user format."""
        if "\\" in value:
            parts = value.split("\\", 1)
            if len(parts) == 2:
                return parts[1].lower()
        return None

    def _match_file_path(
        self, observed_value: str
    ) -> Optional[tuple[str, float, str]]:
        """Match a file path against known entities.

        Handles case-insensitive matching (Windows paths) and
        path normalization.
        """
        normalized = self._normalize_path(observed_value)

        for existing_key, canonical_id in self._resolution_table.items():
            existing_normalized = self._normalize_path(existing_key)

            # Exact match after normalization
            if normalized == existing_normalized:
                return (
                    canonical_id,
                    CONFIDENCE_CASE_INSENSITIVE,
                    f"Path match after normalization: '{observed_value}' ↔ '{existing_key}'",
                )

            # Filename match (same filename, different paths)
            name1 = self._get_filename(normalized)
            name2 = self._get_filename(existing_normalized)
            if name1 and name2 and name1 == name2 and len(name1) > 3:
                # Same filename but different path - this is ambiguous
                return (
                    canonical_id,
                    CONFIDENCE_PARTIAL,
                    f"Same filename, different path: '{observed_value}' ↔ '{existing_key}'",
                )

        return None

    def _normalize_path(self, path: str) -> str:
        """Normalize a file path for comparison."""
        # Convert backslashes to forward slashes and lowercase
        normalized = path.strip().lower().replace("\\", "/")
        # Remove trailing slashes
        normalized = normalized.rstrip("/")
        return normalized

    def _get_filename(self, normalized_path: str) -> str:
        """Extract filename from a normalized path."""
        parts = normalized_path.rsplit("/", 1)
        if len(parts) == 2:
            return parts[1]
        return normalized_path
