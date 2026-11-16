"""IOC (Indicator of Compromise) Extractor.

Extracts IOCs from text content using regex-based pattern matching.
Supports: IP addresses, domain names, hashes (MD5, SHA-1, SHA-256),
file paths (Windows and Unix), URLs, and email addresses.

Requirements: 5.1, 5.2, 5.3, 5.4
"""

from __future__ import annotations

import re
from uuid import uuid4

from ir_agent.models.evidence import IOCRecord


# --- Regex Patterns ---

# IPv4: four octets (0-255) separated by dots.
# Uses word boundaries and negative lookbehind/lookahead to avoid matching
# version numbers like "1.2.3" or partial matches.
_IPV4_PATTERN = re.compile(
    r"(?<![.\w])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?![.\w])"
)

# Domain: valid domain with at least one subdomain and a TLD (2-63 chars).
# Excludes IPs and file paths.
_DOMAIN_PATTERN = re.compile(
    r"(?<![/@\w.])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}"
    r"(?![.\w/])"
)

# Hashes: standalone hex strings of exact length.
# MD5 = 32 hex chars, SHA-1 = 40 hex chars, SHA-256 = 64 hex chars.
_MD5_PATTERN = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")
_SHA1_PATTERN = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])")
_SHA256_PATTERN = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")

# File paths: Windows (drive letter) and Unix (absolute paths).
_WINDOWS_PATH_PATTERN = re.compile(
    r"[A-Za-z]:\\(?:[^\s\\/:*?\"<>|]+\\)*[^\s\\/:*?\"<>|]+"
)
_UNIX_PATH_PATTERN = re.compile(
    r"(?<!\w)/(?:usr|etc|var|tmp|opt|home|root|bin|sbin|lib|proc|sys|mnt|media|dev)"
    r"(?:/[^\s:*?\"<>|;,(){}]+)+"
)

# URL: http:// or https:// followed by host and optional path.
_URL_PATTERN = re.compile(
    r"https?://[^\s<>\"')\]},;]+"
)

# Email: standard email format.
_EMAIL_PATTERN = re.compile(
    r"(?<![.\w])"
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,63}"
    r"(?![.\w])"
)

# Refang substitutions applied before network-indicator matching so that
# defanged values in the source (e.g. 45[.]77[.]183[.]161, hxxps://…) are
# detected and normalized to their real form. Longer/more-specific patterns
# come first (hxxps before hxxp). Requirement UP-08.
_REFANG_SUBS: list[tuple[str, str]] = [
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("[.]", "."),
    ("(.)", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[://]", "://"),
    ("[:]", ":"),
    ("[at]", "@"),
    ("(at)", "@"),
]


def refang(text: str) -> str:
    """Return the refanged form of text (defanged indicators normalized).

    Reverses common defang conventions so that a defanged IP/domain/URL in
    the source is matched by the network-indicator patterns. Requirement UP-08.
    """
    for token, replacement in _REFANG_SUBS:
        text = text.replace(token, replacement)
    return text


class IOCExtractor:
    """Extracts Indicators of Compromise from text content.

    Identifies IP addresses, domains, hashes (MD5/SHA-1/SHA-256),
    file paths, URLs, and email addresses using regex patterns.
    """

    def extract_iocs(self, content: str, file_id: str) -> list[IOCRecord]:
        """Extract IOCs from text content.

        Args:
            content: The text content to scan for IOCs.
            file_id: The source file ID for provenance tracking.

        Returns:
            List of IOCRecord instances found in the content.
        """
        iocs: list[IOCRecord] = []
        lines = content.splitlines()

        for line_num, original_line in enumerate(lines, start=1):
            # Network indicators (URL/IP/domain) are matched on the refanged
            # line so defanged values are detected and normalized. File paths,
            # hashes and emails are matched on the original line. (UP-08)
            line = refang(original_line)
            # Extract URLs first (they contain domains/IPs that should not be double-matched)
            urls_found: set[str] = set()
            for match in _URL_PATTERN.finditer(line):
                value = match.group(0).rstrip(".")
                urls_found.add(value)
                iocs.append(IOCRecord(
                    ioc_id=str(uuid4()),
                    ioc_type="url",
                    value=value,
                    source_file_id=file_id,
                    source_line=line_num,
                ))

            # Extract emails (before domain detection to avoid double-matching)
            emails_found: set[str] = set()
            for match in _EMAIL_PATTERN.finditer(line):
                value = match.group(0)
                emails_found.add(value)
                iocs.append(IOCRecord(
                    ioc_id=str(uuid4()),
                    ioc_type="email",
                    value=value,
                    source_file_id=file_id,
                    source_line=line_num,
                ))

            # Extract IPs (skip if part of a URL already matched)
            for match in _IPV4_PATTERN.finditer(line):
                value = match.group(0)
                if self._is_within_any(match.start(), match.end(), line, urls_found):
                    continue
                iocs.append(IOCRecord(
                    ioc_id=str(uuid4()),
                    ioc_type="ip",
                    value=value,
                    source_file_id=file_id,
                    source_line=line_num,
                ))

            # Extract domains (skip if part of a URL or email)
            for match in _DOMAIN_PATTERN.finditer(line):
                value = match.group(0)
                if self._is_within_any(match.start(), match.end(), line, urls_found | emails_found):
                    continue
                # Skip a "domain" that is actually a filesystem path segment
                # (immediately preceded by a path separator), e.g. the
                # "Microsoft.NET" in C:\Windows\Microsoft.NET\... (UP-08)
                if match.start() > 0 and line[match.start() - 1] in ("\\", "/"):
                    continue
                iocs.append(IOCRecord(
                    ioc_id=str(uuid4()),
                    ioc_type="domain",
                    value=value,
                    source_file_id=file_id,
                    source_line=line_num,
                ))

            # Extract hashes (check longest first to avoid substring matches)
            # SHA-256 (64 chars)
            for match in _SHA256_PATTERN.finditer(line):
                value = match.group(0)
                iocs.append(IOCRecord(
                    ioc_id=str(uuid4()),
                    ioc_type="hash_sha256",
                    value=value,
                    source_file_id=file_id,
                    source_line=line_num,
                ))

            # SHA-1 (40 chars) - exclude substrings of SHA-256 matches
            sha256_spans = [(m.start(), m.end()) for m in _SHA256_PATTERN.finditer(line)]
            for match in _SHA1_PATTERN.finditer(line):
                if self._is_within_spans(match.start(), match.end(), sha256_spans):
                    continue
                value = match.group(0)
                iocs.append(IOCRecord(
                    ioc_id=str(uuid4()),
                    ioc_type="hash_sha1",
                    value=value,
                    source_file_id=file_id,
                    source_line=line_num,
                ))

            # MD5 (32 chars) - exclude substrings of SHA-256 and SHA-1 matches
            sha1_spans = [(m.start(), m.end()) for m in _SHA1_PATTERN.finditer(line)]
            all_longer_spans = sha256_spans + sha1_spans
            for match in _MD5_PATTERN.finditer(line):
                if self._is_within_spans(match.start(), match.end(), all_longer_spans):
                    continue
                value = match.group(0)
                iocs.append(IOCRecord(
                    ioc_id=str(uuid4()),
                    ioc_type="hash_md5",
                    value=value,
                    source_file_id=file_id,
                    source_line=line_num,
                ))

            # Extract file paths
            for match in _WINDOWS_PATH_PATTERN.finditer(line):
                value = match.group(0)
                iocs.append(IOCRecord(
                    ioc_id=str(uuid4()),
                    ioc_type="file_path",
                    value=value,
                    source_file_id=file_id,
                    source_line=line_num,
                ))

            for match in _UNIX_PATH_PATTERN.finditer(line):
                value = match.group(0)
                if self._is_within_any(match.start(), match.end(), line, urls_found):
                    continue
                iocs.append(IOCRecord(
                    ioc_id=str(uuid4()),
                    ioc_type="file_path",
                    value=value,
                    source_file_id=file_id,
                    source_line=line_num,
                ))

        return iocs

    def deduplicate_iocs(self, iocs: list[IOCRecord]) -> list[IOCRecord]:
        """Remove duplicate IOCs by type and value.

        Keeps the first occurrence of each (type, value) pair.

        Args:
            iocs: List of IOCRecords potentially containing duplicates.

        Returns:
            Deduplicated list of IOCRecords.
        """
        seen: set[tuple[str, str]] = set()
        result: list[IOCRecord] = []
        for ioc in iocs:
            key = (ioc.ioc_type, ioc.value)
            if key not in seen:
                seen.add(key)
                result.append(ioc)
        return result

    def defang(self, value: str, ioc_type: str) -> str:
        """Defang an IOC value to prevent accidental activation.

        For IPs and domains: replaces '.' with '[.]'
        For URLs: replaces 'http' with 'hxxp' and '.' with '[.]' in the host portion.

        Args:
            value: The IOC value to defang.
            ioc_type: The type of IOC (ip, domain, url, etc.).

        Returns:
            Defanged IOC value string.
        """
        if ioc_type in ("ip", "domain"):
            return value.replace(".", "[.]")
        elif ioc_type == "url":
            # Replace http/https with hxxp/hxxps and defang dots in host
            defanged = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
            # Defang dots in the host portion (up to first / after ://)
            protocol_end = defanged.find("://") + 3
            rest = defanged[protocol_end:]
            path_start = rest.find("/")
            if path_start == -1:
                # No path - defang all dots
                host = rest.replace(".", "[.]")
                return defanged[:protocol_end] + host
            else:
                host = rest[:path_start].replace(".", "[.]")
                path = rest[path_start:]
                return defanged[:protocol_end] + host + path
        # For other types (hashes, file_path, email), return as-is
        return value

    @staticmethod
    def _is_within_any(
        start: int, end: int, line: str, container_values: set[str]
    ) -> bool:
        """Check if a match span is contained within any of the container values in the line."""
        for val in container_values:
            idx = line.find(val)
            while idx != -1:
                if idx <= start and idx + len(val) >= end:
                    return True
                idx = line.find(val, idx + 1)
        return False

    @staticmethod
    def _is_within_spans(
        start: int, end: int, spans: list[tuple[int, int]]
    ) -> bool:
        """Check if a match span is contained within any of the given spans."""
        for span_start, span_end in spans:
            if span_start <= start and span_end >= end:
                return True
        return False
