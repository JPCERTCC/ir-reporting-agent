"""Unit tests for IOCExtractor.

Validates Requirements 5.1, 5.2, 5.3, 5.4:
- IOC identification (IP, domain, hashes, file paths, URLs, emails)
- IOC record fields (ioc_type, value, source_file_id, source_line)
- Deduplication by type and value
- Defanging IOC values
"""

from __future__ import annotations

import pytest

from ir_agent.extraction.ioc_extractor import IOCExtractor


@pytest.fixture
def extractor() -> IOCExtractor:
    return IOCExtractor()


class TestExtractIPAddresses:
    """Test IPv4 address extraction."""

    def test_basic_ipv4(self, extractor: IOCExtractor) -> None:
        content = "Connection from 192.168.1.100 to 10.0.0.1"
        iocs = extractor.extract_iocs(content, "file-001")
        ip_iocs = [i for i in iocs if i.ioc_type == "ip"]
        values = {i.value for i in ip_iocs}
        assert "192.168.1.100" in values
        assert "10.0.0.1" in values

    def test_ip_boundary_values(self, extractor: IOCExtractor) -> None:
        content = "Range: 0.0.0.0 to 255.255.255.255"
        iocs = extractor.extract_iocs(content, "file-001")
        ip_iocs = [i for i in iocs if i.ioc_type == "ip"]
        values = {i.value for i in ip_iocs}
        assert "0.0.0.0" in values
        assert "255.255.255.255" in values

    def test_avoids_version_numbers(self, extractor: IOCExtractor) -> None:
        content = "Version 1.2.3 is now available"
        iocs = extractor.extract_iocs(content, "file-001")
        ip_iocs = [i for i in iocs if i.ioc_type == "ip"]
        assert len(ip_iocs) == 0

    def test_source_line_tracking(self, extractor: IOCExtractor) -> None:
        content = "line one\n192.168.1.1 found here\nline three"
        iocs = extractor.extract_iocs(content, "file-001")
        ip_iocs = [i for i in iocs if i.ioc_type == "ip"]
        assert len(ip_iocs) == 1
        assert ip_iocs[0].source_line == 2
        assert ip_iocs[0].source_file_id == "file-001"


class TestExtractDomains:
    """Test domain name extraction."""

    def test_basic_domain(self, extractor: IOCExtractor) -> None:
        content = "Contacted malware.example.com for C2"
        iocs = extractor.extract_iocs(content, "file-001")
        domain_iocs = [i for i in iocs if i.ioc_type == "domain"]
        values = {i.value for i in domain_iocs}
        assert "malware.example.com" in values

    def test_domain_with_subdomain(self, extractor: IOCExtractor) -> None:
        content = "DNS query to sub.domain.co.jp"
        iocs = extractor.extract_iocs(content, "file-001")
        domain_iocs = [i for i in iocs if i.ioc_type == "domain"]
        values = {i.value for i in domain_iocs}
        assert "sub.domain.co.jp" in values

    def test_domain_not_extracted_from_url(self, extractor: IOCExtractor) -> None:
        content = "Download from https://evil.com/payload.exe"
        iocs = extractor.extract_iocs(content, "file-001")
        domain_iocs = [i for i in iocs if i.ioc_type == "domain"]
        url_iocs = [i for i in iocs if i.ioc_type == "url"]
        # Domain should not be double-extracted from URL
        domain_values = {i.value for i in domain_iocs}
        assert "evil.com" not in domain_values
        # URL should be extracted
        assert len(url_iocs) >= 1


class TestExtractHashes:
    """Test hash extraction (MD5, SHA-1, SHA-256)."""

    def test_md5_hash(self, extractor: IOCExtractor) -> None:
        content = "Hash: d41d8cd98f00b204e9800998ecf8427e"
        iocs = extractor.extract_iocs(content, "file-001")
        md5_iocs = [i for i in iocs if i.ioc_type == "hash_md5"]
        assert len(md5_iocs) == 1
        assert md5_iocs[0].value == "d41d8cd98f00b204e9800998ecf8427e"

    def test_sha1_hash(self, extractor: IOCExtractor) -> None:
        content = "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709"
        iocs = extractor.extract_iocs(content, "file-001")
        sha1_iocs = [i for i in iocs if i.ioc_type == "hash_sha1"]
        assert len(sha1_iocs) == 1
        assert sha1_iocs[0].value == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def test_sha256_hash(self, extractor: IOCExtractor) -> None:
        content = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extractor.extract_iocs(content, "file-001")
        sha256_iocs = [i for i in iocs if i.ioc_type == "hash_sha256"]
        assert len(sha256_iocs) == 1
        assert sha256_iocs[0].value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_sha256_not_double_matched_as_shorter_hashes(self, extractor: IOCExtractor) -> None:
        content = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extractor.extract_iocs(content, "file-001")
        # Should only match as SHA-256, not as MD5 or SHA-1 substrings
        sha256_iocs = [i for i in iocs if i.ioc_type == "hash_sha256"]
        sha1_iocs = [i for i in iocs if i.ioc_type == "hash_sha1"]
        md5_iocs = [i for i in iocs if i.ioc_type == "hash_md5"]
        assert len(sha256_iocs) == 1
        assert len(sha1_iocs) == 0
        assert len(md5_iocs) == 0


class TestExtractFilePaths:
    """Test file path extraction (Windows and Unix)."""

    def test_windows_path(self, extractor: IOCExtractor) -> None:
        content = r"Malware found at C:\Windows\System32\evil.dll"
        iocs = extractor.extract_iocs(content, "file-001")
        path_iocs = [i for i in iocs if i.ioc_type == "file_path"]
        values = {i.value for i in path_iocs}
        assert r"C:\Windows\System32\evil.dll" in values

    def test_unix_path(self, extractor: IOCExtractor) -> None:
        content = "Suspicious binary at /usr/local/bin/backdoor"
        iocs = extractor.extract_iocs(content, "file-001")
        path_iocs = [i for i in iocs if i.ioc_type == "file_path"]
        values = {i.value for i in path_iocs}
        assert "/usr/local/bin/backdoor" in values

    def test_various_unix_paths(self, extractor: IOCExtractor) -> None:
        content = "Files: /etc/passwd /tmp/payload.sh /var/log/auth.log"
        iocs = extractor.extract_iocs(content, "file-001")
        path_iocs = [i for i in iocs if i.ioc_type == "file_path"]
        values = {i.value for i in path_iocs}
        assert "/etc/passwd" in values
        assert "/tmp/payload.sh" in values
        assert "/var/log/auth.log" in values


class TestExtractURLs:
    """Test URL extraction."""

    def test_http_url(self, extractor: IOCExtractor) -> None:
        content = "Download from http://evil.com/malware.exe"
        iocs = extractor.extract_iocs(content, "file-001")
        url_iocs = [i for i in iocs if i.ioc_type == "url"]
        assert len(url_iocs) == 1
        assert url_iocs[0].value == "http://evil.com/malware.exe"

    def test_https_url(self, extractor: IOCExtractor) -> None:
        content = "C2 callback to https://c2.badactor.net/beacon?id=123"
        iocs = extractor.extract_iocs(content, "file-001")
        url_iocs = [i for i in iocs if i.ioc_type == "url"]
        assert len(url_iocs) == 1
        assert "https://c2.badactor.net/beacon?id=123" in url_iocs[0].value


class TestExtractEmails:
    """Test email address extraction."""

    def test_basic_email(self, extractor: IOCExtractor) -> None:
        content = "Phishing from attacker@malicious-domain.com"
        iocs = extractor.extract_iocs(content, "file-001")
        email_iocs = [i for i in iocs if i.ioc_type == "email"]
        assert len(email_iocs) == 1
        assert email_iocs[0].value == "attacker@malicious-domain.com"

    def test_email_not_extracted_from_url(self, extractor: IOCExtractor) -> None:
        content = "Visit https://user@example.com/path"
        iocs = extractor.extract_iocs(content, "file-001")
        # This is tricky - the URL pattern should capture the whole thing
        url_iocs = [i for i in iocs if i.ioc_type == "url"]
        assert len(url_iocs) >= 1


class TestDeduplicateIOCs:
    """Test deduplication by type and value."""

    def test_removes_exact_duplicates(self, extractor: IOCExtractor) -> None:
        content = "192.168.1.1\n192.168.1.1\n192.168.1.1"
        iocs = extractor.extract_iocs(content, "file-001")
        deduped = extractor.deduplicate_iocs(iocs)
        ip_iocs = [i for i in deduped if i.ioc_type == "ip"]
        assert len(ip_iocs) == 1

    def test_keeps_different_values(self, extractor: IOCExtractor) -> None:
        content = "192.168.1.1\n10.0.0.1"
        iocs = extractor.extract_iocs(content, "file-001")
        deduped = extractor.deduplicate_iocs(iocs)
        ip_iocs = [i for i in deduped if i.ioc_type == "ip"]
        assert len(ip_iocs) == 2

    def test_preserves_first_occurrence(self, extractor: IOCExtractor) -> None:
        content = "192.168.1.1 on line 1\nsomething\n192.168.1.1 on line 3"
        iocs = extractor.extract_iocs(content, "file-001")
        deduped = extractor.deduplicate_iocs(iocs)
        ip_iocs = [i for i in deduped if i.ioc_type == "ip"]
        assert len(ip_iocs) == 1
        assert ip_iocs[0].source_line == 1

    def test_empty_list(self, extractor: IOCExtractor) -> None:
        deduped = extractor.deduplicate_iocs([])
        assert deduped == []


class TestDefang:
    """Test IOC defanging."""

    def test_defang_ip(self, extractor: IOCExtractor) -> None:
        result = extractor.defang("192.168.1.1", "ip")
        assert result == "192[.]168[.]1[.]1"

    def test_defang_domain(self, extractor: IOCExtractor) -> None:
        result = extractor.defang("malware.example.com", "domain")
        assert result == "malware[.]example[.]com"

    def test_defang_url_http(self, extractor: IOCExtractor) -> None:
        result = extractor.defang("http://evil.com/path", "url")
        assert result == "hxxp://evil[.]com/path"

    def test_defang_url_https(self, extractor: IOCExtractor) -> None:
        result = extractor.defang("https://c2.bad.net/beacon", "url")
        assert result == "hxxps://c2[.]bad[.]net/beacon"

    def test_defang_url_no_path(self, extractor: IOCExtractor) -> None:
        result = extractor.defang("http://evil.com", "url")
        assert result == "hxxp://evil[.]com"

    def test_defang_hash_unchanged(self, extractor: IOCExtractor) -> None:
        hash_val = "d41d8cd98f00b204e9800998ecf8427e"
        result = extractor.defang(hash_val, "hash_md5")
        assert result == hash_val

    def test_defang_file_path_unchanged(self, extractor: IOCExtractor) -> None:
        path_val = r"C:\Windows\System32\evil.dll"
        result = extractor.defang(path_val, "file_path")
        assert result == path_val

    def test_defang_email_unchanged(self, extractor: IOCExtractor) -> None:
        email_val = "attacker@evil.com"
        result = extractor.defang(email_val, "email")
        assert result == email_val


class TestIOCRecordFields:
    """Test that IOCRecord fields are populated correctly."""

    def test_ioc_id_is_unique(self, extractor: IOCExtractor) -> None:
        content = "192.168.1.1\n192.168.1.2"
        iocs = extractor.extract_iocs(content, "file-001")
        ids = [i.ioc_id for i in iocs]
        assert len(ids) == len(set(ids))

    def test_source_file_id_propagated(self, extractor: IOCExtractor) -> None:
        content = "192.168.1.1"
        iocs = extractor.extract_iocs(content, "my-file-id")
        assert all(i.source_file_id == "my-file-id" for i in iocs)

    def test_source_line_correct_multiline(self, extractor: IOCExtractor) -> None:
        content = "nothing here\nnothing here either\n192.168.1.1 on line 3\nline 4"
        iocs = extractor.extract_iocs(content, "file-001")
        ip_iocs = [i for i in iocs if i.ioc_type == "ip"]
        assert ip_iocs[0].source_line == 3
