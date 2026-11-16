"""ATT&CK mapping for the Analysis Layer.

Implements ATTCKMapper which maps evidence candidates and approved claims
to MITRE ATT&CK framework tactics and techniques, provides explanations
for mappings, and generates a mapping appendix for reports.

Requirements: 10.1, 10.2, 10.3, 10.4
"""

from typing import Optional

from ir_agent.models.analysis import Claim
from ir_agent.models.enums import ConfidenceLevel
from ir_agent.models.evidence import EvidenceCandidate, EvidenceLedgerEntry
from ir_agent.models.events import ATTCKMapping


# All 12 ATT&CK tactics supported per Requirement 10.3
ATTACK_TACTICS = [
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

# Keyword-to-technique mapping for heuristic-based ATT&CK classification.
# Each entry maps a keyword pattern to (tactic, technique_id, technique_name).
_TECHNIQUE_INDICATORS: list[tuple[list[str], str, str, str]] = [
    # Initial Access
    (
        ["phishing", "spearphishing", "malicious attachment", "malicious link"],
        "Initial Access",
        "T1566",
        "Phishing",
    ),
    (
        ["exploit public", "public-facing", "web server exploit", "vulnerability exploit"],
        "Initial Access",
        "T1190",
        "Exploit Public-Facing Application",
    ),
    (
        ["valid account", "compromised credential", "stolen credential", "reused password"],
        "Initial Access",
        "T1078",
        "Valid Accounts",
    ),
    (
        ["supply chain", "trusted relationship", "third-party"],
        "Initial Access",
        "T1195",
        "Supply Chain Compromise",
    ),
    # Execution
    (
        ["powershell", "pwsh", "powershell.exe"],
        "Execution",
        "T1059.001",
        "PowerShell",
    ),
    (
        ["cmd.exe", "command prompt", "cmd /c", "cmd /k"],
        "Execution",
        "T1059.003",
        "Windows Command Shell",
    ),
    (
        ["python", "python.exe", "python3", "script execution"],
        "Execution",
        "T1059.006",
        "Python",
    ),
    (
        ["wmic", "wmi ", "win32_process", "windows management instrumentation"],
        "Execution",
        "T1047",
        "Windows Management Instrumentation",
    ),
    (
        ["msbuild", "msbuild.exe"],
        "Defense Evasion",
        "T1127.001",
        "Trusted Developer Utilities Proxy Execution: MSBuild",
    ),
    (
        ["scheduled task", "schtasks", "at.exe", "cron"],
        "Execution",
        "T1053",
        "Scheduled Task/Job",
    ),
    # Persistence
    (
        ["registry run key", "hklm\\software\\microsoft\\windows\\currentversion\\run", "autorun"],
        "Persistence",
        "T1547.001",
        "Registry Run Keys / Startup Folder",
    ),
    (
        ["scheduled task", "schtasks /create", "crontab"],
        "Persistence",
        "T1053",
        "Scheduled Task/Job",
    ),
    (
        ["new service", "sc create", "service install", "systemd"],
        "Persistence",
        "T1543.003",
        "Windows Service",
    ),
    (
        ["web shell", "webshell", "backdoor web"],
        "Persistence",
        "T1505.003",
        "Web Shell",
    ),
    # Privilege Escalation
    (
        ["privilege escalation", "privilege elevation", "admin token", "uac bypass"],
        "Privilege Escalation",
        "T1548",
        "Abuse Elevation Control Mechanism",
    ),
    (
        ["exploit vulnerability", "local exploit", "kernel exploit", "cve-"],
        "Privilege Escalation",
        "T1068",
        "Exploitation for Privilege Escalation",
    ),
    (
        ["access token", "token manipulation", "impersonat"],
        "Privilege Escalation",
        "T1134",
        "Access Token Manipulation",
    ),
    # Defense Evasion
    (
        ["obfuscat", "encoded command", "base64", "-encodedcommand", "-enc "],
        "Defense Evasion",
        "T1027",
        "Obfuscated Files or Information",
    ),
    (
        ["disable antivirus", "disable defender", "tamper protection", "stop security"],
        "Defense Evasion",
        "T1562.001",
        "Disable or Modify Tools",
    ),
    (
        ["clear event log", "wevtutil cl", "log deletion", "log clearing",
         "audit log was cleared", "audit log cleared", "eventid=1102", "1102"],
        "Defense Evasion",
        "T1070.001",
        "Clear Windows Event Logs",
    ),
    (
        ["clear command history", "history truncated", "command history file truncated",
         "bash_history", "clear history"],
        "Defense Evasion",
        "T1070.003",
        "Clear Command History",
    ),
    (
        ["masquerad", "rename", "disguise"],
        "Defense Evasion",
        "T1036",
        "Masquerading",
    ),
    (
        ["timestomp", "timestamp modif"],
        "Defense Evasion",
        "T1070.006",
        "Timestomping",
    ),
    # Credential Access
    (
        ["mimikatz", "credential dump", "lsass", "procdump", "sekurlsa"],
        "Credential Access",
        "T1003",
        "OS Credential Dumping",
    ),
    (
        ["brute force", "password spray", "password guess"],
        "Credential Access",
        "T1110",
        "Brute Force",
    ),
    (
        ["keylog", "keystroke"],
        "Credential Access",
        "T1056.001",
        "Keylogging",
    ),
    (
        ["ntds.dit", "sam database", "shadow file", "/etc/shadow"],
        "Credential Access",
        "T1003.003",
        "NTDS",
    ),
    # Discovery
    (
        ["network scan", "port scan", "nmap", "network enumerat"],
        "Discovery",
        "T1046",
        "Network Service Discovery",
    ),
    (
        ["whoami", "system info", "systeminfo", "hostname", "uname"],
        "Discovery",
        "T1082",
        "System Information Discovery",
    ),
    (
        ["net user", "net group", "account enumerat", "user enumerat"],
        "Discovery",
        "T1087",
        "Account Discovery",
    ),
    (
        ["dir /s", "file enumerat", "find /", "ls -la"],
        "Discovery",
        "T1083",
        "File and Directory Discovery",
    ),
    # Lateral Movement
    (
        ["psexec", "remote execution", "wmiexec", "smbexec"],
        "Lateral Movement",
        "T1570",
        "Lateral Tool Transfer",
    ),
    (
        ["rdp", "remote desktop", "mstsc"],
        "Lateral Movement",
        "T1021.001",
        "Remote Desktop Protocol",
    ),
    (
        ["smb", "admin$", "c$", "ipc$", "windows admin share"],
        "Lateral Movement",
        "T1021.002",
        "SMB/Windows Admin Shares",
    ),
    (
        ["ssh", "ssh lateral", "ssh connection"],
        "Lateral Movement",
        "T1021.004",
        "SSH",
    ),
    (
        ["pass the hash", "pth", "overpass"],
        "Lateral Movement",
        "T1550.002",
        "Pass the Hash",
    ),
    # Collection
    (
        ["archive", "compress", "zip", "rar", "7z", "tar"],
        "Collection",
        "T1560",
        "Archive Collected Data",
    ),
    (
        ["screen capture", "screenshot"],
        "Collection",
        "T1113",
        "Screen Capture",
    ),
    (
        ["clipboard", "paste data"],
        "Collection",
        "T1115",
        "Clipboard Data",
    ),
    (
        ["email collect", "mailbox", "pst file"],
        "Collection",
        "T1114",
        "Email Collection",
    ),
    # Command and Control
    (
        ["c2", "c&c", "command and control", "beacon", "callback"],
        "Command and Control",
        "T1071",
        "Application Layer Protocol",
    ),
    (
        ["dns tunnel", "dns exfil", "dnscat"],
        "Command and Control",
        "T1071.004",
        "DNS",
    ),
    (
        ["http beacon", "https beacon", "http callback", "web c2"],
        "Command and Control",
        "T1071.001",
        "Web Protocols",
    ),
    (
        ["proxy", "multi-hop", "relay"],
        "Command and Control",
        "T1090",
        "Proxy",
    ),
    (
        ["encrypted channel", "tls tunnel", "encrypted c2"],
        "Command and Control",
        "T1573",
        "Encrypted Channel",
    ),
    (
        ["socks5", "gost", "socks proxy"],
        "Command and Control",
        "T1090",
        "Proxy",
    ),
    # Exfiltration
    (
        ["exfiltrat", "data theft", "data steal", "upload data"],
        "Exfiltration",
        "T1041",
        "Exfiltration Over C2 Channel",
    ),
    (
        ["sftp", "scp ", "ftp upload", "alternative protocol"],
        "Exfiltration",
        "T1048",
        "Exfiltration Over Alternative Protocol",
    ),
    (
        ["cloud storage", "mega.nz", "dropbox", "google drive", "onedrive"],
        "Exfiltration",
        "T1567.002",
        "Exfiltration to Cloud Storage",
    ),
    (
        ["dns exfil", "dns tunnel"],
        "Exfiltration",
        "T1048.003",
        "Exfiltration Over Unencrypted Non-C2 Protocol",
    ),
    # Impact
    (
        ["ransomware", "encrypt files", "ransom note", "decrypt"],
        "Impact",
        "T1486",
        "Data Encrypted for Impact",
    ),
    (
        ["wipe", "destroy data", "disk wipe", "overwrite"],
        "Impact",
        "T1485",
        "Data Destruction",
    ),
    (
        ["defac", "web defacement"],
        "Impact",
        "T1491",
        "Defacement",
    ),
    (
        ["dos", "denial of service", "ddos", "resource exhaust"],
        "Impact",
        "T1499",
        "Endpoint Denial of Service",
    ),
]


class ATTCKMapper:
    """Maps evidence and claims to MITRE ATT&CK framework techniques.

    Provides heuristic keyword-based mapping of evidence candidates and
    approved claims to ATT&CK tactics and techniques. Supports all 12
    ATT&CK tactics listed in Requirement 10.3.

    Requirements: 10.1, 10.2, 10.3, 10.4
    """

    def __init__(self) -> None:
        """Initialize ATTCKMapper with supported tactics."""
        self.supported_tactics: list[str] = list(ATTACK_TACTICS)

    def map_evidence_candidate(
        self,
        candidate: EvidenceCandidate,
        context: dict,
    ) -> list[ATTCKMapping]:
        """Suggest ATT&CK technique candidates for an evidence candidate.

        Analyzes the observed_fact, interpretation, observed_event, and
        context to determine which ATT&CK techniques the evidence may
        indicate.

        Requirement 10.1: Suggest ATT_CK_Mapping candidates for each
        evidence candidate during extraction.

        Args:
            candidate: The evidence candidate to map.
            context: Additional context dict (e.g., host info, case scope).

        Returns:
            List of ATTCKMapping objects with suggested technique mappings.
        """
        mappings: list[ATTCKMapping] = []
        seen_techniques: set[str] = set()

        # Build searchable text from candidate fields
        search_text = self._build_search_text_from_candidate(candidate, context)

        # Match against technique indicators
        for keywords, tactic, technique_id, technique_name in _TECHNIQUE_INDICATORS:
            if technique_id in seen_techniques:
                continue

            match_result = self._match_keywords(keywords, search_text)
            if match_result is not None:
                matched_keyword, match_count = match_result
                confidence = self._calculate_mapping_confidence(
                    match_count=match_count,
                    source_confidence=candidate.interpretation_confidence,
                )
                mapping = ATTCKMapping(
                    tactic=tactic,
                    technique_id=technique_id,
                    technique_name=technique_name,
                    confidence=confidence,
                    mapping_reason=(
                        f"Evidence text matches indicator '{matched_keyword}' "
                        f"associated with {technique_name} ({technique_id})"
                    ),
                )
                mappings.append(mapping)
                seen_techniques.add(technique_id)

        return mappings

    def map_claim(
        self,
        claim: Claim,
        ledger: list[EvidenceLedgerEntry],
    ) -> list[ATTCKMapping]:
        """Map an approved claim to ATT&CK techniques.

        Uses the claim text, supporting evidence from the ledger, and
        any existing attack_mappings on the claim to produce a consolidated
        set of ATT&CK technique mappings.

        Requirement 10.2: Include ATT_CK_Mapping references for each
        claim where applicable.

        Args:
            claim: The approved claim to map.
            ledger: List of approved evidence ledger entries.

        Returns:
            List of ATTCKMapping objects for this claim.
        """
        mappings: list[ATTCKMapping] = []
        seen_techniques: set[str] = set()

        # First, include any existing mappings already on the claim
        for existing in claim.attack_mappings:
            if existing.technique_id not in seen_techniques:
                mappings.append(existing)
                seen_techniques.add(existing.technique_id)

        # Build searchable text from claim and its supporting evidence
        search_text = self._build_search_text_from_claim(claim, ledger)

        # Match against technique indicators
        for keywords, tactic, technique_id, technique_name in _TECHNIQUE_INDICATORS:
            if technique_id in seen_techniques:
                continue

            match_result = self._match_keywords(keywords, search_text)
            if match_result is not None:
                matched_keyword, match_count = match_result
                confidence = self._calculate_mapping_confidence(
                    match_count=match_count,
                    source_confidence=claim.confidence_level,
                )
                mapping = ATTCKMapping(
                    tactic=tactic,
                    technique_id=technique_id,
                    technique_name=technique_name,
                    confidence=confidence,
                    mapping_reason=(
                        f"Claim text matches indicator '{matched_keyword}' "
                        f"associated with {technique_name} ({technique_id})"
                    ),
                )
                mappings.append(mapping)
                seen_techniques.add(technique_id)

        return mappings

    def explain_mapping(
        self,
        mapping: ATTCKMapping,
        evidence_ids: list[str],
    ) -> str:
        """Provide a human-readable rationale for an ATT&CK mapping.

        Generates an explanation string describing why the evidence was
        mapped to a particular technique, including the tactic context
        and supporting evidence IDs.

        Args:
            mapping: The ATT&CK mapping to explain.
            evidence_ids: List of evidence IDs supporting this mapping.

        Returns:
            Human-readable explanation string.
        """
        evidence_list = ", ".join(evidence_ids) if evidence_ids else "none"

        explanation = (
            f"Technique: {mapping.technique_name} ({mapping.technique_id})\n"
            f"Tactic: {mapping.tactic}\n"
            f"Confidence: {mapping.confidence.value}\n"
            f"Mapping Reason: {mapping.mapping_reason}\n"
            f"Supporting Evidence: {evidence_list}"
        )

        return explanation

    def generate_mapping_appendix(
        self,
        approved_claims: list[Claim],
    ) -> list[dict]:
        """Generate a MITRE ATT&CK mapping appendix for report output.

        Collects all ATT&CK mappings from approved claims and organizes
        them by tactic for inclusion as a report appendix.

        Requirement 10.4: Include a MITRE ATT&CK mapping appendix in
        generated reports.

        Args:
            approved_claims: List of approved claims with attack_mappings.

        Returns:
            List of dicts representing appendix entries, each containing:
            tactic, technique_id, technique_name, confidence,
            mapping_reason, claim_ids, and evidence_ids.
        """
        # Aggregate mappings by technique_id
        technique_aggregation: dict[str, dict] = {}

        for claim in approved_claims:
            for mapping in claim.attack_mappings:
                key = mapping.technique_id
                if key not in technique_aggregation:
                    technique_aggregation[key] = {
                        "tactic": mapping.tactic,
                        "technique_id": mapping.technique_id,
                        "technique_name": mapping.technique_name,
                        "confidence": mapping.confidence.value,
                        "mapping_reason": mapping.mapping_reason,
                        "claim_ids": [],
                        "evidence_ids": [],
                    }

                # Add claim reference
                if claim.claim_id not in technique_aggregation[key]["claim_ids"]:
                    technique_aggregation[key]["claim_ids"].append(claim.claim_id)

                # Add supporting evidence references
                for eid in claim.supporting_evidence:
                    if eid not in technique_aggregation[key]["evidence_ids"]:
                        technique_aggregation[key]["evidence_ids"].append(eid)

                # Upgrade confidence if a higher confidence mapping is found
                existing_conf = ConfidenceLevel(
                    technique_aggregation[key]["confidence"]
                )
                if self._confidence_rank(mapping.confidence) > self._confidence_rank(
                    existing_conf
                ):
                    technique_aggregation[key]["confidence"] = mapping.confidence.value
                    technique_aggregation[key]["mapping_reason"] = mapping.mapping_reason

        # Sort by tactic order, then by technique_id
        tactic_order = {t: i for i, t in enumerate(ATTACK_TACTICS)}
        appendix_entries = sorted(
            technique_aggregation.values(),
            key=lambda x: (
                tactic_order.get(x["tactic"], len(ATTACK_TACTICS)),
                x["technique_id"],
            ),
        )

        return appendix_entries

    # ------------------------------------------------------------------
    # Private helper methods
    # ------------------------------------------------------------------

    def _build_search_text_from_candidate(
        self,
        candidate: EvidenceCandidate,
        context: dict,
    ) -> str:
        """Build a searchable text string from an evidence candidate.

        Combines observed_fact, interpretation, command_line from
        observed_event, and context values into a single lowercase string.

        Args:
            candidate: The evidence candidate.
            context: Additional context dictionary.

        Returns:
            Lowercased combined text for keyword matching.
        """
        parts: list[str] = [
            candidate.observed_fact,
            candidate.interpretation,
        ]

        # Extract relevant fields from observed_event
        observed = candidate.observed_event
        if observed:
            for field_name in (
                "command_line",
                "process_name",
                "event_type",
                "file_path",
                "description",
                "summary",
                "raw_excerpt",
            ):
                value = observed.get(field_name)
                if value and isinstance(value, str):
                    parts.append(value)

            # Check for nested data
            if "details" in observed and isinstance(observed["details"], str):
                parts.append(observed["details"])

        # Include context values
        for key, value in context.items():
            if isinstance(value, str):
                parts.append(value)

        return " ".join(parts).lower()

    def _build_search_text_from_claim(
        self,
        claim: Claim,
        ledger: list[EvidenceLedgerEntry],
    ) -> str:
        """Build a searchable text string from a claim and its evidence.

        Combines claim_text with observed_fact and interpretation from
        each supporting evidence entry in the ledger.

        Args:
            claim: The claim to analyze.
            ledger: Full evidence ledger.

        Returns:
            Lowercased combined text for keyword matching.
        """
        parts: list[str] = [claim.claim_text]

        # Build a lookup of ledger entries by evidence_id
        ledger_map: dict[str, EvidenceLedgerEntry] = {
            entry.evidence_id: entry for entry in ledger
        }

        # Include supporting evidence text
        for evidence_id in claim.supporting_evidence:
            entry = ledger_map.get(evidence_id)
            if entry and not entry.withdrawn:
                parts.append(entry.observed_fact)
                parts.append(entry.interpretation)

                # Include command_line and process from observed_event
                observed = entry.observed_event
                if observed:
                    for field_name in (
                        "command_line",
                        "process_name",
                        "event_type",
                        "file_path",
                    ):
                        value = observed.get(field_name)
                        if value and isinstance(value, str):
                            parts.append(value)

        return " ".join(parts).lower()

    def _match_keywords(
        self,
        keywords: list[str],
        text: str,
    ) -> Optional[tuple[str, int]]:
        """Check if any keywords match in the given text.

        Args:
            keywords: List of keyword patterns to search for.
            text: Lowercased text to search in.

        Returns:
            Tuple of (first matched keyword, total match count) if found,
            None otherwise.
        """
        first_match: Optional[str] = None
        match_count = 0

        for keyword in keywords:
            if keyword.lower() in text:
                match_count += 1
                if first_match is None:
                    first_match = keyword

        if first_match is None:
            return None

        return (first_match, match_count)

    def _calculate_mapping_confidence(
        self,
        match_count: int,
        source_confidence: ConfidenceLevel,
    ) -> ConfidenceLevel:
        """Calculate mapping confidence based on match quality and source.

        The mapping confidence is influenced by:
        - Number of keyword matches (more matches = higher confidence)
        - The confidence level of the source evidence/claim

        The mapping confidence should never exceed the source confidence.

        Args:
            match_count: Number of keyword matches found.
            source_confidence: Confidence of the source evidence or claim.

        Returns:
            Calculated confidence level for the mapping.
        """
        source_rank = self._confidence_rank(source_confidence)

        # Base mapping confidence from match count
        if match_count >= 3:
            base_rank = 4  # confirmed
        elif match_count >= 2:
            base_rank = 3  # probable
        else:
            base_rank = 2  # possible

        # Cap at source confidence — mapping can't be more confident
        # than the underlying evidence
        final_rank = min(base_rank, source_rank)

        return self._rank_to_confidence(final_rank)

    def _confidence_rank(self, confidence: ConfidenceLevel) -> int:
        """Convert confidence level to a numeric rank for comparison.

        Args:
            confidence: A ConfidenceLevel enum value.

        Returns:
            Integer rank (higher = more confident).
        """
        rank_map = {
            ConfidenceLevel.CONFIRMED: 4,
            ConfidenceLevel.PROBABLE: 3,
            ConfidenceLevel.POSSIBLE: 2,
            ConfidenceLevel.UNKNOWN: 1,
            ConfidenceLevel.NOT_OBSERVED: 0,
        }
        return rank_map.get(confidence, 1)

    def _rank_to_confidence(self, rank: int) -> ConfidenceLevel:
        """Convert a numeric rank back to a ConfidenceLevel.

        Args:
            rank: Integer rank value.

        Returns:
            Corresponding ConfidenceLevel enum value.
        """
        if rank >= 4:
            return ConfidenceLevel.CONFIRMED
        elif rank >= 3:
            return ConfidenceLevel.PROBABLE
        elif rank >= 2:
            return ConfidenceLevel.POSSIBLE
        elif rank >= 1:
            return ConfidenceLevel.UNKNOWN
        else:
            return ConfidenceLevel.NOT_OBSERVED
