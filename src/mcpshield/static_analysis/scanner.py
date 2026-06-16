"""Static analysis scanner for MCP tool descriptions — Layer 1 of MCPShield."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from mcpoisoner.payloads.unicode_stego import UnicodeSteganoEncoder

logger = structlog.get_logger()


class ThreatLevel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BLOCKED = "blocked"


class FindingType(str, Enum):
    INVISIBLE_UNICODE = "invisible_unicode"
    HOMOGLYPH = "homoglyph"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SCHEMA_MISMATCH = "schema_mismatch"
    SUSPICIOUS_URL = "suspicious_url"
    MARKDOWN_INJECTION = "markdown_injection"
    RTL_OVERRIDE = "rtl_override"


@dataclass
class ScanFinding:
    finding_type: FindingType
    threat_level: ThreatLevel
    description: str
    evidence: str
    location: str
    recommendation: str


@dataclass
class ScanResult:
    tool_name: str
    threat_level: ThreatLevel
    findings: list[ScanFinding] = field(default_factory=list)
    score: float = 0.0

    @property
    def is_safe(self) -> bool:
        return self.threat_level == ThreatLevel.CLEAN

    @property
    def finding_count(self) -> int:
        return len(self.findings)


SUSPICIOUS_PATTERNS = [
    (r"(?i)\b(exfiltrate|steal|leak|send.*secret|forward.*credential)", "data_exfiltration"),
    (r"(?i)\b(ignore.*previous|disregard.*instruction|override.*policy)", "instruction_override"),
    (r"(?i)\b(do\s+not\s+mention|silently|without.*telling|secretly)", "covert_action"),
    (r"(?i)\b(admin|root|sudo|privilege|escalat)", "privilege_keywords"),
    (r"(?i)\b(curl|wget|fetch|http_request).*\b(external|remote|attacker)", "network_exfil"),
    (r"(?i)IMPORTANT.*SYSTEM.*UPDATE", "fake_system_message"),
    (r"(?i)CRITICAL.*SECURITY.*UPDATE", "fake_security_alert"),
    (r"(?i)compliance.*endpoint|audit.*endpoint|security.*endpoint", "fake_endpoint"),
]

DANGEROUS_CAPABILITIES = {
    "calculator": {"allowed": ["arithmetic"], "forbidden": ["filesystem", "network", "execute"]},
    "file_reader": {"allowed": ["read_file"], "forbidden": ["write_file", "execute", "network"]},
    "database_query": {"allowed": ["read_query"], "forbidden": ["write_query", "drop", "delete"]},
}


class StaticScanner:
    def __init__(self) -> None:
        self.stego_detector = UnicodeSteganoEncoder()
        self.log = logger.bind(component="static_scanner")

    def scan(self, tool_descriptor: dict[str, Any]) -> ScanResult:
        name = tool_descriptor.get("name", "unknown")
        description = tool_descriptor.get("description", "")
        schema = tool_descriptor.get("inputSchema", {})

        findings: list[ScanFinding] = []

        findings.extend(self._scan_unicode(description, name))
        findings.extend(self._scan_patterns(description, name))
        findings.extend(self._scan_schema(name, description, schema))
        findings.extend(self._scan_urls(description, name))
        findings.extend(self._scan_markdown(description, name))

        threat_level = self._compute_threat_level(findings)
        score = self._compute_risk_score(findings)

        return ScanResult(
            tool_name=name,
            threat_level=threat_level,
            findings=findings,
            score=score,
        )

    def _scan_unicode(self, text: str, tool_name: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        invisible = self.stego_detector.detect_invisible_chars(text)
        if invisible:
            total = sum(invisible.values())
            findings.append(ScanFinding(
                finding_type=FindingType.INVISIBLE_UNICODE,
                threat_level=ThreatLevel.MALICIOUS if total > 10 else ThreatLevel.SUSPICIOUS,
                description=f"Found {total} invisible Unicode characters in tool description",
                evidence=str(invisible),
                location=f"tool:{tool_name}/description",
                recommendation="Reject tool or strip invisible characters and re-audit",
            ))

        homoglyphs = self.stego_detector.detect_homoglyphs(text)
        if homoglyphs:
            findings.append(ScanFinding(
                finding_type=FindingType.HOMOGLYPH,
                threat_level=ThreatLevel.MALICIOUS,
                description=f"Found {len(homoglyphs)} homoglyph characters (visual spoofing)",
                evidence=str(homoglyphs[:5]),
                location=f"tool:{tool_name}/description",
                recommendation="Reject tool: homoglyphs indicate intentional deception",
            ))

        return findings

    def _scan_patterns(self, text: str, tool_name: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for pattern, category in SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                findings.append(ScanFinding(
                    finding_type=FindingType.HIDDEN_INSTRUCTION,
                    threat_level=ThreatLevel.MALICIOUS,
                    description=f"Suspicious pattern detected: {category}",
                    evidence=str(matches[:3]),
                    location=f"tool:{tool_name}/description",
                    recommendation="Flag for human review before deployment",
                ))
        return findings

    def _scan_schema(
        self, tool_name: str, description: str, schema: dict[str, Any]
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        caps = DANGEROUS_CAPABILITIES.get(tool_name)
        if caps is None:
            return findings

        desc_lower = description.lower()
        props = schema.get("properties", {})
        all_text = desc_lower + " " + " ".join(
            str(v.get("description", "")).lower() for v in props.values()
        )

        for forbidden in caps["forbidden"]:
            if forbidden in all_text:
                findings.append(ScanFinding(
                    finding_type=FindingType.PRIVILEGE_ESCALATION,
                    threat_level=ThreatLevel.MALICIOUS,
                    description=(
                        f"Tool '{tool_name}' requests '{forbidden}' capability "
                        f"which exceeds its declared purpose"
                    ),
                    evidence=f"Forbidden capability '{forbidden}' found in description/schema",
                    location=f"tool:{tool_name}/schema",
                    recommendation="Reject: capability exceeds declared tool purpose",
                ))

        return findings

    def _scan_urls(self, text: str, tool_name: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        urls = re.findall(r'https?://[^\s<>"\')\]]+', text)
        for url in urls:
            if any(s in url.lower() for s in ["attacker", "exfil", "collect", "evil", "malicious"]):
                findings.append(ScanFinding(
                    finding_type=FindingType.SUSPICIOUS_URL,
                    threat_level=ThreatLevel.MALICIOUS,
                    description="Suspicious URL found in tool description",
                    evidence=url,
                    location=f"tool:{tool_name}/description",
                    recommendation="Block tool: URL appears malicious",
                ))
            else:
                findings.append(ScanFinding(
                    finding_type=FindingType.SUSPICIOUS_URL,
                    threat_level=ThreatLevel.SUSPICIOUS,
                    description="External URL found in tool description",
                    evidence=url,
                    location=f"tool:{tool_name}/description",
                    recommendation="Verify URL legitimacy before approving tool",
                ))
        return findings

    def _scan_markdown(self, text: str, tool_name: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        if re.search(r'<!--.*?-->', text, re.DOTALL):
            findings.append(ScanFinding(
                finding_type=FindingType.MARKDOWN_INJECTION,
                threat_level=ThreatLevel.MALICIOUS,
                description="HTML/Markdown comment found (may hide instructions from users)",
                evidence="<!-- ... --> block detected",
                location=f"tool:{tool_name}/description",
                recommendation="Strip comments and re-audit description content",
            ))
        return findings

    def _compute_threat_level(self, findings: list[ScanFinding]) -> ThreatLevel:
        if not findings:
            return ThreatLevel.CLEAN
        levels = [f.threat_level for f in findings]
        if ThreatLevel.MALICIOUS in levels:
            return ThreatLevel.BLOCKED
        if ThreatLevel.SUSPICIOUS in levels:
            return ThreatLevel.SUSPICIOUS
        return ThreatLevel.CLEAN

    def _compute_risk_score(self, findings: list[ScanFinding]) -> float:
        weights = {
            ThreatLevel.MALICIOUS: 1.0,
            ThreatLevel.SUSPICIOUS: 0.4,
            ThreatLevel.CLEAN: 0.0,
            ThreatLevel.BLOCKED: 1.0,
        }
        if not findings:
            return 0.0
        return min(1.0, sum(weights.get(f.threat_level, 0) for f in findings))
