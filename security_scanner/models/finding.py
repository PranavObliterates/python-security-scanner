"""Data model for a single security finding."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(Enum):
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    CSRF_MISSING = "CSRF_MISSING"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    DEBUG_MODE = "DEBUG_MODE"
    INSECURE_COOKIE = "INSECURE_COOKIE"
    MISSING_SECURITY_HEADER = "MISSING_SECURITY_HEADER"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    SSTI = "SSTI"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    WEAK_CRYPTO = "WEAK_CRYPTO"

    @property
    def owasp_category(self) -> str:
        mapping = {
            VulnerabilityType.SQL_INJECTION: "A03:2021 - Injection",
            VulnerabilityType.COMMAND_INJECTION: "A03:2021 - Injection",
            VulnerabilityType.XSS: "A03:2021 - Injection",
            VulnerabilityType.SSTI: "A03:2021 - Injection",
            VulnerabilityType.PATH_TRAVERSAL: "A01:2021 - Broken Access Control",
            VulnerabilityType.OPEN_REDIRECT: "A01:2021 - Broken Access Control",
            VulnerabilityType.CSRF_MISSING: "A01:2021 - Broken Access Control",
            VulnerabilityType.HARDCODED_SECRET: "A02:2021 - Cryptographic Failures",
            VulnerabilityType.WEAK_CRYPTO: "A02:2021 - Cryptographic Failures",
            VulnerabilityType.SENSITIVE_DATA_EXPOSURE: "A02:2021 - Cryptographic Failures",
            VulnerabilityType.DEBUG_MODE: "A05:2021 - Security Misconfiguration",
            VulnerabilityType.INSECURE_COOKIE: "A05:2021 - Security Misconfiguration",
            VulnerabilityType.MISSING_SECURITY_HEADER: "A05:2021 - Security Misconfiguration",
            VulnerabilityType.INSECURE_DESERIALIZATION: "A08:2021 - Software and Data Integrity Failures",
            VulnerabilityType.SSRF: "A10:2021 - Server-Side Request Forgery",
        }
        return mapping.get(self, "OWASP Top 10")


@dataclass
class Finding:
    vuln_type: VulnerabilityType
    severity: Severity
    endpoint: str
    file: str
    line: int
    code_snippet: str
    explanation: str
    fix_recommendation: str
    fix_before: str = ""
    fix_after: str = ""
    reference: str = ""
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    source: str = "SAST"     # SAST or DAST
