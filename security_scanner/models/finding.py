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
