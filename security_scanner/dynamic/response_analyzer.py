"""Response analyzer — examines HTTP responses for signs of vulnerabilities."""
import re
from typing import List, Optional
from ..models.finding import Finding, Severity, VulnerabilityType


# Database error patterns that confirm SQL injection
DB_ERROR_PATTERNS = [
    r"sql\s*syntax",
    r"mysql",
    r"sqlite3\.OperationalError",
    r"psycopg2",
    r"ORA-\d{5}",
    r"unclosed quotation",
    r"unterminated string",
    r"SQLSTATE",
    r"syntax error",
    r"near \"",
    r"unrecognized token",
    r"ProgrammingError",
    r"DatabaseError",
    r"OperationalError",
]

DB_ERROR_REGEX = re.compile("|".join(DB_ERROR_PATTERNS), re.IGNORECASE)

# Security headers to check
RECOMMENDED_HEADERS = {
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "Content-Security-Policy (CSP) header is missing. CSP helps prevent "
        "XSS attacks by restricting which resources can be loaded."
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "X-Content-Type-Options header is missing. This header prevents MIME "
        "type sniffing, which can lead to security vulnerabilities."
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "X-Frame-Options header is missing. Without it, your site can be "
        "loaded in an iframe, enabling clickjacking attacks."
    ),
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "Strict-Transport-Security (HSTS) header is missing. HSTS ensures "
        "all communication uses HTTPS, preventing downgrade attacks."
    ),
}


def check_response_for_sqli(response_body: str) -> bool:
    """Check if a response body contains database error patterns.

    Returns True if SQL injection appears confirmed.
    """
    return bool(DB_ERROR_REGEX.search(response_body))


def check_response_for_xss(response_body: str, payload: str) -> bool:
    """Check if an XSS payload is reflected unescaped in the response.

    Returns True if the exact payload appears in the response body.
    """
    return payload in response_body


def check_security_headers(response_headers: dict, endpoint: str) -> List[Finding]:
    """Check response headers for missing security headers.

    Returns a list of findings for each missing recommended header.
    """
    findings = []
    for header_name, (severity, explanation) in RECOMMENDED_HEADERS.items():
        if header_name not in response_headers:
            findings.append(Finding(
                vuln_type=VulnerabilityType.MISSING_SECURITY_HEADER,
                severity=severity,
                endpoint=endpoint,
                file="HTTP response",
                line=0,
                code_snippet=f"Missing header: {header_name}",
                explanation=explanation,
                fix_recommendation=f"Add the {header_name} header to your responses.",
                fix_before="# No security headers set",
                fix_after=f'response.headers["{header_name}"] = "..appropriate value.."',
                source="DAST",
            ))
    return findings


def check_cookie_security(response_headers: dict, endpoint: str) -> List[Finding]:
    """Check Set-Cookie headers for missing security flags.

    Checks for: HttpOnly, Secure, SameSite flags.
    """
    findings = []
    set_cookie = response_headers.get("Set-Cookie", "")
    if not set_cookie:
        return findings

    cookie_lower = set_cookie.lower()

    if "httponly" not in cookie_lower:
        findings.append(Finding(
            vuln_type=VulnerabilityType.INSECURE_COOKIE,
            severity=Severity.MEDIUM,
            endpoint=endpoint,
            file="HTTP response",
            line=0,
            code_snippet=f"Set-Cookie: {set_cookie[:80]}...",
            explanation=(
                "Cookie is missing the HttpOnly flag. Without it, JavaScript "
                "can access the cookie via document.cookie, making it easy for "
                "XSS attacks to steal session tokens."
            ),
            fix_recommendation="Add HttpOnly flag to sensitive cookies.",
            fix_before='response.set_cookie("session", value)',
            fix_after='response.set_cookie("session", value, httponly=True)',
            source="DAST",
        ))

    if "secure" not in cookie_lower:
        findings.append(Finding(
            vuln_type=VulnerabilityType.INSECURE_COOKIE,
            severity=Severity.LOW,
            endpoint=endpoint,
            file="HTTP response",
            line=0,
            code_snippet=f"Set-Cookie: {set_cookie[:80]}...",
            explanation=(
                "Cookie is missing the Secure flag. Without it, the cookie "
                "can be sent over unencrypted HTTP, allowing interception."
            ),
            fix_recommendation="Add Secure flag to cookies.",
            fix_before='response.set_cookie("session", value)',
            fix_after='response.set_cookie("session", value, secure=True)',
            source="DAST",
        ))

    return findings
