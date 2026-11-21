"""WebVenom — OWASP Top 10 SAST + DAST Security Scanner for Python Web Applications.

Detects all OWASP Top 10 (2021) vulnerability classes:
  A01 Path Traversal & Open Redirect, A02 Hardcoded Secrets & Weak Crypto,
  A03 SQLi / XSS / SSTI / Command Injection, A05 Security Misconfiguration,
  A06 Vulnerable Components, A07 Broken Auth (JWT), A08 Insecure Deserialization,
  A10 SSRF — plus Gemini AI-powered PDF executive reporting.

Usage:
    from webvenom import scan_app, print_report
    result = scan_app(app)
    print_report(result)
"""
from security_scanner.core.scanner import scan_app
from security_scanner.models.finding import Finding, Severity, VulnerabilityType
from security_scanner.models.scan_result import ScanResult
from security_scanner.reporting.console import print_report
from security_scanner.reporting.json_report import save_json_report, generate_json_report
from security_scanner.reporting.html_report import save_html_report, generate_html_report
from security_scanner.reporting.pdf_report import save_pdf_report
from security_scanner.reporting.sarif_report import save_sarif_report, generate_sarif_report
from security_scanner.reporting.ai_advisor import get_session_api_key, generate_ai_security_summary
from security_scanner.dynamic.remote import scan_remote_url

__version__ = "0.3.0"
__all__ = [
    "scan_app",
    "Finding",
    "Severity",
    "VulnerabilityType",
    "ScanResult",
    "print_report",
    "save_json_report",
    "generate_json_report",
    "save_html_report",
    "generate_html_report",
    "save_pdf_report",
    "save_sarif_report",
    "generate_sarif_report",
    "get_session_api_key",
    "generate_ai_security_summary",
    "scan_remote_url",
]
