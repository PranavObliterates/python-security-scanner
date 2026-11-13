"""PySecure — Embedded SAST + DAST Security Scanner for Python Web Applications.

Detects OWASP Top 10 vulnerabilities (SQLi, XSS, Command Injection, Path Traversal,
SSRF, SSTI, Insecure Deserialization, Hardcoded Secrets, CSRF, and Misconfigurations).
Includes Gemini AI-powered PDF security audit reporting.
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

__version__ = "0.2.0"
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
]
