"""Python Security Scanner Library — Embedded security scanning for web apps."""
from .core.scanner import scan_app
from .models.finding import Finding, Severity, VulnerabilityType
from .models.scan_result import ScanResult
from .reporting.console import print_report
from .reporting.json_report import save_json_report
from .reporting.html_report import save_html_report
from .reporting.pdf_report import save_pdf_report

__version__ = "0.2.0"
__all__ = [
    "scan_app",
    "Finding",
    "Severity",
    "VulnerabilityType",
    "ScanResult",
    "print_report",
    "save_json_report",
    "save_html_report",
    "save_pdf_report",
]
