"""Python Security Scanner Library — Embedded security scanning for web apps."""
from typing import Optional

from .core.scanner import scan_app
from .models.finding import Finding, Severity, VulnerabilityType
from .models.scan_result import ScanResult
from .reporting.console import print_report
from .reporting.json_report import save_json_report
from .reporting.html_report import save_html_report
from .dynamic.remote import scan_remote_url


def save_pdf_report(
    result: ScanResult,
    filepath: str = "security_report.pdf",
    api_key: Optional[str] = None,
    prompt_for_key: bool = False,
) -> str:
    """Generate a PDF report (requires the optional ``pdf`` extra)."""
    try:
        from .reporting.pdf_report import save_pdf_report as generate_report
    except ImportError as exc:
        raise ImportError(
            "PDF reports require the optional dependency. Install with "
            "`pip install pysecure-scanner[pdf]`."
        ) from exc
    return generate_report(result, filepath, api_key, prompt_for_key)


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
    "scan_remote_url",
]
