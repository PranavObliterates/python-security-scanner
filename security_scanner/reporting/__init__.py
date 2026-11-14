"""Reporting modules for console, HTML, JSON, and PDF reports."""
from typing import Optional

from .console import print_report
from .json_report import save_json_report, generate_json_report
from .html_report import save_html_report, generate_html_report
from .sarif_report import save_sarif_report, generate_sarif_report
from .ai_advisor import get_session_api_key, generate_ai_security_summary
from ..models.scan_result import ScanResult


def save_pdf_report(
    result: ScanResult,
    filepath: str = "security_report.pdf",
    api_key: Optional[str] = None,
    prompt_for_key: bool = False,
) -> str:
    """Generate a PDF report (requires the optional ``pdf`` extra)."""
    try:
        from .pdf_report import save_pdf_report as generate_report
    except ImportError as exc:
        raise ImportError(
            "PDF reports require the optional dependency. Install with "
            "`pip install pysecure-scanner[pdf]`."
        ) from exc
    return generate_report(result, filepath, api_key, prompt_for_key)


__all__ = [
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
