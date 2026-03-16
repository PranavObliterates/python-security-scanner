"""Reporting module — console, JSON, and HTML report generation."""
from .console import print_report
from .json_report import generate_json_report, save_json_report
from .html_report import generate_html_report, save_html_report

__all__ = [
    "print_report",
    "generate_json_report", "save_json_report",
    "generate_html_report", "save_html_report",
]
