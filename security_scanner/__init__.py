"""Python Security Scanner Library — Embedded security scanning for web apps."""
from .core.scanner import scan_app
from .models.finding import Finding, Severity, VulnerabilityType
from .models.scan_result import ScanResult

__version__ = "0.1.0"
__all__ = ["scan_app", "Finding", "Severity", "VulnerabilityType", "ScanResult"]
