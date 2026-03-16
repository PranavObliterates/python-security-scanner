"""Data models for scan findings and results."""
from .finding import Finding, Severity, VulnerabilityType
from .scan_result import ScanResult

__all__ = ["Finding", "Severity", "VulnerabilityType", "ScanResult"]
