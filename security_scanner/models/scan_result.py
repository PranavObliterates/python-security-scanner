"""Container for all scan findings."""
from dataclasses import dataclass, field
from typing import List
from .finding import Finding, Severity


@dataclass
class ScanResult:
    app_name: str
    findings: List[Finding] = field(default_factory=list)
    routes_scanned: int = 0
    scan_duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0

    def summary(self) -> str:
        # Use a fixed order for summary display
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        parts = []
        for sev in severity_order:
            count = sum(1 for f in self.findings if f.severity == sev)
            if count > 0:
                parts.append(f"{count} {sev.value}")
        return " | ".join(parts) if parts else "No issues found"
