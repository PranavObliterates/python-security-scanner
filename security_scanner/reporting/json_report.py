"""Generate JSON report from scan results."""
import json
from datetime import datetime
from ..models.scan_result import ScanResult


def generate_json_report(result: ScanResult) -> str:
    """Convert scan results to a JSON string."""
    report = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "app_name": result.app_name,
        "routes_scanned": result.routes_scanned,
        "scan_duration_seconds": round(result.scan_duration_seconds, 3),
        "summary": {
            "total_issues": len(result.findings),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
        },
        "findings": [],
    }

    for finding in result.findings:
        report["findings"].append({
            "type": finding.vuln_type.value,
            "severity": finding.severity.value,
            "source": finding.source,
            "endpoint": finding.endpoint,
            "file": finding.file,
            "line": finding.line,
            "code": finding.code_snippet,
            "explanation": finding.explanation,
            "fix": finding.fix_recommendation,
            "fix_before": finding.fix_before,
            "fix_after": finding.fix_after,
            "reference": finding.reference,
        })

    return json.dumps(report, indent=2)


def save_json_report(result: ScanResult, filepath: str) -> None:
    """Save scan results as a JSON file."""
    json_string = generate_json_report(result)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(json_string)
    print(f"   [*] JSON report saved to: {filepath}")
