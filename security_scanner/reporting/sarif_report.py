"""SARIF (Static Analysis Results Interchange Format) v2.1.0 report generator.

Standard format consumed by GitHub Code Scanning, GitLab SAST, VS Code, and CI/CD tools.
"""
import json
from typing import Dict, Any, List
from ..models.scan_result import ScanResult
from ..models.finding import Finding, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map internal severity to SARIF level (error, warning, note, none)."""
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    return mapping.get(severity, "warning")


def generate_sarif_report(result: ScanResult) -> Dict[str, Any]:
    """Generate a SARIF v2.1.0 report dictionary from ScanResult."""
    rules_dict = {}
    results = []

    for f in result.findings:
        rule_id = f.vuln_type.value
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("_", " ").title(),
                "shortDescription": {"text": f.vuln_type.value},
                "fullDescription": {"text": f.explanation or f.vuln_type.value},
                "helpUri": f.reference or "https://owasp.org/Top10/",
                "properties": {
                    "category": f.vuln_type.owasp_category,
                    "defaultSeverity": f.severity.value,
                },
            }

        file_uri = f.file if f.file and f.file not in ("app configuration", "settings.py", "(dynamic test)") else "app.py"
        line_num = max(1, f.line)

        sarif_item = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(f.severity),
            "message": {
                "text": f"{f.explanation}\nRemediation: {f.fix_recommendation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_uri.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line_num,
                            "snippet": {
                                "text": f.code_snippet,
                            },
                        },
                    }
                }
            ],
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence,
                "source": f.source,
                "endpoint": f.endpoint,
                "status": f.status,
                "cwe": f.cwe,
            },
        }
        results.append(sarif_item)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PySecure",
                        "version": "0.2.0",
                        "informationUri": "https://github.com/PranavObliterates/python-security-scanner",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif_doc


def save_sarif_report(result: ScanResult, filepath: str) -> None:
    """Generate and write a SARIF report to a file."""
    doc = generate_sarif_report(result)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
