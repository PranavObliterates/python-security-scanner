"""Local dependency manifest checks.

This module intentionally performs deterministic checks only. Network-backed
advisory lookups belong in a separate, explicit opt-in integration.
"""
import os
import re
import json
from typing import List, Tuple

from ..models.finding import Finding, Severity, VulnerabilityType


MANIFEST_NAMES = ("requirements.txt", "requirements-dev.txt", "Pipfile", "pyproject.toml")


def _pinned_requirements(root: str) -> List[Tuple[str, str, str, int]]:
    root = os.path.abspath(root)
    if os.path.isfile(root):
        root = os.path.dirname(root)
    packages: List[Tuple[str, str, str, int]] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "__pycache__", "node_modules"}]
        for manifest in MANIFEST_NAMES:
            if manifest not in files:
                continue
            path = os.path.join(current, manifest)
            if manifest == "pyproject.toml":
                try:
                    specs = _read_pyproject(path).get("project", {}).get("dependencies", [])
                    for spec in specs:
                        name, version = _exact_requirement(spec)
                        if name and version:
                            packages.append((name, version, path, 0))
                except (OSError, ValueError, ImportError):
                    continue
            elif manifest == "Pipfile":
                try:
                    with open(path, encoding="utf-8") as handle:
                        section = ""
                        for line_number, raw in enumerate(handle, 1):
                            stripped = raw.strip()
                            if stripped.startswith("[") and stripped.endswith("]"):
                                section = stripped[1:-1]
                            elif section in ("packages", "dev-packages") and "=" in stripped:
                                package, spec = stripped.split("=", 1)
                                version = spec.strip().strip("\"'")
                                if version.startswith("=="):
                                    packages.append((package.strip(), version[2:].strip(), path, line_number))
                except OSError:
                    continue
            else:
                try:
                    with open(path, encoding="utf-8") as handle:
                        for line_number, raw in enumerate(handle, 1):
                            match = re.match(
                                r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9_.+-]+)",
                                raw.split("#", 1)[0],
                            )
                            if match:
                                packages.append((match.group(1), match.group(2), path, line_number))
                except OSError:
                    continue
    return packages


def scan_osv_advisories(root: str, timeout: float = 8.0) -> Tuple[List[Finding], List[str]]:
    """Query OSV.dev for pinned direct dependencies; performs network access."""
    import requests

    findings: List[Finding] = []
    warnings: List[str] = []
    for name, version, path, line_number in _pinned_requirements(root):
        try:
            response = requests.post(
                "https://api.osv.dev/v1/query",
                json={
                    "package": {"name": name, "ecosystem": "PyPI"},
                    "version": version,
                },
                timeout=timeout,
            )
            response.raise_for_status()
            advisories = response.json().get("vulns", [])
        except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
            warnings.append(f"OSV lookup failed for {name}=={version}: {exc}")
            continue
        for advisory in advisories:
            severity = Severity.MEDIUM
            for severity_entry in advisory.get("severity", []):
                try:
                    score = float(severity_entry.get("score", "0"))
                    if score >= 7:
                        severity = Severity.HIGH
                    elif score >= 4:
                        severity = Severity.MEDIUM
                except (TypeError, ValueError):
                    continue
            vuln_id = advisory.get("id", "OSV advisory")
            findings.append(Finding(
                vuln_type=VulnerabilityType.DEPENDENCY_VULNERABILITY,
                severity=severity,
                endpoint="(dependency manifest)",
                file=path,
                line=line_number,
                code_snippet=f"{name}=={version}",
                explanation=f"OSV reports {vuln_id} for {name} {version}.",
                fix_recommendation="Review the advisory and upgrade to a fixed version compatible with your application.",
                reference=f"https://osv.dev/vulnerability/{vuln_id}",
                source="SAST",
                status="confirmed",
                rule_id=f"PYSEC-OSV-{vuln_id}",
                cwe="CWE-1104",
            ))
    return findings, warnings


def _requirement_name(line: str) -> Tuple[str, bool]:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "[", "git+", "http")):
        return "", False
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*(.*)$", line)
    if not match:
        return "", False
    return match.group(1), bool(re.search(r"^\s*===?\s*[A-Za-z0-9_.+-]+", match.group(2)))


def _read_pyproject(path: str) -> dict:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def _parse_dependency_string(spec: str) -> Tuple[str, str]:
    match = re.match(
        r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*(.*)$",
        spec.split(";", 1)[0].strip(),
    )
    if not match:
        return "", ""
    version_match = re.match(r"^(?:===?|~=|>=|<=|>|<)\s*([A-Za-z0-9_.+-]+)", match.group(2))
    return match.group(1), version_match.group(1) if version_match else ""


def _exact_requirement(spec: str) -> Tuple[str, str]:
    name, _ = _parse_dependency_string(spec)
    if not name:
        return "", ""
    pattern = (
        r"^\s*" + re.escape(name)
        + r"(?:\[[^\]]+\])?\s*===?\s*([A-Za-z0-9_.+-]+)"
    )
    match = re.match(pattern, spec.split(";", 1)[0].strip())
    return (name, match.group(1)) if match else (name, "")


def _finding(path: str, line: int, name: str, explanation: str,
             recommendation: str, vuln_type: VulnerabilityType) -> Finding:
    return Finding(
        vuln_type=vuln_type,
        severity=Severity.LOW if vuln_type == VulnerabilityType.UNPINNED_DEPENDENCY else Severity.INFO,
        endpoint="(dependency manifest)",
        file=path,
        line=line,
        code_snippet=name,
        explanation=explanation,
        fix_recommendation=recommendation,
        reference="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        source="SAST",
        status="informational",
        rule_id="PYSEC-DEP-001" if vuln_type == VulnerabilityType.UNPINNED_DEPENDENCY else "PYSEC-DEP-002",
        cwe="CWE-1104",
    )


def scan_dependency_manifests(root: str) -> List[Finding]:
    """Audit supported dependency manifests below *root* without network access."""
    root = os.path.abspath(root)
    if os.path.isfile(root):
        root = os.path.dirname(root)
    findings: List[Finding] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "__pycache__", "node_modules"}]
        for manifest in MANIFEST_NAMES:
            if manifest not in files:
                continue
            path = os.path.join(current, manifest)
            if manifest == "pyproject.toml":
                try:
                    dependencies = _read_pyproject(path).get("project", {}).get("dependencies", [])
                except (OSError, ValueError, ImportError):
                    continue
                for line_number, spec in enumerate(dependencies, 1):
                    name, version = _exact_requirement(spec)
                    if name and not version:
                        findings.append(_finding(
                            path,
                            line_number,
                            spec,
                            f"Dependency '{name}' is not pinned to an exact version.",
                            "Pin production dependencies to exact versions and update them through a reviewed process.",
                            VulnerabilityType.UNPINNED_DEPENDENCY,
                        ))
                continue
            if manifest == "Pipfile":
                try:
                    with open(path, encoding="utf-8") as handle:
                        section = ""
                        for line_number, raw in enumerate(handle, 1):
                            stripped = raw.strip()
                            if stripped.startswith("[") and stripped.endswith("]"):
                                section = stripped[1:-1]
                                continue
                            if section not in ("packages", "dev-packages") or "=" not in stripped:
                                continue
                            package, spec = stripped.split("=", 1)
                            version = spec.strip().strip("\"'")
                            if version != "*" and version.startswith("=="):
                                continue
                            findings.append(_finding(
                                path,
                                line_number,
                                stripped,
                                f"Dependency '{package.strip()}' is not pinned to an exact version.",
                                "Pin production dependencies to exact versions and update them through a reviewed process.",
                                VulnerabilityType.UNPINNED_DEPENDENCY,
                            ))
                except OSError:
                    continue
                continue
            try:
                with open(path, encoding="utf-8") as handle:
                    lines = handle.readlines()
            except OSError:
                continue
            for line_number, raw in enumerate(lines, 1):
                name, pinned = _requirement_name(raw)
                if name and not pinned:
                    findings.append(_finding(
                        path, line_number, raw.strip(),
                        f"Dependency '{name}' is not pinned to a reproducible version.",
                        "Pin production dependencies and update them through a reviewed dependency process.",
                        VulnerabilityType.UNPINNED_DEPENDENCY,
                    ))
    return findings
