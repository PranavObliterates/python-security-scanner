"""Passive dynamic checks for application health and response safety.

This module intentionally does not generate or send exploit payloads. Vulnerability
identification comes from the source analyzers; dynamic checks make only benign
baseline requests and report unexpected server errors for developer review.
"""
import re
from typing import List

from ..models.finding import Finding, Severity, VulnerabilityType


def _safe_path(path: str) -> str:
    """Replace route placeholders with benign values without adding query input."""
    path = re.sub(r"<(?:\w+:)?(\w+)>", "0", path)
    return re.sub(r"\{(\w+)\}", "0", path)


def _response_body(response) -> str:
    content = getattr(response, "data", None)
    if content is None:
        content = getattr(response, "content", b"")
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return str(content)


def _baseline_error(path: str, status_code: int, body: str) -> Finding:
    return Finding(
        vuln_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        severity=Severity.LOW,
        endpoint=path,
        file="(passive dynamic check)",
        line=0,
        code_snippet=f"GET {path} -> HTTP {status_code}",
        explanation=(
            f"A benign baseline request returned HTTP {status_code}. "
            "Review the endpoint's exception handling and ensure production "
            "responses do not expose stack traces or implementation details."
        ),
        fix_recommendation=(
            "Handle expected errors explicitly, log diagnostic details server-side, "
            "and return a generic production error response."
        ),
        fix_before=body[:240],
        fix_after="return a generic error response; log the exception securely",
        source="DAST",
        confidence="MEDIUM",
    )


def _run_baseline(client, path: str) -> List[Finding]:
    try:
        response = client.get(_safe_path(path))
    except Exception:
        return []
    if response.status_code >= 500:
        return [_baseline_error(path, response.status_code, _response_body(response))]
    return []


def run_dast_tests(app, routes) -> List[Finding]:
    """Run non-invasive baseline checks against a Flask application.

    No query-string, form, JSON, template, SQL, or serialized attack data is
    sent. Source-level analyzers are responsible for identifying vulnerabilities.
    """
    client = app.test_client()
    findings: List[Finding] = []
    for route in routes:
        findings.extend(_run_baseline(client, route.path))
    return findings


def run_django_dast_tests(routes) -> List[Finding]:
    """Run non-invasive baseline checks against the configured Django app."""
    try:
        from django.test import Client as DjangoClient
    except ImportError:
        return []

    client = DjangoClient()
    findings: List[Finding] = []
    for route in routes:
        findings.extend(_run_baseline(client, route.path))
    return findings


def run_fastapi_dast_tests(app, routes) -> List[Finding]:
    """Run non-invasive baseline checks against a FastAPI application."""
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        return []

    try:
        client = TestClient(app)
    except Exception:
        return []

    findings: List[Finding] = []
    for route in routes:
        findings.extend(_run_baseline(client, route.path))
    return findings
