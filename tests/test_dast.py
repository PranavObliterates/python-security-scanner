"""Tests for passive Dynamic Application Security Testing (DAST)."""
from security_scanner.dynamic.payload_tester import run_dast_tests
from security_scanner.dynamic.response_analyzer import check_security_headers
from security_scanner.core.route_discovery import discover_flask_routes
from security_scanner.models.finding import VulnerabilityType


class TestResponseAnalyzer:

    def test_check_security_headers_missing(self):
        """Should flag missing security headers."""
        headers = {"Content-Type": "text/html"}
        findings = check_security_headers(headers, "/")
        assert len(findings) >= 3  # CSP, X-Frame-Options, HSTS at least


class TestDASTIntegration:

    def test_dast_does_not_send_attack_input(self, vulnerable_app):
        """DAST should remain passive; SAST identifies source vulnerabilities."""
        routes = discover_flask_routes(vulnerable_app)
        findings = run_dast_tests(vulnerable_app, routes)
        assert all(f.vuln_type != VulnerabilityType.XSS for f in findings)
        assert all(f.vuln_type != VulnerabilityType.SQL_INJECTION for f in findings)

    def test_dast_findings_are_marked_dast(self, vulnerable_app):
        """All DAST findings should have source='DAST'."""
        routes = discover_flask_routes(vulnerable_app)
        findings = run_dast_tests(vulnerable_app, routes)
        for f in findings:
            assert f.source == "DAST"

    def test_active_dast_uses_harmless_reflection_canary(self, vulnerable_app):
        routes = discover_flask_routes(vulnerable_app)
        findings = run_dast_tests(vulnerable_app, routes, active=True)
        assert any(f.vuln_type == VulnerabilityType.XSS for f in findings)
        assert all("pysecure-canary" in f.code_snippet for f in findings if f.vuln_type == VulnerabilityType.XSS)
