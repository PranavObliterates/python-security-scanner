"""Tests for Dynamic Application Security Testing (DAST)."""
from security_scanner.dynamic.payload_tester import run_dast_tests, load_payloads
from security_scanner.dynamic.response_analyzer import (
    check_response_for_sqli, check_response_for_xss, check_security_headers,
)
from security_scanner.core.route_discovery import discover_flask_routes
from security_scanner.models.finding import VulnerabilityType


class TestPayloadLoading:

    def test_load_sqli_payloads(self):
        """Should load SQL injection payloads from file."""
        payloads = load_payloads("sqli_payloads.txt")
        assert len(payloads) >= 10
        assert "' OR '1'='1" in payloads

    def test_load_xss_payloads(self):
        """Should load XSS payloads from file."""
        payloads = load_payloads("xss_payloads.txt")
        assert len(payloads) >= 10
        assert any("script" in p.lower() for p in payloads)

    def test_load_nonexistent_file(self):
        """Should return empty list for missing file."""
        payloads = load_payloads("does_not_exist.txt")
        assert payloads == []


class TestResponseAnalyzer:

    def test_detects_sql_error_in_response(self):
        """Should detect DB error patterns."""
        response = "sqlite3.OperationalError: near \"'\": syntax error"
        assert check_response_for_sqli(response) is True

    def test_no_sql_error_in_clean_response(self):
        """Should not flag clean HTML."""
        response = "<h1>Welcome to our website</h1>"
        assert check_response_for_sqli(response) is False

    def test_detects_reflected_xss(self):
        """Should detect reflected XSS payload."""
        payload = "<script>alert('XSS')</script>"
        response = f"<h1>Results for: {payload}</h1>"
        assert check_response_for_xss(response, payload) is True

    def test_no_reflected_xss_when_escaped(self):
        """Should not flag escaped payloads."""
        payload = "<script>alert('XSS')</script>"
        response = "<h1>Results for: &lt;script&gt;alert('XSS')&lt;/script&gt;</h1>"
        assert check_response_for_xss(response, payload) is False

    def test_check_security_headers_missing(self):
        """Should flag missing security headers."""
        headers = {"Content-Type": "text/html"}
        findings = check_security_headers(headers, "/")
        assert len(findings) >= 3  # CSP, X-Frame-Options, HSTS at least


class TestDASTIntegration:

    def test_dast_detects_xss(self, vulnerable_app):
        """DAST should detect reflected XSS."""
        routes = discover_flask_routes(vulnerable_app)
        findings = run_dast_tests(vulnerable_app, routes)
        xss_findings = [f for f in findings if f.vuln_type == VulnerabilityType.XSS]
        assert len(xss_findings) >= 1

    def test_dast_findings_are_marked_dast(self, vulnerable_app):
        """All DAST findings should have source='DAST'."""
        routes = discover_flask_routes(vulnerable_app)
        findings = run_dast_tests(vulnerable_app, routes)
        for f in findings:
            assert f.source == "DAST"
