"""Integration tests — test scan_app() end-to-end."""
from security_scanner import scan_app
from security_scanner.models.finding import VulnerabilityType


class TestScanApp:

    def test_scan_vulnerable_app(self, vulnerable_app):
        """scan_app should find multiple issues in vulnerable app."""
        result = scan_app(vulnerable_app, dynamic=False)
        assert len(result.findings) >= 3  # At least SQLi + XSS + config
        assert result.routes_scanned >= 3

    def test_scan_returns_scan_result(self, vulnerable_app):
        """scan_app should return a ScanResult object."""
        result = scan_app(vulnerable_app, dynamic=False)
        assert result.app_name != ""
        assert result.scan_duration_seconds >= 0

    def test_finds_sql_injection(self, vulnerable_app):
        """Should detect SQL injection."""
        result = scan_app(vulnerable_app, dynamic=False)
        sqli = [f for f in result.findings if f.vuln_type == VulnerabilityType.SQL_INJECTION]
        assert len(sqli) >= 1

    def test_finds_xss(self, vulnerable_app):
        """Should detect XSS."""
        result = scan_app(vulnerable_app, dynamic=False)
        xss = [f for f in result.findings if f.vuln_type == VulnerabilityType.XSS]
        assert len(xss) >= 1

    def test_finds_weak_secret(self, vulnerable_app):
        """Should detect weak secret key."""
        result = scan_app(vulnerable_app, dynamic=False)
        secrets = [f for f in result.findings
                    if f.vuln_type == VulnerabilityType.HARDCODED_SECRET]
        assert len(secrets) >= 1

    def test_finds_ssti(self, vulnerable_app):
        """Should detect SSTI in render_template_string with dynamic input."""
        result = scan_app(vulnerable_app, dynamic=False)
        ssti = [f for f in result.findings if f.vuln_type == VulnerabilityType.SSTI]
        assert len(ssti) >= 1

    def test_finds_deserialization(self, vulnerable_app):
        """Should detect insecure deserialization via pickle.loads."""
        result = scan_app(vulnerable_app, dynamic=False)
        deser = [f for f in result.findings
                 if f.vuln_type == VulnerabilityType.INSECURE_DESERIALIZATION]
        assert len(deser) >= 1

    def test_summary_string(self, vulnerable_app):
        """Summary should contain counts."""
        result = scan_app(vulnerable_app, dynamic=False)
        summary = result.summary()
        assert "CRITICAL" in summary or "HIGH" in summary

    def test_safe_app_fewer_issues(self, safe_app):
        """Safe app should have significantly fewer code-level findings."""
        result = scan_app(safe_app, dynamic=False)
        code_findings = [f for f in result.findings
                         if f.vuln_type in (VulnerabilityType.SQL_INJECTION,
                                            VulnerabilityType.XSS)]
        assert len(code_findings) == 0
