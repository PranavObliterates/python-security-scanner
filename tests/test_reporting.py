"""Tests for all report generators: console, JSON, and HTML."""
import json
from unittest.mock import patch

from security_scanner.models.finding import Finding, Severity, VulnerabilityType  # type: ignore
from security_scanner.models.scan_result import ScanResult  # type: ignore
from security_scanner.reporting.console import print_report  # type: ignore
from security_scanner.reporting.json_report import generate_json_report  # type: ignore
from security_scanner.reporting.html_report import generate_html_report  # type: ignore


def _make_sample_result():
    """Create a ScanResult with sample findings for testing."""
    result = ScanResult(app_name="test_app")
    result.routes_scanned = 3
    result.scan_duration_seconds = 0.123

    result.findings = [
        Finding(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            endpoint="/user",
            file="test.py",
            line=10,
            code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
            explanation="SQL injection via f-string.",
            fix_recommendation="Use parameterized queries.",
            fix_before='cursor.execute(f"SELECT ... WHERE id = {user_id}")',
            fix_after='cursor.execute("SELECT ... WHERE id = %s", (user_id,))',
            reference="https://owasp.org/sqli",
            source="SAST",
        ),
        Finding(
            vuln_type=VulnerabilityType.XSS,
            severity=Severity.CRITICAL,
            endpoint="/search",
            file="test.py",
            line=20,
            code_snippet='return f"<h1>{term}</h1>"',
            explanation="Reflected XSS.",
            fix_recommendation="Escape output.",
            source="DAST",
        ),
        Finding(
            vuln_type=VulnerabilityType.HARDCODED_SECRET,
            severity=Severity.HIGH,
            endpoint="(global config)",
            file="app config",
            line=0,
            code_snippet='secret_key = "password123"',
            explanation="Weak secret key.",
            fix_recommendation="Use environment variables.",
            source="SAST",
        ),
    ]
    return result


def _make_empty_result():
    """Create a ScanResult with no findings."""
    result = ScanResult(app_name="safe_app")
    result.routes_scanned = 2
    result.scan_duration_seconds = 0.05
    return result


class TestConsoleReport:

    def test_prints_without_error(self):
        """Console report should print without crashing."""
        result = _make_sample_result()
        # Capture print output
        with patch("builtins.print"):
            print_report(result)

    def test_prints_empty_report(self):
        """Empty report should print 'no issues found'."""
        result = _make_empty_result()
        with patch("builtins.print"):
            print_report(result)


class TestJSONReport:

    def test_generates_valid_json(self):
        """JSON report should be parseable JSON."""
        result = _make_sample_result()
        json_str = generate_json_report(result)
        data = json.loads(json_str)
        assert isinstance(data, dict)

    def test_json_has_required_fields(self):
        """JSON report should contain all required top-level fields."""
        result = _make_sample_result()
        data = json.loads(generate_json_report(result))
        assert "scan_date" in data
        assert "app_name" in data
        assert "routes_scanned" in data
        assert "summary" in data
        assert "findings" in data

    def test_json_finding_count(self):
        """JSON findings count should match actual findings."""
        result = _make_sample_result()
        data = json.loads(generate_json_report(result))
        assert len(data["findings"]) == 3
        assert data["summary"]["total_issues"] == 3

    def test_json_severity_counts(self):
        """JSON summary should have correct severity counts."""
        result = _make_sample_result()
        data = json.loads(generate_json_report(result))
        assert data["summary"]["critical"] == 2
        assert data["summary"]["high"] == 1

    def test_json_finding_structure(self):
        """Each JSON finding should have type, severity, endpoint, etc."""
        result = _make_sample_result()
        data = json.loads(generate_json_report(result))
        finding = data["findings"][0]
        assert "type" in finding
        assert "severity" in finding
        assert "endpoint" in finding
        assert "explanation" in finding
        assert "fix" in finding

    def test_json_empty_report(self):
        """Empty report should generate valid JSON with 0 findings."""
        result = _make_empty_result()
        data = json.loads(generate_json_report(result))
        assert data["summary"]["total_issues"] == 0
        assert len(data["findings"]) == 0


class TestHTMLReport:

    def test_generates_valid_html(self):
        """HTML report should be a valid HTML string."""
        result = _make_sample_result()
        html = generate_html_report(result)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_html_contains_app_name(self):
        """HTML report should include the app name."""
        result = _make_sample_result()
        html = generate_html_report(result)
        assert "test_app" in html

    def test_html_contains_findings(self):
        """HTML report should include finding details."""
        result = _make_sample_result()
        html = generate_html_report(result)
        assert "SQL_INJECTION" in html
        assert "XSS" in html
        assert "CRITICAL" in html

    def test_html_contains_severity_badges(self):
        """HTML report should have severity count badges."""
        result = _make_sample_result()
        html = generate_html_report(result)
        assert "2 Critical" in html  # 2 critical findings
        assert "1 High" in html      # 1 high finding

    def test_html_escapes_code(self):
        """HTML report should escape special characters in code snippets."""
        result = _make_sample_result()
        html = generate_html_report(result)
        # The < in <h1> should be escaped
        assert "&lt;" in html or "&amp;" in html

    def test_html_empty_report(self):
        """Empty HTML report should show 'no issues' message."""
        result = _make_empty_result()
        html = generate_html_report(result)
        assert "No security issues found" in html

    def test_html_contains_owasp_links(self):
        """HTML report should include OWASP reference links."""
        result = _make_sample_result()
        html = generate_html_report(result)
        assert "owasp.org" in html


class TestPDFReport:

    def test_generates_pdf_report(self, tmp_path):
        """PDF report should generate valid PDF file without error."""
        from security_scanner.reporting.pdf_report import save_pdf_report
        result = _make_sample_result()
        out_file = str(tmp_path / "test_report.pdf")
        saved = save_pdf_report(result, out_file, prompt_for_key=False)
        assert saved == out_file
        import os
        assert os.path.exists(out_file)
        assert os.path.getsize(out_file) > 1000

    def test_generates_empty_pdf_report(self, tmp_path):
        """PDF report should generate cleanly for safe apps with no findings."""
        from security_scanner.reporting.pdf_report import save_pdf_report
        result = _make_empty_result()
        out_file = str(tmp_path / "safe_report.pdf")
        saved = save_pdf_report(result, out_file, prompt_for_key=False)
        assert saved == out_file
        import os
        assert os.path.exists(out_file)
        assert os.path.getsize(out_file) > 1000

    def test_pdf_report_with_xml_special_characters(self, tmp_path):
        """PDF report must not crash when code snippets contain <script>, &, <, or >."""
        from security_scanner.reporting.pdf_report import save_pdf_report
        result = ScanResult(app_name="adversarial_app")
        result.routes_scanned = 1
        result.findings.append(Finding(
            vuln_type=VulnerabilityType.XSS,
            severity=Severity.CRITICAL,
            endpoint="/xss",
            file="app.py",
            line=42,
            code_snippet='return f"<script>alert(document.cookie && 1)</script>"',
            explanation="Unescaped <script> tag & user input in response.",
            fix_recommendation="Use escape() and disallow raw <script>.",
            fix_before='f"<script>{payload}</script>"',
            fix_after='escape(payload)',
            reference="https://owasp.org/www-community/attacks/xss",
            source="SAST",
        ))
        out_file = str(tmp_path / "xss_report.pdf")
        saved = save_pdf_report(result, out_file, prompt_for_key=False)
        assert saved == out_file
        import os
        assert os.path.exists(out_file)
        assert os.path.getsize(out_file) > 1000


