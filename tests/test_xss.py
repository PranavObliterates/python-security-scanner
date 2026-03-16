"""Tests for the XSS analyzer."""
from security_scanner.analyzers.xss import XSSAnalyzer
from security_scanner.models.finding import VulnerabilityType


class TestXSSAnalyzer:

    def test_detects_fstring_xss(self):
        """Should detect f-string XSS with HTML tags and user input."""
        source = '''
term = request.args.get("q", "")
return f"<h1>Results for: {term}</h1>"
'''
        analyzer = XSSAnalyzer("/search", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert findings[0].vuln_type == VulnerabilityType.XSS

    def test_detects_div_xss(self):
        """Should detect XSS in div tags."""
        source = '''
name = request.args.get("name", "")
return f"<div>{name}</div>"
'''
        analyzer = XSSAnalyzer("/profile", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1

    def test_ignores_escaped_output(self):
        """Should NOT flag escaped output (no user input detected as direct)."""
        source = '''
title = "Welcome"
return f"<h1>{title}</h1>"
'''
        analyzer = XSSAnalyzer("/home", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) == 0

    def test_ignores_no_html(self):
        """Should NOT flag output without HTML tags."""
        source = '''
term = request.args.get("q", "")
return f"You searched for: {term}"
'''
        analyzer = XSSAnalyzer("/search", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) == 0

    def test_finding_has_correct_fields(self):
        """XSS finding should have all required fields."""
        source = '''
term = request.args.get("q", "")
return f"<h1>Results for: {term}</h1>"
'''
        analyzer = XSSAnalyzer("/search", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1
        f = findings[0]
        assert f.severity.value == "CRITICAL"
        assert f.endpoint == "/search"
        assert "XSS" in f.vuln_type.value
        assert f.fix_recommendation != ""
