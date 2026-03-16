"""Tests for the Secrets analyzer."""
from security_scanner.analyzers.secrets import SecretsAnalyzer
from security_scanner.models.finding import VulnerabilityType, Severity


class TestSecretsAnalyzer:

    def test_detects_hardcoded_password(self):
        """Should detect hardcoded password assignment."""
        source = '''
password = "supersecret123"
'''
        analyzer = SecretsAnalyzer("/admin", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert findings[0].vuln_type == VulnerabilityType.HARDCODED_SECRET

    def test_detects_weak_password_as_high(self):
        """Weak passwords like 'password123' should be HIGH severity."""
        source = '''
password = "password123"
'''
        analyzer = SecretsAnalyzer("/admin", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH

    def test_detects_api_key(self):
        """Should detect hardcoded API keys."""
        source = '''
api_key = "sk-1234567890abcdef"
'''
        analyzer = SecretsAnalyzer("/settings", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert findings[0].vuln_type == VulnerabilityType.HARDCODED_SECRET

    def test_detects_auth_token(self):
        """Should detect hardcoded auth tokens."""
        source = '''
auth_token = "bearer-xyz-123456"
'''
        analyzer = SecretsAnalyzer("/auth", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1

    def test_detects_db_password(self):
        """Should detect database password."""
        source = '''
db_password = "mysql_root_pass"
'''
        analyzer = SecretsAnalyzer("/db", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1

    def test_ignores_env_var(self):
        """Should NOT flag secrets loaded from environment variables."""
        source = '''
import os
password = os.environ.get("DB_PASSWORD")
'''
        analyzer = SecretsAnalyzer("/settings", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) == 0

    def test_ignores_non_secret_variables(self):
        """Should NOT flag variables without secret-like names."""
        source = '''
username = "admin"
count = 42
title = "Welcome"
'''
        analyzer = SecretsAnalyzer("/home", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) == 0

    def test_ignores_empty_string(self):
        """Should NOT flag empty string assignments."""
        source = '''
api_key = ""
'''
        analyzer = SecretsAnalyzer("/settings", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) == 0

    def test_ignores_short_values(self):
        """Should NOT flag values shorter than 3 characters."""
        source = '''
api_key = "ab"
'''
        analyzer = SecretsAnalyzer("/settings", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) == 0

    def test_finding_has_fix_recommendation(self):
        """Finding should include fix recommendation with env var suggestion."""
        source = '''
secret_key = "my_super_secret_key"
'''
        analyzer = SecretsAnalyzer("/config", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1
        f = findings[0]
        assert f.fix_recommendation != ""
        assert f.fix_before != ""
        assert f.fix_after != ""
        assert "environ" in f.fix_after.lower() or "os" in f.fix_after.lower()
