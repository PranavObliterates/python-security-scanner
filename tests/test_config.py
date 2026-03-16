"""Tests for configuration security checks."""
from flask import Flask
from security_scanner.analyzers.config import check_flask_config
from security_scanner.models.finding import VulnerabilityType, Severity


class TestConfigChecks:

    def test_detects_debug_mode(self):
        """Should flag debug mode."""
        app = Flask(__name__)
        app.debug = True
        app.secret_key = "x" * 32  # Long enough to not trigger weak secret
        findings = check_flask_config(app)
        debug_findings = [f for f in findings if f.vuln_type == VulnerabilityType.DEBUG_MODE]
        assert len(debug_findings) >= 1

    def test_detects_weak_secret(self):
        """Should flag weak secret key."""
        app = Flask(__name__)
        app.secret_key = "password123"
        findings = check_flask_config(app)
        secret_findings = [f for f in findings if f.vuln_type == VulnerabilityType.HARDCODED_SECRET]
        assert len(secret_findings) >= 1

    def test_detects_missing_csrf(self):
        """Should flag missing CSRF protection."""
        app = Flask(__name__)
        app.secret_key = "x" * 32
        findings = check_flask_config(app)
        csrf_findings = [f for f in findings if f.vuln_type == VulnerabilityType.CSRF_MISSING]
        assert len(csrf_findings) >= 1

    def test_strong_secret_not_flagged(self):
        """Should NOT flag a strong, long secret key."""
        app = Flask(__name__)
        app.secret_key = "a" * 32  # 32 chars = strong enough
        findings = check_flask_config(app)
        secret_findings = [f for f in findings
                           if f.vuln_type == VulnerabilityType.HARDCODED_SECRET]
        assert len(secret_findings) == 0

    def test_no_debug_not_flagged(self):
        """Should NOT flag when debug mode is off."""
        app = Flask(__name__)
        app.debug = False
        app.secret_key = "x" * 32
        findings = check_flask_config(app)
        debug_findings = [f for f in findings if f.vuln_type == VulnerabilityType.DEBUG_MODE]
        assert len(debug_findings) == 0
