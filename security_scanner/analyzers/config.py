"""Configuration security checks — debug mode, secrets, CSRF, cookies."""
from typing import List
from ..models.finding import Finding, Severity, VulnerabilityType

WEAK_SECRETS = [
    "secret", "password", "password123", "123456", "changeme",
    "default", "admin", "test", "debug", "development",
    "super_secret", "mysecret", "flask-secret",
]


def check_flask_config(app) -> List[Finding]:
    """Run all configuration checks on a Flask app.

    Checks:
    1. Debug mode enabled
    2. Weak or hardcoded SECRET_KEY
    3. Missing CSRF protection
    """
    findings = []

    # Check 1: Debug mode
    if app.debug:
        findings.append(Finding(
            vuln_type=VulnerabilityType.DEBUG_MODE,
            severity=Severity.HIGH,
            endpoint="(global config)",
            file="app configuration",
            line=0,
            code_snippet="app.run(debug=True)",
            explanation=(
                "Debug mode is enabled. Flask's debugger allows "
                "anyone to execute arbitrary Python code on your server. "
                "If this is exposed to the internet, an attacker gets "
                "full control of your machine."
            ),
            fix_recommendation="Never run debug=True in production.",
            fix_before="app.run(debug=True)",
            fix_after="app.run(debug=False)",
            reference="https://flask.palletsprojects.com/en/stable/debugging/",
            source="SAST",
        ))

    # Check 2: Weak or hardcoded SECRET_KEY
    secret_key = app.config.get("SECRET_KEY", "")
    if secret_key:
        if isinstance(secret_key, str):
            if secret_key.lower() in WEAK_SECRETS or len(secret_key) < 16:
                findings.append(Finding(
                    vuln_type=VulnerabilityType.HARDCODED_SECRET,
                    severity=Severity.HIGH,
                    endpoint="(global config)",
                    file="app configuration",
                    line=0,
                    code_snippet=f'app.secret_key = "{secret_key}"',
                    explanation=(
                        f"SECRET_KEY is weak or easily guessable ('{secret_key}'). "
                        f"Flask uses this key to sign session cookies. An attacker "
                        f"who knows this key can forge sessions and impersonate "
                        f"any user, including admins."
                    ),
                    fix_recommendation="Use a long random secret key from environment variables.",
                    fix_before=f'app.secret_key = "{secret_key}"',
                    fix_after='import os\napp.secret_key = os.environ.get("SECRET_KEY")',
                    reference="https://flask.palletsprojects.com/en/stable/config/#SECRET_KEY",
                    source="SAST",
                ))
    else:
        findings.append(Finding(
            vuln_type=VulnerabilityType.HARDCODED_SECRET,
            severity=Severity.MEDIUM,
            endpoint="(global config)",
            file="app configuration",
            line=0,
            code_snippet="SECRET_KEY not set",
            explanation=(
                "No SECRET_KEY is configured. Flask sessions and flash "
                "messages will not work, and any feature relying on "
                "cookie signing is insecure."
            ),
            fix_recommendation="Set a strong SECRET_KEY.",
            fix_before="# no secret key set",
            fix_after='import os\napp.secret_key = os.environ.get("SECRET_KEY")',
            source="SAST",
        ))

    # Check 3: CSRF protection
    has_csrf = False
    if hasattr(app, 'extensions'):
        for ext_name in app.extensions:
            if "csrf" in ext_name.lower():
                has_csrf = True
                break

    if not has_csrf:
        findings.append(Finding(
            vuln_type=VulnerabilityType.CSRF_MISSING,
            severity=Severity.HIGH,
            endpoint="(global config)",
            file="app configuration",
            line=0,
            code_snippet="No CSRF protection detected",
            explanation=(
                "No CSRF protection (like Flask-WTF CSRFProtect) is active. "
                "Without CSRF tokens, an attacker can create a malicious webpage "
                "that submits forms to your app on behalf of logged-in users — "
                "for example, changing their password or making purchases."
            ),
            fix_recommendation="Add Flask-WTF CSRF protection.",
            fix_before="app = Flask(__name__)\n# no CSRF",
            fix_after="from flask_wtf.csrf import CSRFProtect\napp = Flask(__name__)\nCSRFProtect(app)",
            reference="https://owasp.org/www-community/attacks/csrf",
            source="SAST",
        ))

    return findings


def check_django_config(settings=None) -> List[Finding]:
    """Run all configuration checks on a Django project.

    Checks:
    1. DEBUG mode enabled
    2. Weak or hardcoded SECRET_KEY
    3. Missing CsrfViewMiddleware
    4. Missing SecurityMiddleware
    """
    if settings is None:
        from django.conf import settings

    findings = []

    # Check 1: Debug mode
    if getattr(settings, "DEBUG", False):
        findings.append(Finding(
            vuln_type=VulnerabilityType.DEBUG_MODE,
            severity=Severity.HIGH,
            endpoint="(global config)",
            file="settings.py",
            line=0,
            code_snippet="DEBUG = True",
            explanation=(
                "DEBUG mode is enabled. Django's debug mode exposes detailed "
                "error pages with full tracebacks, local variables, and SQL "
                "queries to anyone who triggers an error. In production, "
                "this gives attackers a roadmap of your application."
            ),
            fix_recommendation="Set DEBUG = False in production settings.",
            fix_before="DEBUG = True",
            fix_after="DEBUG = False",
            reference="https://docs.djangoproject.com/en/stable/ref/settings/#debug",
            source="SAST",
        ))

    # Check 2: Weak or hardcoded SECRET_KEY
    secret_key = getattr(settings, "SECRET_KEY", "")
    if secret_key:
        if isinstance(secret_key, str):
            if secret_key.lower() in WEAK_SECRETS or len(secret_key) < 20:
                findings.append(Finding(
                    vuln_type=VulnerabilityType.HARDCODED_SECRET,
                    severity=Severity.HIGH,
                    endpoint="(global config)",
                    file="settings.py",
                    line=0,
                    code_snippet=f'SECRET_KEY = "{secret_key[:20]}..."',
                    explanation=(
                        f"SECRET_KEY is weak or easily guessable. Django uses "
                        f"this key to sign cookies, CSRF tokens, and password "
                        f"reset tokens. An attacker who knows this key can "
                        f"forge any of these."
                    ),
                    fix_recommendation="Use a long random secret key from environment variables.",
                    fix_before=f'SECRET_KEY = "{secret_key[:20]}..."',
                    fix_after='import os\nSECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")',
                    reference="https://docs.djangoproject.com/en/stable/ref/settings/#secret-key",
                    source="SAST",
                ))
    else:
        findings.append(Finding(
            vuln_type=VulnerabilityType.HARDCODED_SECRET,
            severity=Severity.MEDIUM,
            endpoint="(global config)",
            file="settings.py",
            line=0,
            code_snippet="SECRET_KEY not set",
            explanation="No SECRET_KEY is configured. Django cannot function securely without one.",
            fix_recommendation="Set a strong SECRET_KEY.",
            fix_before="# no secret key set",
            fix_after='import os\nSECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")',
            source="SAST",
        ))

    # Check 3: CSRF middleware
    middleware = getattr(settings, "MIDDLEWARE", [])
    has_csrf = any("csrf" in m.lower() for m in middleware)
    if not has_csrf:
        findings.append(Finding(
            vuln_type=VulnerabilityType.CSRF_MISSING,
            severity=Severity.HIGH,
            endpoint="(global config)",
            file="settings.py",
            line=0,
            code_snippet="CsrfViewMiddleware not in MIDDLEWARE",
            explanation=(
                "Django's CsrfViewMiddleware is not in your MIDDLEWARE list. "
                "Without it, all POST/PUT/DELETE forms are vulnerable to "
                "Cross-Site Request Forgery attacks."
            ),
            fix_recommendation="Add CsrfViewMiddleware to MIDDLEWARE.",
            fix_before='MIDDLEWARE = [...]\n# missing CsrfViewMiddleware',
            fix_after='MIDDLEWARE = [\n    ...\n    "django.middleware.csrf.CsrfViewMiddleware",\n    ...\n]',
            reference="https://docs.djangoproject.com/en/stable/ref/csrf/",
            source="SAST",
        ))

    # Check 4: SecurityMiddleware
    has_security = any("security" in m.lower() for m in middleware)
    if not has_security:
        findings.append(Finding(
            vuln_type=VulnerabilityType.MISSING_SECURITY_HEADER,
            severity=Severity.MEDIUM,
            endpoint="(global config)",
            file="settings.py",
            line=0,
            code_snippet="SecurityMiddleware not in MIDDLEWARE",
            explanation=(
                "Django's SecurityMiddleware is not in your MIDDLEWARE list. "
                "It provides important protections like HTTPS redirect, "
                "HSTS, XSS filter header, and content-type sniffing prevention."
            ),
            fix_recommendation="Add SecurityMiddleware to MIDDLEWARE.",
            fix_before='MIDDLEWARE = [...]\n# missing SecurityMiddleware',
            fix_after='MIDDLEWARE = [\n    "django.middleware.security.SecurityMiddleware",\n    ...\n]',
            reference="https://docs.djangoproject.com/en/stable/ref/middleware/#django.middleware.security.SecurityMiddleware",
            source="SAST",
        ))

    return findings

