# WebVenom — Python Security Scanner (SAST + DAST)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%20(2021)-orange.svg)](https://owasp.org/Top10/)

**PySecure** is an installable security scanner for Python web applications (**Flask, Django, and FastAPI**). It combines source analysis with bounded, private-target-only dynamic checks.

It generates human-friendly terminal reports, machine-readable JSON, visual HTML dashboards, and **executive PDF reports powered by Google Gemini AI**.

> PySecure detects a broad set of OWASP Top 10 vulnerability classes across Python Flask, Django, and FastAPI applications.

The framework scanner provides SAST and passive in-process checks. The optional URL scanner crawls localhost/private-network targets with strict page, request, timeout, and rate limits. Its opt-in active probe is a harmless reflection canary, not an exploit test.

**Contents:** [Install](#-installation) · [Scan apps](#-usage) · [Remote DAST](#remote-dast) · [Tests](#-running-tests--evaluation)

---

## 🛡️ OWASP Top 10 Coverage

| OWASP Category | Vulnerability Type | Detection Method |
|---|---|---|
| **A01: Broken Access Control** | Path Traversal / Arbitrary File Read | SAST |
| **A01: Broken Access Control** | Open Redirects | SAST |
| **A01: Broken Access Control** | Missing CSRF Protection | SAST (Config) |
| **A02: Cryptographic Failures** | Hardcoded Secrets & Passwords | SAST (AST Pattern Engine) |
| **A02: Cryptographic Failures** | Broken Hashing (MD4, MD5, SHA-1, SHA-0) | SAST |
| **A02: Cryptographic Failures** | Insecure Cookie Attributes | DAST (Runtime Headers) |
| **A03: Injection** | SQL Injection (SQLi) | SAST (source-to-sink analysis) |
| **A03: Injection** | Cross-Site Scripting (Reflected XSS) | SAST |
| **A03: Injection** | Command Injection (RCE) | SAST |
| **A03: Injection** | Server-Side Template Injection (SSTI) | SAST |
| **A05: Security Misconfiguration** | Debug Mode Enabled | SAST (Global Config) |
| **A05: Security Misconfiguration** | CORS Wildcard with Credentials | SAST (Global Config) |
| **A05: Security Misconfiguration** | Missing Security Headers (CSP, HSTS, X-Frame) | DAST |
| **A07: Identification & Authentication Failures** | JWT signature, algorithm, and hardcoded-key misuse | SAST |
| **A08: Software & Data Integrity** | Insecure Deserialization (pickle, PyYAML) | SAST |
| **A10: Server-Side Request Forgery** | SSRF (Unchecked HTTP requests) | SAST |

---

## 🚀 Installation

### Local Installation (Editable / Development Mode)
```bash
git clone https://github.com/PranavObliterates/python-security-scanner.git
cd python-security-scanner
pip install -e .
```

### From PyPI
```bash
pip install webvenom
```

For JavaScript-rendered page discovery, install the optional browser extra and browser binary:
```bash
pip install "webvenom[browser]"
playwright install chromium
```

---

## 🏗️ Architecture & How It Works

PySecure operates via a dual-engine analysis pipeline designed for speed and reduced false positives:

```
                      ┌────────────────────────────────────────┐
                      │        Target Flask / Django App       │
                      └──────────────────┬─────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
                 ▼                                               ▼
     ┌───────────────────────┐                       ┌───────────────────────┐
     │   Static (SAST)       │                       │   Dynamic (DAST)      │
     │   AST Taint Engine    │                       │   In-Memory Prober    │
     ├───────────────────────┤                       ├───────────────────────┤
     │ • Route AST traversal │                       │ • Test client harness │
     │ • Input source traces │                       │ • Benign baseline    │
     │ • Taint propagation   │                       │ • Response reflection │
     │ • Config audit        │                       │ • Header/Cookie audit │
     └───────────┬───────────┘                       └───────────┬───────────┘
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         ▼
                             ┌───────────────────────┐
                             │      ScanResult       │
                             │ (Normalized Findings) │
                             └───────────┬───────────┘
                                         │
         ┌───────────────────┬────────────┴───────┬───────────────────┬───────────────────┐
         ▼                   ▼                    ▼                   ▼                   ▼
 ┌───────────────┐   ┌───────────────┐    ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
 │ Console ANSI  │   │  JSON Report  │    │ SARIF v2.1.0  │   │ HTML Dashboard│   │ PDF Executive │
 │ Output        │   │  (CI/CD)      │    │ (GitHub Code) │   │ (Visual UI)   │   │ + Gemini AI   │
 └───────────────┘   └───────────────┘    └───────────────┘   └───────────────┘   └───────────────┘
```

1. **Static Analysis (SAST)**:
   - **AST Analysis Engine**: Parses Python source code into Abstract Syntax Trees using Python's native `ast` module.
   - Reuses parsed syntax trees for identical route source and caches source lines, reducing repeated setup work across the analyzer rules.
   - **Deep Taint Propagation**: Identifies untrusted user input sources (Flask `request.args`, `request.form`, `request.json`, `request.values`, `request.data`, `request.headers`, `request.query_string`; Django `request.GET`, `request.POST`, `request.body`, `request.COOKIES`, `request.FILES`, `request.META`) and tracks data flow across variable assignments, method transformations (e.g. `.strip()`, `.lower()`), nested collections (dictionaries, lists, tuples), string formatting (`.format()`, `%` formatting, f-strings), and intermediate variables into sensitive sinks.
   - **Dangerous Sink Detection**: Catches raw SQL interpolation, `pickle.loads()` / `pickle.load()`, `os.system()` / `subprocess` shell calls, unvalidated `open()` path traversals, unvalidated HTTP calls (SSRF), unvalidated redirects, and weak cryptographic hashing (`md4`, `md5`, `sha1`, `sha`, `hmac`).
   - **Sanitization & Safety-Aware**: Accurately recognizes type conversions (`int()`, `float()`), HTML escaping (`markupsafe.escape()`, `html.escape()`), path sanitizers (`werkzeug.utils.secure_filename()`), safe URL generators (`url_for()`, `reverse()`), shell quoting (`shlex.quote()`), and safe subprocess invocations with `shell=False`.
   - **Noise Reduction & Third-Party Isolation**: Isolates application-layer view code and excludes third-party framework code located inside `site-packages` or `dist-packages`, eliminating false positives in library internals.
   - **Configuration Auditing**: Inspects Flask and Django application configurations for insecure `DEBUG = True`, weak or hardcoded `SECRET_KEY`, missing `CSRF` protection, and missing security middleware.

2. **Dynamic Analysis (DAST)**:
   - **Passive Baseline Checks**: Uses framework test clients only for benign requests. It never generates or sends SQL, XSS, SSTI, deserialization, or command-injection payloads.
   - **Endpoint Risk Identification**: SAST maps untrusted input to dangerous sinks and reports the affected endpoint, source file, line, confidence, and remediation. DAST complements this with response-header, cookie, and baseline error checks.
   - **Transport & Cookie Audit**: Analyzes response headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`) and inspects session cookies for `Secure`, `HttpOnly`, and `SameSite` flags.

3. **Reporting & AI Insights**:
   - **Console Output**: Instant ANSI color-coded vulnerability summaries with remediation code diffs (`fix_before` vs. `fix_after`).
   - **JSON Export**: Machine-readable format conforming to automated vulnerability management platforms and CI/CD pipelines.
   - **SARIF v2.1.0 Export**: OASIS standard format consumed directly by GitHub Code Scanning, GitLab SAST, and VS Code.
   - **HTML Dashboard**: Self-contained visual report with interactive severity filtering and OWASP category mapping.
   - **Executive PDF + Gemini AI**: Formatted PDF report with automatic XML-entity escaping for HTML/XSS code snippets, combining metrics with optional session-only Google Gemini AI executive analysis and prioritized developer remediation roadmaps.

---

## 💻 Usage

### 1. In-App Python Code (2 Lines)
```python
from pysecure import scan_app, save_pdf_report

# Scan your Flask, Django, or FastAPI app
result = scan_app(app, dynamic=True)

# Generate AI-powered PDF report (prompts for session-only Gemini API key)
save_pdf_report(result, "security_report.pdf", prompt_for_key=True)
```

### 2. Command Line Interface (CLI)
```bash
# Scan a Flask application by file or directory (auto-detects app.py)
webvenom scan demos/vulnerable-flask/app.py --html report.html --pdf report.pdf
webvenom scan demos/vulnerable-flask/ --static-only

# Scan a Django project by directory, manage.py, or wsgi module
webvenom scan demos/vulnerable-django/
webvenom scan demos/vulnerable-django/manage.py
webvenom scan demos/vulnerable-django/vuln_django/wsgi.py --pdf django_audit.pdf

# Scan with session-only Gemini API key for remediation guidance
webvenom scan app.py --pdf audit.pdf --api-key YOUR_GEMINI_KEY

# Export SARIF for GitHub Code Scanning / CI
webvenom scan app.py --sarif results.sarif

# Static-only scan (fast mode without running test client)
webvenom scan app.py --static-only --json report.json

# Audit dependency manifests for unpinned requirements
webvenom scan app.py --static-only --dependencies

# Opt-in harmless canary checks through the local framework test client
webvenom scan app.py --active-dast --no-ai-prompt

# Crawl a local development server (localhost/private IP only)
webvenom scan-url http://127.0.0.1:5000/ --max-pages 40 --max-depth 3 --max-requests 100 --delay 0.25 --json dast.json

# Use optional Playwright to discover links rendered by JavaScript
webvenom scan-url http://127.0.0.1:5000/ --browser

# Query OSV.dev for known vulnerabilities in exact-pinned dependency versions
webvenom scan . --static-only --dependencies --osv

# CI/CD Quality Gate: fail only on HIGH or CRITICAL issues
webvenom scan app.py --fail-on HIGH

# Enable detailed scan timings and crawl request diagnostics
webvenom scan app.py --debug
webvenom scan-url http://127.0.0.1:5000/ --debug

# Filter output by minimum severity and ignore specific rules
webvenom scan app.py --severity MEDIUM --ignore DEBUG_MODE,WEAK_CRYPTO
```

### 3. Configuration Files (`pyproject.toml` or `.pysecurerc`)
PySecure automatically discovers configuration from `pyproject.toml` or `.pysecurerc` in the project root:

**`pyproject.toml`:**
```toml
[tool.pysecure]
severity = "MEDIUM"
fail_on = "HIGH"
ignore = ["DEBUG_MODE"]
```

**`.pysecurerc`:**
```json
{
  "severity": "MEDIUM",
  "fail_on": "HIGH",
  "ignore": ["DEBUG_MODE"]
}
```

---

## 🤖 Optional AI Remediation Guidance (Zero Disk Persistence)

PySecure can use Google's Gemini API to translate technical findings into endpoint-specific, prioritized developer remediation guidance:
- **Session-Only Security**: You enter the Gemini API key into the terminal when prompted. It remains **strictly in volatile process memory** and is **never written to disk, config files, or git**.
- When the terminal or process terminates, the key is completely purged.
- If you skip the prompt or do not have an API key, PySecure automatically falls back to its built-in rule engine so PDF generation always succeeds.
- The AI prompt explicitly forbids exploit payloads and attack instructions. The scanner remains useful without an API key because every finding includes a deterministic fix recommendation.

PySecure does not self-modify or silently update itself. Automatic updates would create a supply-chain and reproducibility risk. Keep the scanner current through reviewed package releases and pin versions in CI; the scanner can still operate offline with its built-in rules.

Dependency auditing is deterministic and offline by default. It reports unpinned requirements; known-vulnerability database lookups should be added only as an explicit network-enabled CI step. Active DAST is opt-in and uses harmless reflection canaries only. Never point it at systems without authorization.

## Remote DAST

### Safety limits

`scan-url` accepts only `http://` or `https://` localhost/private IP targets; DNS hostnames other than `localhost` are rejected. It blocks cross-origin links and redirects, caps response bodies at 1 MB, and applies a minimum 0.1-second delay plus a hard request budget. Public IP targets are rejected. The crawler discovers HTML links and forms but **does not submit forms**. Active canaries are optional and only add a unique query marker to HTML GET pages. Browser mode applies the same private-origin restriction and request budget.

### Authentication and authorization

Authentication is supplied as a JSON workflow file. Put secret values in environment variables; the file contains only references:

```json
{
  "login": {
    "method": "POST",
    "path": "/login",
    "csrf": {"path": "/login", "field": "csrf_token"},
    "form": {
      "username": {"env": "PYSECURE_TEST_USERNAME"},
      "password": {"env": "PYSECURE_TEST_PASSWORD"}
    }
  },
  "authorization": [
    {
      "path": "/admin",
      "unauthenticated_statuses": [302, 401, 403],
      "authenticated_statuses": [200]
    }
  ]
}
```

The optional `csrf` entry fetches a page first and reads the named hidden input field into the login form. Set `PYSECURE_TEST_USERNAME` and `PYSECURE_TEST_PASSWORD` in the shell or CI secret store, then run:

```bash
webvenom scan-url http://127.0.0.1:5000/ --auth-config dast-auth.json
```

Authorization checks run only for paths explicitly listed in the workflow. The scanner compares the expected anonymous and authenticated status codes; it does not infer a site's authorization policy. Auth sessions and credentials are held only in process memory and are not written to reports.

OSV lookups send package names and exact versions to `api.osv.dev`; use `--osv` only when network access and external package metadata disclosure are acceptable. Browser support is optional. Playwright performs rendered-page discovery and limited DOM HTML-sink canary checks; it is not full browser-based exploit testing.

---

## 🧪 Running Tests & Evaluation

Run the automated test suite from the repository root:
```bash
pytest
```

Optional framework evaluation scripts are also included:
```bash
python -m scripts.evaluate_flask
python -m scripts.evaluate_django
python -m scripts.evaluate_fastapi
```

---

## 📁 Repository Layout

- `pysecure/` — public CLI package.
- `security_scanner/` — scanner engine, analyzers, DAST checks, models, and report generators.
- `tests/` — unit and integration tests.
- `examples/` — small safe and vulnerable samples plus analyzer fixtures.
- `demos/vulnerable-flask/` and `demos/vulnerable-django/` — complete intentionally vulnerable apps; run only locally or in an isolated environment.
- `scripts/` — optional framework accuracy evaluation modules.

Generated reports, databases, build artifacts, and local secrets are ignored and should not be committed. This README is the canonical project documentation.

### GitHub Actions (including scheduled scans)

PySecure runs one bounded scan per command. Use your CI scheduler for recurring scans; this example runs on pushes and every Monday:

```yaml
name: PySecure
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install PySecure
        run: pip install .
      - name: Scan source
        run: webvenom scan . --static-only --dependencies --sarif pysecure.sarif --fail-on HIGH
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pysecure.sarif
```

---

## 📦 Publishing to PyPI

To build and publish this package to PyPI:
```bash
# 1. Install build tools
pip install build twine

# 2. Build distributions (source and wheel)
python -m build

# 3. Upload to PyPI
twine upload dist/*
```

