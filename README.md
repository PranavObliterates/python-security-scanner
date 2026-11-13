# PySecure — Python Security Scanner (SAST + DAST)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%20(2021)-orange.svg)](https://owasp.org/Top10/)

**PySecure** is an embedded security scanner for Python web applications (**Flask, Django, and FastAPI**). It shifts security testing left by running both **Static Application Security Testing (SAST)** via AST analysis and **Dynamic Application Security Testing (DAST)** via in-memory simulated attacks right during development and CI/CD pipelines.

It generates human-friendly terminal reports, machine-readable JSON, visual HTML dashboards, and **executive PDF reports powered by Google Gemini AI**.

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
| **A03: Injection** | SQL Injection (SQLi) | SAST & DAST (Simulated Payloads) |
| **A03: Injection** | Cross-Site Scripting (Reflected XSS) | SAST & DAST (Response Reflection) |
| **A03: Injection** | Command Injection (RCE) | SAST |
| **A03: Injection** | Server-Side Template Injection (SSTI) | SAST & DAST |
| **A05: Security Misconfiguration** | Debug Mode Enabled | SAST (Global Config) |
| **A05: Security Misconfiguration** | CORS Wildcard with Credentials | SAST (Global Config) |
| **A05: Security Misconfiguration** | Missing Security Headers (CSP, HSTS, X-Frame) | DAST |
| **A08: Software & Data Integrity** | Insecure Deserialization (pickle, PyYAML) | SAST & DAST |
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
pip install pysecure-scanner
```

---

## 🏗️ Architecture & How It Works

PySecure operates via a dual-engine analysis pipeline designed for maximum speed and zero false positives:

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
     │ • Input source traces │                       │ • Fuzzing payloads    │
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
   - **Deep Taint Propagation**: Identifies untrusted user input sources (Flask `request.args`, `request.form`, `request.json`, `request.values`, `request.data`, `request.headers`; Django `request.GET`, `request.POST`, `request.body`, `request.COOKIES`) and tracks data flow across variable assignments, method transformations (e.g. `.strip()`, `.lower()`), nested collections (dictionaries, lists, tuples), and intermediate variables into sensitive sinks.
   - **Dangerous Sink Detection**: Catches raw SQL interpolation, `pickle.loads()`, `os.system()` / `subprocess` shell calls, unvalidated `open()` path traversals, unvalidated HTTP calls (SSRF), unvalidated redirects, and weak cryptographic hashing (`md4`, `md5`, `sha1`, `sha`).
   - **Sanitization-Aware**: Respects defensive measures such as `werkzeug.utils.secure_filename()` and `markupsafe.escape()`, eliminating false positives on properly sanitized values.
   - **Configuration Auditing**: Inspects Flask and Django application configurations for insecure `DEBUG = True`, weak or hardcoded `SECRET_KEY`, missing `CSRF` protection, and missing security middleware.

2. **Dynamic Analysis (DAST)**:
   - **In-Memory Simulated Probing**: Harnesses Flask and Django built-in test clients to execute safe, non-destructive payloads without deploying a live web server or network listeners.
   - **Response Reflection & Behavior Testing**: Detects Reflected XSS through DOM tag reflection, SQLi via database error responses, and SSTI via template evaluation differential checking against baseline responses.
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
pysecure scan vuln-flask/app.py --html report.html --pdf report.pdf
pysecure scan vuln-flask/ --static-only

# Scan a Django project by directory, manage.py, or wsgi module
pysecure scan vuln-django/
pysecure scan vuln-django/manage.py
pysecure scan vuln-django/vuln_django/wsgi.py --pdf django_audit.pdf
pysecure scan vuln_django.wsgi:application --pdf django_audit.pdf

# Scan with session-only Gemini API key
pysecure scan app.py --pdf audit.pdf --api-key YOUR_GEMINI_KEY

# Export SARIF for GitHub Code Scanning / CI
pysecure scan app.py --sarif results.sarif

# Static-only scan (fast mode without running test client)
pysecure scan app.py --static-only --json report.json
```

---

## 🤖 Gemini AI Executive Reporting (Zero Disk Persistence)

PySecure integrates directly with Google's Gemini models to translate technical findings into executive risk summaries and prioritized developer remediation roadmaps:
- **Session-Only Security**: You enter the Gemini API key into the terminal when prompted. It remains **strictly in volatile process memory** and is **never written to disk, config files, or git**.
- When the terminal or process terminates, the key is completely purged.
- If you skip the prompt or do not have an API key, PySecure automatically falls back to its built-in rule engine so PDF generation always succeeds.

---

## 🧪 Running Tests & Evaluation

PySecure includes a comprehensive evaluation suite with 100% precision and recall benchmarks:
```bash
# Run all unit and integration tests
pytest

# Measure scanner accuracy and confusion matrix on Flask
python evaluate_flask.py

# Measure scanner accuracy and confusion matrix on Django
python evaluate_django.py

# Run full multi-application test suite
python run_test_suite.py
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
