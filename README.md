# 🛡️ Python Security Scanner

A Python-based embedded security scanner that automatically detects vulnerabilities in Flask web applications using **AST (Abstract Syntax Tree) analysis** and **configuration inspection**.

> Built as an academic project to demonstrate static analysis techniques for web application security.

---

## 🔍 What It Detects

| Vulnerability | Severity | Detection Method |
|--------------|----------|-----------------|
| **SQL Injection** | 🔴 CRITICAL | AST analysis of f-strings and string concatenation in SQL queries |
| **Cross-Site Scripting (XSS)** | 🔴 CRITICAL | AST analysis of HTML output with unescaped user input |
| **Hardcoded Secrets** | 🟠 HIGH | Inspection of Flask `SECRET_KEY` configuration |
| **Missing CSRF Protection** | 🟠 HIGH | Detection of missing Flask-WTF CSRFProtect |

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/PranavObliterates/python-security-scanner.git
cd python-security-scanner
```

### 2. Set up virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install flask
```

### 4. Run the scanner

```bash
python run_scan.py
```

---

## 📦 Usage as a Library

You can integrate the scanner into your own Flask project with just **3 lines of code**:

```python
from security_scanner import scan_app
from your_app import app

result = scan_app(app)

print(f"Found {len(result.findings)} vulnerabilities")
print(f"Critical: {result.critical_count}")
print(f"High: {result.high_count}")

for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.vuln_type.value} at {finding.endpoint}")
    print(f"  → {finding.explanation}")
    print(f"  → Fix: {finding.fix_recommendation}")
```

---

## 📊 Sample Output

```
============================================================
  SECURITY SCAN REPORT — examples.vulnerable_app
  Routes scanned: 4
  Scan time: 0.002s
============================================================

  🔴 [1] CRITICAL: SQL_INJECTION
      Endpoint: /user
      Code:     query = f"SELECT * FROM users WHERE id = {user_id}"
      Why:      Variable 'user_id' comes from user input and is inserted
                directly into a SQL query.
      Fix:      Use parameterized queries instead of string interpolation.

  🔴 [2] CRITICAL: XSS
      Endpoint: /search
      Code:     return f"<h1>Results for: {term}</h1>"
      Why:      Variable 'term' contains user input placed directly into
                HTML output without escaping.
      Fix:      Escape all user input before including in HTML.

  🟠 [3] HIGH: HARDCODED_SECRET
      Code:     app.secret_key = "password123"
      Fix:      Use a long random secret key from environment variables.

  🟠 [4] HIGH: CSRF_MISSING
      Code:     No CSRF protection detected
      Fix:      Add Flask-WTF CSRF protection.

  Summary: 3 Critical | 2 High | 0 Medium
  Total issues: 5
============================================================
```

---

## 🗂️ Project Structure

```
python-security-scanner/
├── security_scanner/           # Main library package
│   ├── __init__.py             # Public API (scan_app)
│   ├── core/
│   │   ├── scanner.py          # Orchestrator — ties everything together
│   │   └── route_discovery.py  # Discovers Flask routes via introspection
│   ├── analyzers/
│   │   ├── sql_injection.py    # SQL Injection detection via AST
│   │   ├── xss.py              # XSS detection via AST
│   │   └── config.py           # Config checks (secrets, CSRF, debug)
│   ├── models/
│   │   ├── finding.py          # Finding dataclass & enums
│   │   └── scan_result.py      # ScanResult container
│   └── reporting/
│       └── json_report.py      # JSON report generation
├── examples/
│   └── vulnerable_app.py       # Deliberately vulnerable Flask app for testing
├── run_scan.py                 # CLI entry point
├── scan_report.json            # Generated after scanning (git-ignored)
├── .gitignore
└── README.md
```

---

## 🧪 How It Works

### 1. Route Discovery
The scanner imports your Flask app and uses `app.url_map` to automatically discover all registered routes and their view functions.

### 2. AST Analysis
For each route's source code, the scanner parses it into an **Abstract Syntax Tree** and walks the tree looking for dangerous patterns:

- **SQL Injection**: Detects f-strings and string concatenation containing SQL keywords (`SELECT`, `INSERT`, `DELETE`, etc.) where variables come from `request.args`, `request.form`, or other user input sources.
- **XSS**: Detects f-strings containing HTML tags (`<h1>`, `<div>`, etc.) with unescaped user input, and `render_template_string()` calls with user-controlled variables.

### 3. Configuration Inspection
The scanner checks the Flask app object directly for:
- Weak or hardcoded `SECRET_KEY` values
- Missing CSRF protection (Flask-WTF)
- Debug mode enabled in production

### 4. Report Generation
Results are output to the console with severity icons and also saved as a structured JSON report for CI/CD integration.

---

## 🛣️ Roadmap

- [x] SQL Injection detection (AST-based)
- [x] XSS detection (AST-based)
- [x] Configuration security checks
- [x] JSON report output
- [x] `scan_app()` public API
- [ ] Security header checks (CSP, HSTS, X-Frame-Options)
- [ ] Dynamic testing with attack payloads
- [ ] HTML report generation
- [ ] Django & FastAPI support
- [ ] pytest test suite
- [ ] CI/CD GitHub Actions integration

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-analyzer`)
3. Commit your changes (`git commit -m "Add new analyzer"`)
4. Push to the branch (`git push origin feature/new-analyzer`)
5. Open a Pull Request

---

## 📚 References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Prevention](https://owasp.org/www-community/attacks/csrf)
- [Python AST Module Documentation](https://docs.python.org/3/library/ast.html)
- [Flask Security Considerations](https://flask.palletsprojects.com/en/stable/security/)

---

## 📄 License

This project is licensed under the MIT License.

---

**Built by Coders** 🚀
