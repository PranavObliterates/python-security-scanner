"""
Evaluation Framework for the Python Security Scanner

Measures accuracy, precision, recall, F1 score and prints a confusion matrix.
Run with: python evaluate.py

How it works:
  1. Define test cases: code snippets labeled as vulnerable or safe (SAST)
  2. Define DAST test cases: Flask routes to probe with payloads (DAST)
  3. Run the scanner's analyzers on each snippet / app
  4. Compare scanner output to ground truth
  5. Calculate and display metrics (separate + combined)
"""
import sqlite3
from flask import Flask, request, render_template_string  # type: ignore
from markupsafe import escape
from security_scanner.analyzers.sql_injection import SQLInjectionAnalyzer  # type: ignore
from security_scanner.analyzers.xss import XSSAnalyzer  # type: ignore
from security_scanner.analyzers.secrets import SecretsAnalyzer  # type: ignore
from security_scanner.dynamic.payload_tester import run_dast_tests  # type: ignore
from security_scanner.core.route_discovery import discover_flask_routes  # type: ignore
from security_scanner.models.finding import VulnerabilityType  # type: ignore

# ─── SAST Test Cases ───────────────────────────────────────────────────────────
# Each test case: (description, source_code, vuln_type, is_vulnerable)
# vuln_type: "sqli", "xss", or "secrets"
# is_vulnerable: True = should be flagged, False = should NOT be flagged

SAST_TEST_CASES = [
    # ══════════════════════════════════════════════════════════════
    # SQL INJECTION — TRUE POSITIVES (should be detected)
    # ══════════════════════════════════════════════════════════════
    (
        "SQLi: f-string with user input",
        '''
user_id = request.args.get("id")
query = f"SELECT * FROM users WHERE id = {user_id}"
        ''',
        "sqli", True
    ),
    (
        "SQLi: string concat with user input",
        '''
username = request.form.get("username")
query = "SELECT * FROM users WHERE name = '" + username + "'"
        ''',
        "sqli", True
    ),
    (
        "SQLi: f-string DELETE with user input",
        '''
table = request.args.get("table")
query = f"DELETE FROM {table} WHERE 1=1"
        ''',
        "sqli", True
    ),
    (
        "SQLi: f-string INSERT with user input",
        '''
name = request.form.get("name")
query = f"INSERT INTO users (name) VALUES ('{name}')"
        ''',
        "sqli", True
    ),
    (
        "SQLi: f-string UPDATE with user input",
        '''
email = request.args.get("email")
query = f"UPDATE users SET email = '{email}' WHERE id = 1"
        ''',
        "sqli", True
    ),
    (
        "SQLi: tricky spaces (should be detected but might be missed)",
        '''
user_id    =    request.args.get("id")
query = f"SELECT * FROM users WHERE id = {user_id}"
        ''',
        "sqli", True
    ),

    # ══════════════════════════════════════════════════════════════
    # SQL INJECTION — TRUE NEGATIVES (should NOT be detected)
    # ══════════════════════════════════════════════════════════════
    (
        "Safe SQL: parameterized query",
        '''
user_id = request.args.get("id")
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
        ''',
        "sqli", False
    ),
    (
        "Safe SQL: no user input in f-string",
        '''
import datetime
date = datetime.datetime.now().strftime("%Y-%m-%d")
query = f"SELECT * FROM logs WHERE date = '{date}'"
        ''',
        "sqli", False
    ),
    (
        "Safe SQL: ORM usage",
        '''
user_id = request.args.get("id")
user = User.query.filter_by(id=user_id).first()
        ''',
        "sqli", False
    ),
    (
        "Safe SQL: plain string no interpolation",
        '''
query = "SELECT * FROM users WHERE active = 1"
cursor.execute(query)
        ''',
        "sqli", False
    ),
    (
        "Safe SQL: constant in f-string",
        '''
limit = 10
query = f"SELECT * FROM users LIMIT {limit}"
        ''',
        "sqli", False
    ),

    # ══════════════════════════════════════════════════════════════
    # XSS — TRUE POSITIVES
    # ══════════════════════════════════════════════════════════════
    (
        "XSS: f-string HTML with user input",
        '''
term = request.args.get("q", "")
return f"<h1>Results for: {term}</h1>"
        ''',
        "xss", True
    ),
    (
        "XSS: f-string div with user input",
        '''
name = request.args.get("name", "")
return f"<div class='greeting'>Hello {name}!</div>"
        ''',
        "xss", True
    ),
    (
        "XSS: f-string paragraph with user input",
        '''
comment = request.form.get("comment", "")
return f"<p>{comment}</p>"
        ''',
        "xss", True
    ),

    # ══════════════════════════════════════════════════════════════
    # XSS — TRUE NEGATIVES
    # ══════════════════════════════════════════════════════════════
    (
        "Safe XSS: escaped output",
        '''
from markupsafe import escape
term = request.args.get("q", "")
return f"<h1>Results for: {escape(term)}</h1>"
        ''',
        "xss", False
    ),
    (
        "Safe XSS: no user input in HTML",
        '''
title = "Welcome"
return f"<h1>{title}</h1>"
        ''',
        "xss", False
    ),
    (
        "Safe XSS: plain text no HTML",
        '''
term = request.args.get("q", "")
return f"You searched for: {term}"
        ''',
        "xss", False
    ),
    (
        "Safe XSS: using render_template (safe)",
        '''
name = request.args.get("name", "")
return render_template("profile.html", name=name)
        ''',
        "xss", False
    ),

    # ══════════════════════════════════════════════════════════════
    # SECRETS — TRUE POSITIVES
    # ══════════════════════════════════════════════════════════════
    (
        "Secret: hardcoded password",
        '''
password = "supersecret123"
db_password = "admin123"
        ''',
        "secrets", True
    ),
    (
        "Secret: hardcoded API key",
        '''
api_key = "sk-1234567890abcdef"
        ''',
        "secrets", True
    ),
    (
        "Secret: hardcoded token",
        '''
auth_token = "bearer-xyz-123456"
        ''',
        "secrets", True
    ),

    # ══════════════════════════════════════════════════════════════
    # SECRETS — TRUE NEGATIVES
    # ══════════════════════════════════════════════════════════════
    (
        "Safe secret: env var",
        '''
import os
password = os.environ.get("DB_PASSWORD")
        ''',
        "secrets", False
    ),
    (
        "Safe secret: no secret variable names",
        '''
username = "admin"
count = 42
        ''',
        "secrets", False
    ),
    (
        "Safe secret: empty string",
        '''
api_key = ""
        ''',
        "secrets", False
    ),
]


# ─── DAST Test Cases ───────────────────────────────────────────────────────────
# Each: (description, vuln_type_to_check, is_vulnerable)
# These use a real Flask app with test client

def _build_dast_vulnerable_app():
    """Build a Flask app with known vulnerabilities for DAST testing."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "password123"

    @app.route("/")
    def index():
        return "<h1>Home</h1>"

    @app.route("/user")
    def get_user():
        """VULNERABLE: SQL injection via f-string."""
        user_id = request.args.get("id", "1")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'alice')")
        query = f"SELECT * FROM users WHERE id = {user_id}"
        try:
            result = conn.execute(query).fetchall()
        except Exception as e:
            return str(e), 500
        conn.close()
        return str(result)

    @app.route("/search")
    def search():
        """VULNERABLE: Reflected XSS."""
        term = request.args.get("q", "")
        return f"<h1>Results for: {term}</h1>"

    @app.route("/profile")
    def profile():
        """VULNERABLE: XSS via render_template_string."""
        name = request.args.get("name", "")
        template = f"<h1>Hello {name}</h1>"
        return render_template_string(template)

    @app.route("/login", methods=["POST"])
    def login():
        """VULNERABLE: SQL injection via string concat."""
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        try:
            result = conn.execute(query).fetchone()
        except Exception as e:
            return str(e), 500
        conn.close()
        return "OK" if result else "Failed"

    return app


def _build_dast_safe_app():
    """Build a Flask app that uses secure practices."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "a" * 32

    @app.route("/")
    def index():
        return "<h1>Home - Safe</h1>"

    @app.route("/user")
    def get_user():
        """SAFE: Parameterized query."""
        user_id = request.args.get("id", "1")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'alice')")
        result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
        conn.close()
        return str(result)

    @app.route("/search")
    def search():
        """SAFE: Escaped output."""
        term = request.args.get("q", "")
        return f"<h1>Results for: {escape(term)}</h1>"

    return app


DAST_TEST_CASES = [
    # (description, app_builder, vuln_type_to_find, expect_found)
    ("DAST SQLi: detects SQL injection in /user",
     _build_dast_vulnerable_app, VulnerabilityType.SQL_INJECTION, True),
    ("DAST XSS: detects reflected XSS in /search",
     _build_dast_vulnerable_app, VulnerabilityType.XSS, True),
    ("DAST Safe: no SQLi in parameterized /user",
     _build_dast_safe_app, VulnerabilityType.SQL_INJECTION, False),
    ("DAST Safe: no XSS in escaped /search",
     _build_dast_safe_app, VulnerabilityType.XSS, False),
]


def run_analyzer(source_code: str, vuln_type: str):
    """Run the appropriate SAST analyzer and return findings."""
    if vuln_type == "sqli":
        analyzer = SQLInjectionAnalyzer("/test", "test.py", source_code)
    elif vuln_type == "xss":
        analyzer = XSSAnalyzer("/test", "test.py", source_code)
    elif vuln_type == "secrets":
        analyzer = SecretsAnalyzer("/test", "test.py", source_code)
    else:
        return []
    return analyzer.analyze()


def _print_header(text):
    print()
    print("=" * 70)
    print(f"  {text}")
    print("=" * 70)


def _print_confusion_matrix(tp, fp, tn, fn, label=""):
    title = f"CONFUSION MATRIX{' — ' + label if label else ''}"
    _print_header(title)
    print()
    print("                        Predicted")
    print("                   Positive    Negative")
    print(f"  Actual Positive    TP={tp:<5}    FN={fn:<5}")
    print(f"  Actual Negative    FP={fp:<5}    TN={tn:<5}")


def _calc_metrics(tp, fp, tn, fn):
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total * 100 if total > 0 else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "total": total,
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1,
    }


def _print_metrics(metrics, label=""):
    title = f"METRICS{' — ' + label if label else ''}"
    _print_header(title)
    print()
    print(f"  Total test cases:  {metrics['total']}")
    print(f"  True Positives:    {metrics['tp']}")
    print(f"  False Positives:   {metrics['fp']}")
    print(f"  True Negatives:    {metrics['tn']}")
    print(f"  False Negatives:   {metrics['fn']}")
    print()
    print(f"  Accuracy:          {metrics['accuracy']:.1f}%")
    print(f"  Precision:         {metrics['precision']:.1f}%")
    print(f"  Recall:            {metrics['recall']:.1f}%")
    print(f"  F1 Score:          {metrics['f1']:.1f}%")
    print()

    if metrics['accuracy'] >= 80:
        print(f"  Rating: EXCELLENT -- Scanner performs well on {label or 'test'} cases.")
    elif metrics['accuracy'] >= 65:
        print("  Rating: GOOD -- Scanner catches most issues with some false positives/negatives.")
    elif metrics['accuracy'] >= 50:
        print("  Rating: FAIR -- Scanner needs improvement in detection accuracy.")
    else:
        print("  Rating: POOR -- Scanner needs significant improvement.")


def evaluate_sast():
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    _print_header("SAST (Static Analysis) EVALUATION")
    print()

    for description, source_code, vuln_type, is_vulnerable in SAST_TEST_CASES:
        findings = run_analyzer(source_code, vuln_type)
        detected = len(findings) > 0

        if is_vulnerable and detected:
            status = "[OK] TP"
            tp += 1  # type: ignore
        elif is_vulnerable and not detected:
            status = "[XX] FN"
            fn += 1  # type: ignore
        elif not is_vulnerable and not detected:
            status = "[OK] TN"
            tn += 1  # type: ignore
        else:
            status = "[XX] FP"
            fp += 1  # type: ignore

        print(f"  {status}  {description}")

    _print_confusion_matrix(tp, fp, tn, fn, "SAST")
    metrics = _calc_metrics(tp, fp, tn, fn)
    _print_metrics(metrics, "SAST")
    return metrics


def evaluate_dast():
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    _print_header("DAST (Dynamic Analysis) EVALUATION")
    print()

    for description, app_builder, vuln_type, expect_found in DAST_TEST_CASES:
        app = app_builder()
        routes = discover_flask_routes(app)
        try:
            findings = run_dast_tests(app, routes)
        except Exception as e:
            findings = []
            print(f"  [ERR] {description} — {e}")
            if expect_found:
                fn += 1  # type: ignore
            else:
                tn += 1  # type: ignore
            continue

        detected = any(f.vuln_type == vuln_type for f in findings)

        if expect_found and detected:
            status = "[OK] TP"
            tp += 1  # type: ignore
        elif expect_found and not detected:
            status = "[XX] FN"
            fn += 1  # type: ignore
        elif not expect_found and not detected:
            status = "[OK] TN"
            tn += 1  # type: ignore
        else:
            status = "[XX] FP"
            fp += 1  # type: ignore

        print(f"  {status}  {description}")

    _print_confusion_matrix(tp, fp, tn, fn, "DAST")
    metrics = _calc_metrics(tp, fp, tn, fn)
    _print_metrics(metrics, "DAST")
    return metrics


def evaluate():
    """Run full evaluation (SAST + DAST) and print combined results."""
    print()
    print("*" * 70)
    print("  SECURITY SCANNER -- FULL EVALUATION REPORT")
    print("*" * 70)

    sast = evaluate_sast()
    dast = evaluate_dast()

    # Combined metrics
    combined_tp = sast["tp"] + dast["tp"]
    combined_fp = sast["fp"] + dast["fp"]
    combined_tn = sast["tn"] + dast["tn"]
    combined_fn = sast["fn"] + dast["fn"]
    combined = _calc_metrics(combined_tp, combined_fp, combined_tn, combined_fn)

    _print_confusion_matrix(combined_tp, combined_fp, combined_tn, combined_fn, "COMBINED")
    _print_metrics(combined, "COMBINED (SAST + DAST)")

    print("*" * 70)
    print("  EVALUATION COMPLETE")
    print("*" * 70)
    print()

    return combined


if __name__ == "__main__":
    evaluate()
