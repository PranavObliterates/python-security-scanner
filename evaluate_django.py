"""
Django Evaluation Framework — measures accuracy, precision, recall for Django scanning.

Similar to evaluate.py for Flask, this tests the scanner against Django-specific
code patterns and apps.

Run with: python evaluate_django.py
"""
import os
import sqlite3
import django
from django.conf import settings as django_settings

# Configure Django settings FIRST, before any other Django imports
if not django_settings.configured:
    django_settings.configure(
        DEBUG=True,
        SECRET_KEY="test-secret-key-for-eval",
        ROOT_URLCONF="evaluate_django",
        ALLOWED_HOSTS=["*"],
        MIDDLEWARE=[
            "django.middleware.common.CommonMiddleware",
        ],
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
    )
    django.setup()

from django.http import HttpResponse
from django.test import Client as DjangoClient
from django.urls import path
from django.utils.html import escape as django_escape

from security_scanner.analyzers.sql_injection import SQLInjectionAnalyzer
from security_scanner.analyzers.xss import XSSAnalyzer
from security_scanner.analyzers.secrets import SecretsAnalyzer
from security_scanner.analyzers.config import check_django_config
from security_scanner.core.route_discovery import discover_django_routes
from security_scanner.dynamic.payload_tester import run_django_dast_tests
from security_scanner.models.finding import VulnerabilityType


# ─── SAST Test Cases (Django-specific code patterns) ──────────────────────────
# Each: (description, source_code, vuln_type, is_vulnerable)

DJANGO_SAST_TEST_CASES = [
    # ═══════════════════════════════════════════════════════════
    # SQL INJECTION — TRUE POSITIVES (Django patterns)
    # ═══════════════════════════════════════════════════════════
    (
        "Django SQLi: f-string with request.GET",
        '''
user_id = request.GET.get("id")
query = f"SELECT * FROM users WHERE id = {user_id}"
        ''',
        "sqli", True
    ),
    (
        "Django SQLi: string concat with request.POST",
        '''
username = request.POST.get("username")
query = "SELECT * FROM users WHERE name = '" + username + "'"
        ''',
        "sqli", True
    ),
    (
        "Django SQLi: f-string DELETE with request.GET",
        '''
table = request.GET.get("table")
query = f"DELETE FROM {table} WHERE 1=1"
        ''',
        "sqli", True
    ),

    # ═══════════════════════════════════════════════════════════
    # SQL INJECTION — TRUE NEGATIVES
    # ═══════════════════════════════════════════════════════════
    (
        "Django Safe SQL: parameterized query",
        '''
user_id = request.GET.get("id")
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
        ''',
        "sqli", False
    ),
    (
        "Django Safe SQL: ORM usage",
        '''
user_id = request.GET.get("id")
user = User.objects.filter(id=user_id).first()
        ''',
        "sqli", False
    ),
    (
        "Django Safe SQL: no user input",
        '''
query = "SELECT * FROM users WHERE active = 1"
cursor.execute(query)
        ''',
        "sqli", False
    ),

    # ═══════════════════════════════════════════════════════════
    # XSS — TRUE POSITIVES (Django patterns)
    # ═══════════════════════════════════════════════════════════
    (
        "Django XSS: f-string HTML with request.GET",
        '''
term = request.GET.get("q", "")
return HttpResponse(f"<h1>Results for: {term}</h1>")
        ''',
        "xss", True
    ),
    (
        "Django XSS: f-string div with request.POST",
        '''
comment = request.POST.get("comment", "")
return HttpResponse(f"<div>{comment}</div>")
        ''',
        "xss", True
    ),

    # ═══════════════════════════════════════════════════════════
    # XSS — TRUE NEGATIVES
    # ═══════════════════════════════════════════════════════════
    (
        "Django Safe XSS: escaped output",
        '''
from django.utils.html import escape
term = request.GET.get("q", "")
return HttpResponse(f"<h1>Results for: {escape(term)}</h1>")
        ''',
        "xss", False
    ),
    (
        "Django Safe XSS: no HTML in output",
        '''
term = request.GET.get("q", "")
return HttpResponse(f"You searched for: {term}")
        ''',
        "xss", False
    ),
    (
        "Django Safe XSS: no user input",
        '''
title = "Welcome"
return HttpResponse(f"<h1>{title}</h1>")
        ''',
        "xss", False
    ),

    # ═══════════════════════════════════════════════════════════
    # SECRETS — TRUE POSITIVES
    # ═══════════════════════════════════════════════════════════
    (
        "Django Secret: hardcoded password",
        '''
db_password = "admin123"
        ''',
        "secrets", True
    ),
    (
        "Django Secret: hardcoded API key",
        '''
api_key = "sk-live-abcdef123456"
        ''',
        "secrets", True
    ),

    # ═══════════════════════════════════════════════════════════
    # SECRETS — TRUE NEGATIVES
    # ═══════════════════════════════════════════════════════════
    (
        "Django Safe secret: env var",
        '''
import os
db_password = os.environ.get("DB_PASSWORD")
        ''',
        "secrets", False
    ),
    (
        "Django Safe secret: empty string",
        '''
api_key = ""
        ''',
        "secrets", False
    ),
]


# ─── DAST Test Cases (Django apps) ────────────────────────────────────────────

def _build_dast_vulnerable_django_app():
    """Build a Django app with known vulnerabilities for DAST testing."""
    # Views defined here
    def vuln_user(request):
        user_id = request.GET.get("id", "1")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'alice')")
        query = f"SELECT * FROM users WHERE id = {user_id}"
        try:
            result = conn.execute(query).fetchall()
        except Exception as e:
            return HttpResponse(str(e), status=500)
        conn.close()
        return HttpResponse(str(result))

    def vuln_search(request):
        term = request.GET.get("q", "")
        return HttpResponse(f"<h1>Results for: {term}</h1>")

    return [vuln_user, vuln_search]


def _build_dast_safe_django_app():
    """Build a Django app that uses secure practices for DAST testing."""
    def safe_user(request):
        user_id = request.GET.get("id", "1")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'alice')")
        result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
        conn.close()
        return HttpResponse(str(result))

    def safe_search(request):
        term = request.GET.get("q", "")
        return HttpResponse(f"<h1>Results for: {django_escape(term)}</h1>")

    return [safe_user, safe_search]


# ─── URL patterns for DAST testing ─────────────────────────────────────────────
# These get set dynamically during evaluation
_vuln_views = _build_dast_vulnerable_django_app()
_safe_views = _build_dast_safe_django_app()

urlpatterns = [
    path("vuln/user/", _vuln_views[0], name="vuln_user"),
    path("vuln/search/", _vuln_views[1], name="vuln_search"),
    path("safe/user/", _safe_views[0], name="safe_user"),
    path("safe/search/", _safe_views[1], name="safe_search"),
]


# ─── Helper Functions ─────────────────────────────────────────────────────────

def run_analyzer(source_code, vuln_type):
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


# ─── SAST Evaluation ──────────────────────────────────────────────────────────

def evaluate_django_sast():
    tp = fp = tn = fn = 0

    _print_header("DJANGO SAST (Static Analysis) EVALUATION")
    print()

    for description, source_code, vuln_type, is_vulnerable in DJANGO_SAST_TEST_CASES:
        findings = run_analyzer(source_code, vuln_type)
        detected = len(findings) > 0

        if is_vulnerable and detected:
            status = "[OK] TP"
            tp += 1
        elif is_vulnerable and not detected:
            status = "[XX] FN"
            fn += 1
        elif not is_vulnerable and not detected:
            status = "[OK] TN"
            tn += 1
        else:
            status = "[XX] FP"
            fp += 1

        print(f"  {status}  {description}")

    _print_confusion_matrix(tp, fp, tn, fn, "DJANGO SAST")
    metrics = _calc_metrics(tp, fp, tn, fn)
    _print_metrics(metrics, "DJANGO SAST")
    return metrics


# ─── DAST Evaluation ──────────────────────────────────────────────────────────

def evaluate_django_dast():
    tp = fp = tn = fn = 0

    _print_header("DJANGO DAST (Dynamic Analysis) EVALUATION")
    print()

    # Discover routes from our test URL patterns
    routes = discover_django_routes()

    # Get vulnerable and safe route groups
    vuln_routes = [r for r in routes if "/vuln/" in r.path]
    safe_routes = [r for r in routes if "/safe/" in r.path]

    # Test 1: Vulnerable routes should trigger SQLi findings
    try:
        vuln_findings = run_django_dast_tests(vuln_routes)
        sqli_found = any(f.vuln_type == VulnerabilityType.SQL_INJECTION for f in vuln_findings)
        if sqli_found:
            print("  [OK] TP  DAST Django SQLi: detects SQL injection in /vuln/user/")
            tp += 1
        else:
            print("  [XX] FN  DAST Django SQLi: missed SQL injection in /vuln/user/")
            fn += 1
    except Exception as e:
        print(f"  [ERR]    DAST Django SQLi: {e}")
        fn += 1

    # Test 2: Vulnerable routes should trigger XSS findings
    try:
        xss_found = any(f.vuln_type == VulnerabilityType.XSS for f in vuln_findings)
        if xss_found:
            print("  [OK] TP  DAST Django XSS: detects reflected XSS in /vuln/search/")
            tp += 1
        else:
            print("  [XX] FN  DAST Django XSS: missed reflected XSS in /vuln/search/")
            fn += 1
    except Exception as e:
        print(f"  [ERR]    DAST Django XSS: {e}")
        fn += 1

    # Test 3: Safe routes should NOT trigger SQLi
    try:
        safe_findings = run_django_dast_tests(safe_routes)
        sqli_found = any(f.vuln_type == VulnerabilityType.SQL_INJECTION for f in safe_findings)
        if not sqli_found:
            print("  [OK] TN  DAST Django Safe: no SQLi in parameterized /safe/user/")
            tn += 1
        else:
            print("  [XX] FP  DAST Django Safe: false SQLi alarm on /safe/user/")
            fp += 1
    except Exception as e:
        print(f"  [ERR]    DAST Django Safe SQLi: {e}")
        tn += 1

    # Test 4: Safe routes should NOT trigger XSS
    try:
        xss_found = any(f.vuln_type == VulnerabilityType.XSS for f in safe_findings)
        if not xss_found:
            print("  [OK] TN  DAST Django Safe: no XSS in escaped /safe/search/")
            tn += 1
        else:
            print("  [XX] FP  DAST Django Safe: false XSS alarm on /safe/search/")
            fp += 1
    except Exception as e:
        print(f"  [ERR]    DAST Django Safe XSS: {e}")
        tn += 1

    _print_confusion_matrix(tp, fp, tn, fn, "DJANGO DAST")
    metrics = _calc_metrics(tp, fp, tn, fn)
    _print_metrics(metrics, "DJANGO DAST")
    return metrics


# ─── Config Evaluation ────────────────────────────────────────────────────────

def evaluate_django_config():
    tp = fp = tn = fn = 0

    _print_header("DJANGO CONFIG EVALUATION")
    print()

    # Current settings have DEBUG=True, weak SECRET_KEY, no CSRF, no Security MW
    findings = check_django_config()
    finding_types = [f.vuln_type for f in findings]

    # Should detect DEBUG mode
    if VulnerabilityType.DEBUG_MODE in finding_types:
        print("  [OK] TP  Config: detects DEBUG = True")
        tp += 1
    else:
        print("  [XX] FN  Config: missed DEBUG = True")
        fn += 1

    # Should detect weak SECRET_KEY
    if VulnerabilityType.HARDCODED_SECRET in finding_types:
        print("  [OK] TP  Config: detects weak SECRET_KEY")
        tp += 1
    else:
        print("  [XX] FN  Config: missed weak SECRET_KEY")
        fn += 1

    # Should detect missing CSRF middleware
    if VulnerabilityType.CSRF_MISSING in finding_types:
        print("  [OK] TP  Config: detects missing CsrfViewMiddleware")
        tp += 1
    else:
        print("  [XX] FN  Config: missed missing CsrfViewMiddleware")
        fn += 1

    # Should detect missing SecurityMiddleware
    if VulnerabilityType.MISSING_SECURITY_HEADER in finding_types:
        print("  [OK] TP  Config: detects missing SecurityMiddleware")
        tp += 1
    else:
        print("  [XX] FN  Config: missed missing SecurityMiddleware")
        fn += 1

    _print_confusion_matrix(tp, fp, tn, fn, "DJANGO CONFIG")
    metrics = _calc_metrics(tp, fp, tn, fn)
    _print_metrics(metrics, "DJANGO CONFIG")
    return metrics


# ─── Main evaluation ─────────────────────────────────────────────────────────

def evaluate():
    """Run full Django evaluation (SAST + DAST + Config) and print combined results."""
    print()
    print("*" * 70)
    print("  DJANGO SECURITY SCANNER -- FULL EVALUATION REPORT")
    print("*" * 70)

    sast = evaluate_django_sast()
    dast = evaluate_django_dast()
    config = evaluate_django_config()

    # Combined metrics
    combined_tp = sast["tp"] + dast["tp"] + config["tp"]
    combined_fp = sast["fp"] + dast["fp"] + config["fp"]
    combined_tn = sast["tn"] + dast["tn"] + config["tn"]
    combined_fn = sast["fn"] + dast["fn"] + config["fn"]
    combined = _calc_metrics(combined_tp, combined_fp, combined_tn, combined_fn)

    _print_confusion_matrix(combined_tp, combined_fp, combined_tn, combined_fn, "COMBINED DJANGO")
    _print_metrics(combined, "COMBINED DJANGO (SAST + DAST + CONFIG)")

    print("*" * 70)
    print("  DJANGO EVALUATION COMPLETE")
    print("*" * 70)
    print()

    return combined


if __name__ == "__main__":
    evaluate()
