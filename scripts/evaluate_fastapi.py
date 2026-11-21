"""
FastAPI Evaluation Framework for PySecure

Measures accuracy, precision, recall, F1 score and prints confusion matrices for FastAPI SAST, DAST, and Config.
Run with: python -m scripts.evaluate_fastapi
"""
import sqlite3
import sys
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import HTMLResponse
from starlette.testclient import TestClient

from security_scanner.core.scanner import scan_app
from security_scanner.core.route_discovery import discover_fastapi_routes
from security_scanner.analyzers.a05_security_misconfiguration import check_fastapi_config
from security_scanner.analyzers.a03_sql_injection import SQLInjectionAnalyzer
from security_scanner.analyzers.a03_cross_site_scripting import XSSAnalyzer
from security_scanner.analyzers.a01_path_traversal import PathTraversalAnalyzer
from security_scanner.analyzers.a10_server_side_request_forgery import SSRFAnalyzer
from security_scanner.analyzers.a03_command_injection import CommandInjectionAnalyzer
from security_scanner.analyzers.a02_weak_cryptography import WeakCryptoAnalyzer
from security_scanner.models.finding import VulnerabilityType

# ─── SAST Test Cases ───────────────────────────────────────────────────────────
# Each: (description, code_snippet, expected_vuln_type, is_vulnerable)

SAST_TEST_CASES = [
    # True Positives
    (
        "FastAPI SQLi: f-string with parameter",
        '''
def get_user(q: str):
    cur.execute(f"SELECT * FROM users WHERE name = '{q}'")
        ''',
        "sqli", True
    ),
    (
        "FastAPI XSS: unescaped parameter reflection",
        '''
def search(query: str):
    return HTMLResponse(f"<h1>Results: {query}</h1>")
        ''',
        "xss", True
    ),
    (
        "FastAPI Path Traversal: direct open",
        '''
def read_doc(path: str):
    with open(path, "r") as f:
        return f.read()
        ''',
        "path_traversal", True
    ),
    (
        "FastAPI SSRF: unvalidated requests.get",
        '''
def proxy(target: str):
    import requests
    return requests.get(target).text
        ''',
        "ssrf", True
    ),
    (
        "FastAPI Command Injection: os.system with parameter",
        '''
def run_tool(cmd: str):
    import os
    os.system(cmd)
        ''',
        "cmd_injection", True
    ),
    (
        "FastAPI Weak Crypto: md5 hashing",
        '''
def hash_pass(p: str):
    import hashlib
    return hashlib.md5(p.encode()).hexdigest()
        ''',
        "weak_crypto", True
    ),

    # True Negatives (Safe patterns)
    (
        "FastAPI Safe SQL: parameterized query",
        '''
def get_user(q: str):
    cur.execute("SELECT * FROM users WHERE name = ?", (q,))
        ''',
        "sqli", False
    ),
    (
        "FastAPI Safe XSS: html.escape",
        '''
def search(query: str):
    import html
    return HTMLResponse(f"<h1>Results: {html.escape(query)}</h1>")
        ''',
        "xss", False
    ),
    (
        "FastAPI Safe Path: secure_filename",
        '''
def read_doc(path: str):
    from werkzeug.utils import secure_filename
    safe = secure_filename(path)
    with open(f"/safe/dir/{safe}", "r") as f:
        return f.read()
        ''',
        "path_traversal", False
    ),
    (
        "FastAPI Safe SSRF: hardcoded internal URL",
        '''
def proxy(q: str):
    import requests
    return requests.get("https://api.internal.service/health").text
        ''',
        "ssrf", False
    ),
    (
        "FastAPI Safe Crypto: sha256 hashing",
        '''
def hash_pass(p: str):
    import hashlib
    return hashlib.sha256(p.encode()).hexdigest()
        ''',
        "weak_crypto", False
    ),
]


def run_sast_eval():
    tp = fp = tn = fn = 0
    print("\n" + "=" * 70)
    print("  FASTAPI SAST (Static Analysis) EVALUATION")
    print("=" * 70)

    for desc, code, vtype, is_vuln in SAST_TEST_CASES:
        if vtype == "sqli":
            analyzer = SQLInjectionAnalyzer("/test", "test.py", code)
        elif vtype == "xss":
            analyzer = XSSAnalyzer("/test", "test.py", code)
        elif vtype == "path_traversal":
            analyzer = PathTraversalAnalyzer("/test", "test.py", code)
        elif vtype == "ssrf":
            analyzer = SSRFAnalyzer("/test", "test.py", code)
        elif vtype == "cmd_injection":
            analyzer = CommandInjectionAnalyzer("/test", "test.py", code)
        elif vtype == "weak_crypto":
            analyzer = WeakCryptoAnalyzer("/test", "test.py", code)
        else:
            continue

        findings = analyzer.analyze()
        detected = len(findings) > 0

        if is_vuln and detected:
            tp += 1
            print(f"  [OK] TP  {desc}")
        elif not is_vuln and not detected:
            tn += 1
            print(f"  [OK] TN  {desc}")
        elif is_vuln and not detected:
            fn += 1
            print(f"  [XX] FN  {desc}")
        else:
            fp += 1
            print(f"  [XX] FP  {desc}")

    return tp, fp, tn, fn


def run_config_eval():
    print("\n" + "=" * 70)
    print("  FASTAPI CONFIG EVALUATION")
    print("=" * 70)
    tp = fp = tn = fn = 0

    # 1. Vuln app with debug=True and CORS wildcard credentials
    vuln_app = FastAPI(debug=True)
    vuln_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
    )
    vuln_findings = check_fastapi_config(vuln_app)
    types = [f.vuln_type for f in vuln_findings]

    if VulnerabilityType.DEBUG_MODE in types:
        tp += 1
        print("  [OK] TP  Config: detects FastAPI debug=True")
    else:
        fn += 1
        print("  [XX] FN  Config: missed FastAPI debug=True")

    if VulnerabilityType.CORS_MISCONFIGURATION in types:
        tp += 1
        print("  [OK] TP  Config: detects CORS wildcard with credentials")
    else:
        fn += 1
        print("  [XX] FN  Config: missed CORS wildcard with credentials")

    # 2. Safe app
    safe_app = FastAPI(debug=False)
    safe_app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://myapp.com"],
        allow_credentials=True,
    )
    safe_findings = check_fastapi_config(safe_app)
    safe_types = [f.vuln_type for f in safe_findings]

    if VulnerabilityType.DEBUG_MODE not in safe_types:
        tn += 1
        print("  [OK] TN  Config: safe debug=False")
    else:
        fp += 1
        print("  [XX] FP  Config: false alarm on debug=False")

    if VulnerabilityType.CORS_MISCONFIGURATION not in safe_types:
        tn += 1
        print("  [OK] TN  Config: safe explicit CORS origin")
    else:
        fp += 1
        print("  [XX] FP  Config: false alarm on explicit CORS origin")

    return tp, fp, tn, fn


def compute_metrics(tp, fp, tn, fn):
    total = tp + fp + tn + fn
    acc = (tp + tn) / total * 100 if total else 0
    prec = tp / (tp + fp) * 100 if (tp + fp) else 100
    rec = tp / (tp + fn) * 100 if (tp + fn) else 100
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) else 0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "total": total, "accuracy": acc, "precision": prec,
        "recall": rec, "f1": f1
    }


def evaluate_fastapi_sast():
    tp, fp, tn, fn = run_sast_eval()
    return compute_metrics(tp, fp, tn, fn)


def evaluate_fastapi_config():
    tp, fp, tn, fn = run_config_eval()
    return compute_metrics(tp, fp, tn, fn)


def evaluate():
    s_tp, s_fp, s_tn, s_fn = run_sast_eval()
    c_tp, c_fp, c_tn, c_fn = run_config_eval()
    return compute_metrics(s_tp + c_tp, s_fp + c_fp, s_tn + c_tn, s_fn + c_fn)


def print_metrics(name, tp, fp, tn, fn):
    m = compute_metrics(tp, fp, tn, fn)
    print("\n" + "=" * 70)
    print(f"  METRICS — {name}")
    print("=" * 70)
    print(f"  Total test cases:  {m['total']}")
    print(f"  True Positives:    {m['tp']}")
    print(f"  False Positives:   {m['fp']}")
    print(f"  True Negatives:    {m['tn']}")
    print(f"  False Negatives:   {m['fn']}")
    print(f"  Accuracy:          {m['accuracy']:.1f}%")
    print(f"  Precision:         {m['precision']:.1f}%")
    print(f"  Recall:            {m['recall']:.1f}%")
    print(f"  F1 Score:          {m['f1']:.1f}%")



def main():
    print("*" * 70)
    print("  FASTAPI SECURITY SCANNER -- FULL EVALUATION REPORT")
    print("*" * 70)

    sast_tp, sast_fp, sast_tn, sast_fn = run_sast_eval()
    print_metrics("FASTAPI SAST", sast_tp, sast_fp, sast_tn, sast_fn)

    cfg_tp, cfg_fp, cfg_tn, cfg_fn = run_config_eval()
    print_metrics("FASTAPI CONFIG", cfg_tp, cfg_fp, cfg_tn, cfg_fn)

    tot_tp = sast_tp + cfg_tp
    tot_fp = sast_fp + cfg_fp
    tot_tn = sast_tn + cfg_tn
    tot_fn = sast_fn + cfg_fn
    print_metrics("COMBINED FASTAPI (SAST + CONFIG)", tot_tp, tot_fp, tot_tn, tot_fn)
    print("*" * 70)
    print("  FASTAPI EVALUATION COMPLETE")
    print("*" * 70)


if __name__ == "__main__":
    main()
