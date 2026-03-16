"""Scan the vuln-flask app."""
import sys
sys.path.insert(0, ".")  # ensure project root is in path

from security_scanner import scan_app
from security_scanner.reporting.console import print_report
from security_scanner.reporting.json_report import save_json_report
from security_scanner.reporting.html_report import save_html_report

# Import YOUR Flask app
# This assumes vuln-flask/app.py has: app = Flask(__name__)
sys.path.insert(0, "vuln-flask")
from app import app

# ─── Run the scan ───────────────────────────────────────────
result = scan_app(app, dynamic=True)

# ─── Console output ─────────────────────────────────────────
print_report(result)

# ─── Save reports ────────────────────────────────────────────
save_json_report(result, "my_scan_report.json")
save_html_report(result, "my_scan_report.html")

print(f"\n   Done. {len(result.findings)} issues found in {result.scan_duration_seconds:.3f}s")
