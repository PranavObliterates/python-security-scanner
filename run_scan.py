"""Run the security scanner against the vulnerable test app."""
from examples.vulnerable_flask_app import app
from security_scanner import scan_app
from security_scanner.reporting.console import print_report
from security_scanner.reporting.json_report import save_json_report
from security_scanner.reporting.html_report import save_html_report

# ─── Run the scan ───────────────────────────────────────────
result = scan_app(app, dynamic=True)

# ─── Console output ─────────────────────────────────────────
print_report(result)

# ─── Save reports ────────────────────────────────────────────
save_json_report(result, "scan_report.json")
save_html_report(result, "scan_report.html")

print(f"\n   Done. {len(result.findings)} issues found in {result.scan_duration_seconds:.3f}s")
