"""Run the security scanner against the vulnerable test app."""
import sys
from examples.vulnerable_flask_app import app
from security_scanner import scan_app
from security_scanner.reporting.console import print_report
from security_scanner.reporting.json_report import save_json_report
from security_scanner.reporting.html_report import save_html_report
from security_scanner.reporting.pdf_report import save_pdf_report

# ─── Run the scan ───────────────────────────────────────────
result = scan_app(app, dynamic=True)

# ─── Console output ─────────────────────────────────────────
print_report(result)

# ─── Save reports ────────────────────────────────────────────
save_json_report(result, "flask_scan_report.json")
save_html_report(result, "flask_scan_report.html")
save_pdf_report(result, "flask_scan_report.pdf", prompt_for_key=False)

print(f"\n   Done. {len(result.findings)} issues found in {result.scan_duration_seconds:.3f}s")
print("   [*] PDF report saved to: flask_scan_report.pdf")
