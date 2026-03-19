"""
Run the security scanner against the Django example apps.

Usage:
    python run_django_scan.py
"""
from examples.vulnerable_django_app import application as vuln_app
from security_scanner import scan_app
from security_scanner.reporting.console import print_report
from security_scanner.reporting.json_report import save_json_report
from security_scanner.reporting.html_report import save_html_report


def main():
    print("\n" + "=" * 60)
    print("  Scanning VULNERABLE Django App")
    print("=" * 60)

    result = scan_app(vuln_app, dynamic=True, framework="django")
    print_report(result)
    save_json_report(result, "django_scan_report.json")
    save_html_report(result, "django_scan_report.html")

    print(f"\n   Done. {len(result.findings)} issues found in {result.scan_duration_seconds:.3f}s")


if __name__ == "__main__":
    main()
