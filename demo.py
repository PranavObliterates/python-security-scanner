"""
PySecure Interactive Demonstration Script

Run with: python demo.py

Demonstrates scanning a web application, printing the ANSI security report,
and exporting reports to JSON, HTML, and SARIF formats.
"""
import sys
from pysecure import scan_app, print_report, save_json_report, save_html_report, save_sarif_report
from examples.vulnerable_flask_app import app

def main():
    print("=" * 65)
    print("  PySecure Quickstart Demo -- Python Security Scanner")
    print("=" * 65)
    print("[*] Running SAST + DAST scan against sample vulnerable application...")

    # Run scan (SAST + DAST)
    result = scan_app(app, dynamic=True)

    # Print human-friendly ANSI console report
    print_report(result)

    # Export machine-readable formats
    save_json_report(result, "demo_report.json")
    save_html_report(result, "demo_report.html")
    save_sarif_report(result, "demo_report.sarif")

    print("[*] Generated demo reports:")
    print("    - demo_report.json  (Machine-readable JSON)")
    print("    - demo_report.html  (Interactive HTML Dashboard)")
    print("    - demo_report.sarif (GitHub Code Scanning OASIS format)")
    print("\nTo generate an AI-powered PDF report with your Gemini key:")
    print("    pysecure scan examples/vulnerable_flask_app.py --pdf report.pdf")
    print("=" * 65)

if __name__ == "__main__":
    main()
