import os
import sys
import logging
import importlib.util
import argparse
from security_scanner import scan_app
from security_scanner.reporting.console import print_report
from security_scanner.reporting.html_report import save_html_report
from security_scanner.reporting.json_report import save_json_report
from security_scanner.reporting.pdf_report import save_pdf_report

def main():
    parser = argparse.ArgumentParser(description="Scan Flask app for security vulnerabilities.")
    parser.add_argument("--api-key", help="Session-only Gemini API key for AI executive report (not saved to disk).")
    parser.add_argument("--pdf", default="vuln_flask_project_report.pdf", help="Output PDF file path.")
    parser.add_argument("--no-prompt", action="store_true", help="Do not prompt for Gemini API key interactively.")
    args, _ = parser.parse_known_args()

    # Suppress backend web server logs for a clean presentation output
    logging.getLogger('werkzeug').setLevel(logging.CRITICAL)

    print("\n" + "=" * 60)
    print("  Scanning Full VULNERABLE FLASK Project (vuln-flask/)")
    print("=" * 60)

    # 1. Setup path to import the app
    app_dir = os.path.join(os.getcwd(), "vuln-flask")
    if not os.path.exists(app_dir):
        print(f"Error: {app_dir} not found.")
        return

    sys.path.append(app_dir)

    # 2. Dynamically load the 'app' from app.py
    try:
        spec = importlib.util.spec_from_file_location("vuln_app", os.path.join(app_dir, "app.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        app = getattr(module, "app", None)
        
        if not app:
            print("Error: 'app' object not found in vuln-flask/app.py")
            return

        # --- FIX: Set templates path correctly ---
        app.root_path = app_dir
        app.template_folder = os.path.join(app_dir, "templates")

        # Hide internal app stack traces from DAST attacks
        if hasattr(app, 'logger'):
            app.logger.setLevel(logging.CRITICAL)

        # 3. Run the scan
        result = scan_app(app, dynamic=True)
        
        # 4. Show and save findings
        print_report(result)
        save_json_report(result, "vuln_flask_project_report.json")
        save_html_report(result, "vuln_flask_project_report.html")
        save_pdf_report(result, args.pdf, api_key=args.api_key, prompt_for_key=not args.no_prompt)
        print(f"   [*] PDF report saved to: {args.pdf}")
        
        print(f"\n   Done. {len(result.findings)} issues found in {result.scan_duration_seconds:.3f}s")
        
    except Exception as e:
        print(f"Error during scan: {e}")

if __name__ == "__main__":
    main()
