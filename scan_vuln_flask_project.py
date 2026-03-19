import os
import sys
import logging
import importlib.util
from security_scanner import scan_app
from security_scanner.reporting.console import print_report
from security_scanner.reporting.html_report import save_html_report
from security_scanner.reporting.json_report import save_json_report

def main():
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
        
        print(f"\n   Done. {len(result.findings)} issues found in {result.scan_duration_seconds:.3f}s")
        
    except Exception as e:
        print(f"Error during scan: {e}")

if __name__ == "__main__":
    main()
