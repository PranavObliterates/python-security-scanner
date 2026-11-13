import os
import sys
import logging
import django
from django.core.wsgi import get_wsgi_application
import argparse
from security_scanner import scan_app
from security_scanner.reporting.console import print_report
from security_scanner.reporting.html_report import save_html_report
from security_scanner.reporting.json_report import save_json_report
from security_scanner.reporting.pdf_report import save_pdf_report

def main():
    parser = argparse.ArgumentParser(description="Scan Django app for security vulnerabilities.")
    parser.add_argument("--api-key", help="Session-only Gemini API key for AI executive report (not saved to disk).")
    parser.add_argument("--pdf", default="vuln_django_project_report.pdf", help="Output PDF file path.")
    parser.add_argument("--no-prompt", action="store_true", help="Do not prompt for Gemini API key interactively.")
    args, _ = parser.parse_known_args()

    # Suppress backend web server logs for a clean presentation output
    logging.getLogger('django.request').setLevel(logging.CRITICAL)
    logging.getLogger('django.server').setLevel(logging.CRITICAL)

    print("\n" + "=" * 60)
    print("  Scanning Full VULNERABLE DJANGO Project (vuln-django/)")
    print("=" * 60)

    # 1. Setup path and environment for Django
    project_dir = os.path.join(os.getcwd(), "vuln-django")
    if not os.path.exists(project_dir):
        print(f"Error: {project_dir} not found.")
        return

    sys.path.append(project_dir)
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vuln_django.settings')

    try:
        # 2. Initialize Django and get application
        django.setup()
        application = get_wsgi_application()

        # 3. Run the scan
        result = scan_app(application, dynamic=True, framework="django")
        
        # 4. Show and save findings
        print_report(result)
        save_json_report(result, "vuln_django_project_report.json")
        save_html_report(result, "vuln_django_project_report.html")
        save_pdf_report(result, args.pdf, api_key=args.api_key, prompt_for_key=not args.no_prompt)
        print(f"   [*] PDF report saved to: {args.pdf}")
        
        print(f"\n   Done. {len(result.findings)} issues found in {result.scan_duration_seconds:.3f}s")
        
    except Exception as e:
        print(f"Error during Django scan: {e}")

if __name__ == "__main__":
    main()
