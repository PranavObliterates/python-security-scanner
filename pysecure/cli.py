"""Command Line Interface for PySecure."""
import os
import sys
import argparse
import importlib.util
from security_scanner.core.scanner import scan_app
from security_scanner.reporting.console import print_report
from security_scanner.reporting.json_report import save_json_report
from security_scanner.reporting.html_report import save_html_report
from security_scanner.reporting.pdf_report import save_pdf_report
from security_scanner import __version__


def load_app_from_path(app_target: str):
    """Load Flask or Django app object from file path or module string.

    Supports:
        - "path/to/app.py" (looks for 'app' or 'application')
        - "path/to/app.py:app"
        - "C:\\path\\to\\app.py:app"
        - "my_module.wsgi:application"
    """
    file_part, var_name = app_target, None
    if ":" in app_target and not os.path.exists(app_target):
        parts = app_target.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isidentifier():
            file_part, var_name = parts[0], parts[1]

    abs_path = os.path.abspath(file_part)
    if os.path.isfile(abs_path):
        app_dir = os.path.dirname(abs_path)
        if app_dir not in sys.path:
            sys.path.insert(0, app_dir)

        spec = importlib.util.spec_from_file_location("pysecure_target_app", abs_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module specification from '{file_part}'")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        if var_name:
            app_obj = getattr(mod, var_name, None)
        else:
            app_obj = getattr(mod, "app", None) or getattr(mod, "application", None)

        if app_obj is None:
            raise AttributeError(f"Could not find 'app' or 'application' object in '{file_part}'.")
        return app_obj

    # Try standard Python module import
    try:
        mod = importlib.import_module(file_part)
        return getattr(mod, var_name or "app", None) or getattr(mod, "application", None)
    except Exception as e:
        raise ImportError(f"Cannot load target '{app_target}': {e}")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    # Convenience: if user runs `pysecure app.py` instead of `pysecure scan app.py`
    if argv and not argv[0].startswith("-") and argv[0] not in ("scan", "help"):
        argv = ["scan"] + argv

    parser = argparse.ArgumentParser(
        prog="pysecure",
        description="PySecure: Embedded SAST + DAST Security Scanner for Python Web Applications.",
    )
    parser.add_argument("--version", action="version", version=f"pysecure {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a Flask or Django application")
    scan_parser.add_argument(
        "target",
        help="Path to Python file or module (e.g. app.py, app.py:app, or wsgi:application)"
    )
    scan_parser.add_argument(
        "--static-only",
        action="store_true",
        help="Run static code analysis (SAST) only; disable dynamic payload testing."
    )
    scan_parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save report to JSON file."
    )
    scan_parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save report to HTML file."
    )
    scan_parser.add_argument(
        "--pdf",
        metavar="FILE",
        help="Save report to PDF file with Gemini AI security insights."
    )
    scan_parser.add_argument(
        "--api-key",
        metavar="KEY",
        help="Session-only Gemini API key for AI executive report (not saved to disk)."
    )
    scan_parser.add_argument(
        "--no-ai-prompt",
        action="store_true",
        help="Do not prompt for Gemini API key interactively in the terminal."
    )

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0 if len(argv) == 0 else 1)

    if args.command == "scan":
        print(f"\n[*] Loading application from: {args.target}...")
        try:
            app = load_app_from_path(args.target)
        except Exception as e:
            print(f"[!] Error loading target app: {e}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Starting PySecure scan (SAST + {'DAST' if not args.static_only else 'Static Only'})...")
        result = scan_app(app, dynamic=not args.static_only)

        # Print terminal output
        print_report(result)

        # Optional outputs
        if args.json:
            save_json_report(result, args.json)
        if args.html:
            save_html_report(result, args.html)
        if args.pdf:
            save_pdf_report(
                result,
                args.pdf,
                api_key=args.api_key,
                prompt_for_key=not args.no_ai_prompt
            )
            print(f"   [*] PDF report saved to: {args.pdf}")

        # Exit code reflects findings: return 1 if critical issues found
        sys.exit(1 if result.has_critical else 0)


if __name__ == "__main__":
    main()

