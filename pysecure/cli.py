"""Command Line Interface for PySecure."""
import os
import sys
import re
import argparse
import importlib.util
from security_scanner.core.scanner import scan_app
from security_scanner.reporting.console import print_report
from security_scanner.reporting.json_report import save_json_report
from security_scanner.reporting.html_report import save_html_report
from security_scanner.reporting.pdf_report import save_pdf_report
from security_scanner.reporting.sarif_report import save_sarif_report
from security_scanner import __version__


def load_app_from_path(app_target: str):
    """Load Flask or Django app object from file path, directory, or module string.

    Supports:
        - "path/to/project_dir" (finds app.py, wsgi.py, manage.py)
        - "path/to/app.py" (looks for 'app' or 'application')
        - "path/to/app.py:app"
        - "C:\\path\\to\\app.py:app"
        - "path/to/manage.py" (initializes Django and gets WSGI application)
        - "my_module.wsgi:application"
    """
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    file_part, var_name = app_target, None
    if ":" in app_target and not os.path.exists(app_target):
        parts = app_target.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isidentifier():
            file_part, var_name = parts[0], parts[1]

    abs_path = os.path.abspath(file_part)

    # If target is a directory, resolve to an entry point file
    if os.path.isdir(abs_path):
        candidates = ["app.py", "wsgi.py", "manage.py", "main.py", "application.py"]
        found_target = None
        for cand in candidates:
            cand_path = os.path.join(abs_path, cand)
            if os.path.isfile(cand_path):
                found_target = cand_path
                break
        if not found_target:
            for root, dirs, files in os.walk(abs_path):
                dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "__pycache__", "node_modules")]
                for cand in candidates:
                    if cand in files:
                        found_target = os.path.join(root, cand)
                        break
                if found_target:
                    break
        if found_target:
            abs_path = found_target
            file_part = found_target
        else:
            raise FileNotFoundError(
                f"Directory '{app_target}' contains no recognizable entry point (app.py, wsgi.py, manage.py)."
            )

    if os.path.isfile(abs_path):
        app_dir = os.path.dirname(abs_path)
        parent_dir = os.path.dirname(app_dir)
        grandparent_dir = os.path.dirname(parent_dir)
        for p in [app_dir, parent_dir, grandparent_dir]:
            if p and os.path.isdir(p) and p not in sys.path:
                sys.path.insert(0, p)

        spec = importlib.util.spec_from_file_location("pysecure_target_app", abs_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module specification from '{file_part}'")
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            # Check if this is a Django file requiring settings
            if "DJANGO_SETTINGS_MODULE" in str(e) or not os.environ.get("DJANGO_SETTINGS_MODULE"):
                try:
                    with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    m = re.search(r"['\"]DJANGO_SETTINGS_MODULE['\"]\s*,\s*['\"]([^'\"]+)['\"]", content)
                    if m:
                        os.environ.setdefault("DJANGO_SETTINGS_MODULE", m.group(1))
                        import django
                        django.setup()
                        from django.core.wsgi import get_wsgi_application
                        return get_wsgi_application()
                except Exception:
                    pass
            raise

        if var_name:
            app_obj = getattr(mod, var_name, None)
        else:
            app_obj = getattr(mod, "app", None) or getattr(mod, "application", None)

        if app_obj is None:
            # Check if this is a Django manage.py or contains DJANGO_SETTINGS_MODULE
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                m = re.search(r"['\"]DJANGO_SETTINGS_MODULE['\"]\s*,\s*['\"]([^'\"]+)['\"]", content)
                if m:
                    settings_mod = m.group(1)
                    os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_mod)
                    import django
                    django.setup()
                    from django.core.wsgi import get_wsgi_application
                    return get_wsgi_application()
            except Exception:
                pass

        if app_obj is None:
            raise AttributeError(f"Could not find 'app' or 'application' object in '{file_part}'.")
        # Handle factory functions like create_app()
        if callable(app_obj) and not hasattr(app_obj, "route") and not hasattr(app_obj, "wsgi_app"):
            try:
                app_obj = app_obj()
            except Exception:
                pass
        return app_obj

    # Try standard Python module import
    try:
        mod = importlib.import_module(file_part)
        app_obj = getattr(mod, var_name or "app", None) or getattr(mod, "application", None)
        if callable(app_obj) and not hasattr(app_obj, "route") and not hasattr(app_obj, "wsgi_app"):
            try:
                app_obj = app_obj()
            except Exception:
                pass
        if app_obj is None:
            raise AttributeError(f"Could not find 'app' or 'application' object in module '{file_part}'.")
        return app_obj
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
        "--sarif",
        metavar="FILE",
        help="Save report to OASIS SARIF v2.1.0 format (for GitHub Code Scanning)."
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
        if args.sarif:
            save_sarif_report(result, args.sarif)
            print(f"   [*] SARIF report saved to: {args.sarif}")
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

