"""Command Line Interface for PySecure."""
import logging
import os
import sys
import re
import argparse
import importlib.util
import requests
from security_scanner.core.scanner import scan_app
from security_scanner.models.finding import Severity
from security_scanner.reporting.console import print_report
from security_scanner.reporting.json_report import save_json_report
from security_scanner.reporting.html_report import save_html_report
from security_scanner.reporting.sarif_report import save_sarif_report
from security_scanner.dynamic.remote import ScopeError, scan_remote_url
from security_scanner.analyzers.dependencies import scan_dependency_manifests, scan_osv_advisories
from security_scanner import __version__

logger = logging.getLogger(__name__)


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def load_cli_config(target: str = "") -> dict:
    """Load configuration from .pysecurerc or pyproject.toml."""
    target_dir = target if os.path.isdir(target) else os.path.dirname(os.path.abspath(target)) if os.path.isfile(target) else "."
    search_dirs = [os.getcwd()]
    if target_dir and target_dir not in search_dirs:
        search_dirs.append(target_dir)

    for d in search_dirs:
        rc_path = os.path.join(d, ".pysecurerc")
        if os.path.isfile(rc_path):
            try:
                import json
                with open(rc_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                logger.debug("Could not read PySecure config at %s", rc_path, exc_info=True)
                pass

        pyproj_path = os.path.join(d, "pyproject.toml")
        if os.path.isfile(pyproj_path):
            try:
                try:
                    import tomllib
                except ImportError:
                    import tomli as tomllib
                with open(pyproj_path, "rb") as f:
                    data = tomllib.load(f)
                    cfg = data.get("tool", {}).get("pysecure")
                    if cfg and isinstance(cfg, dict):
                        return cfg
            except Exception:
                logger.debug("Could not read PySecure settings from %s", pyproj_path, exc_info=True)
                pass
    return {}


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
        previous_module = sys.modules.get(spec.name)
        sys.modules[spec.name] = mod
        try:
            try:
                logger.debug("Loading application module from %s", abs_path)
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
                        logger.debug("Django application fallback failed for %s", abs_path, exc_info=True)
                raise
        finally:
            if previous_module is None:
                sys.modules.pop(spec.name, None)
            else:
                sys.modules[spec.name] = previous_module

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
            app_obj = app_obj()
        return app_obj

    # If not a file/dir and input contains path separators or file extension, fail fast
    if not os.path.exists(abs_path) and ("/" in file_part or "\\" in file_part or file_part.endswith(".py")):
        raise FileNotFoundError(f"Target path does not exist: '{app_target}'")

    # Try standard Python module import
    try:
        mod = importlib.import_module(file_part)
        app_obj = getattr(mod, var_name or "app", None) or getattr(mod, "application", None)
        if callable(app_obj) and not hasattr(app_obj, "route") and not hasattr(app_obj, "wsgi_app"):
            app_obj = app_obj()
        if app_obj is None:
            raise AttributeError(f"Could not find 'app' or 'application' object in module '{file_part}'.")
        return app_obj
    except Exception as e:
        raise ImportError(f"Cannot load target '{app_target}': {e}")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    # Convenience: if user runs `pysecure app.py` instead of `pysecure scan app.py`
    if argv and not argv[0].startswith("-") and argv[0] not in ("scan", "scan-url", "help"):
        argv = ["scan"] + argv

    parser = argparse.ArgumentParser(
        prog="pysecure",
        description="PySecure: Embedded SAST + DAST Security Scanner for Python Web Applications.",
    )
    parser.add_argument("--version", action="version", version=f"pysecure {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a Flask, Django, or FastAPI application")
    scan_parser.add_argument(
        "target",
        help="Path to Python file or module (e.g. app.py, app.py:app, or wsgi:application)"
    )
    scan_parser.add_argument(
        "--static-only",
        action="store_true",
        help="Run source analysis only; disable passive baseline requests."
    )
    scan_parser.add_argument(
        "--active-dast",
        action="store_true",
        help="Send harmless canary probes through the local framework test client (opt-in).",
    )
    scan_parser.add_argument(
        "--dependencies",
        action="store_true",
        help="Audit dependency manifests for unpinned requirements.",
    )
    scan_parser.add_argument(
        "--osv",
        action="store_true",
        help="Query OSV.dev for known advisories affecting pinned dependencies (network required).",
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
    scan_parser.add_argument(
        "--severity",
        type=lambda s: s.upper(),
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Minimum severity level to include in findings and reports."
    )
    scan_parser.add_argument(
        "--fail-on",
        type=lambda s: s.upper(),
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Exit with code 1 if issues at or above this severity are found (default: CRITICAL)."
    )
    scan_parser.add_argument(
        "--ignore",
        metavar="RULES",
        help="Comma-separated list of vulnerability types or rule names to ignore (e.g. DEBUG_MODE,WEAK_CRYPTO)."
    )
    scan_parser.add_argument(
        "--debug",
        action="store_true",
        help="Log detailed scan stages and show tracebacks for failures.",
    )

    url_parser = subparsers.add_parser(
        "scan-url",
        help="Crawl and passively scan a localhost/private-network web application.",
    )
    url_parser.add_argument("url", help="HTTP(S) URL on localhost or a private IP address.")
    url_parser.add_argument("--max-pages", type=int, default=50, help="Maximum HTML pages to crawl (default: 50).")
    url_parser.add_argument("--max-depth", type=int, default=3, help="Maximum link depth (default: 3).")
    url_parser.add_argument("--max-requests", type=int, default=150, help="Hard request budget (default: 150).")
    url_parser.add_argument("--delay", type=float, default=0.25, help="Minimum seconds between requests (default: 0.25).")
    url_parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds (default: 5).")
    url_parser.add_argument("--active", action="store_true", help="Send harmless reflection canaries to HTML pages.")
    url_parser.add_argument("--auth-config", help="JSON login and explicit authorization rules; secrets must use environment references.")
    url_parser.add_argument("--browser", action="store_true", help="Use optional Playwright to crawl rendered JavaScript pages.")
    url_parser.add_argument("--dependencies", metavar="DIR", help="Also audit dependency manifests under a directory.")
    url_parser.add_argument("--osv", action="store_true", help="Query OSV.dev for pinned dependency advisories.")
    url_parser.add_argument("--json", metavar="FILE", help="Save JSON report.")
    url_parser.add_argument("--html", metavar="FILE", help="Save HTML report.")
    url_parser.add_argument("--pdf", metavar="FILE", help="Save PDF report.")
    url_parser.add_argument("--sarif", metavar="FILE", help="Save SARIF report.")
    url_parser.add_argument(
        "--debug",
        action="store_true",
        help="Log detailed crawl requests and show tracebacks for failures.",
    )

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0 if len(argv) == 0 else 1)

    logging.basicConfig(
        level=logging.WARNING,
        format="[%(levelname)s] %(name)s: %(message)s",
    )
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logging.getLogger("security_scanner").setLevel(logging.DEBUG)

    if args.command == "scan":
        if args.osv and not args.dependencies:
            parser.error("--osv requires --dependencies.")
        if args.active_dast and args.static_only:
            parser.error("--active-dast cannot be used with --static-only.")
        print(f"\n[*] Loading application from: {args.target}...")
        try:
            app = load_app_from_path(args.target)
        except Exception as e:
            if args.debug:
                logger.exception("Application loading failed")
            print(f"[!] Error loading target app: {e}", file=sys.stderr)
            sys.exit(1)

        mode = "DAST + active canaries" if args.active_dast else ("DAST" if not args.static_only else "Static Only")
        print(f"[*] Starting PySecure scan (SAST + {mode})...")
        try:
            result = scan_app(
                app,
                dynamic=not args.static_only,
                active_dast=args.active_dast,
                dependency_root=(
                    os.path.abspath(args.target)
                    if args.dependencies and os.path.isdir(args.target)
                    else os.path.dirname(os.path.abspath(args.target))
                    if args.dependencies else ""
                ),
                osv_lookup=args.osv,
            )
        except Exception as e:
            if args.debug:
                logger.exception("Scan failed")
            print(f"[!] Scan failed: {e}", file=sys.stderr)
            sys.exit(1)

        # Load file-based config defaults (.pysecurerc or pyproject.toml [tool.pysecure])
        cfg = load_cli_config(args.target)

        # Apply config defaults if CLI arguments were not provided
        severity_filter = args.severity or cfg.get("severity")
        fail_on_threshold = args.fail_on or cfg.get("fail_on", "CRITICAL")
        ignore_rules = args.ignore or cfg.get("ignore", [])
        if isinstance(ignore_rules, list):
            ignore_rules = ",".join(ignore_rules)

        # Filter findings by ignore list
        if ignore_rules:
            ignore_set = {x.strip().upper() for x in ignore_rules.split(",") if x.strip()}
            result.findings = [f for f in result.findings if f.vuln_type.value.upper() not in ignore_set]

        # Filter findings by minimum severity
        if severity_filter:
            min_sev = SEVERITY_ORDER.get(str(severity_filter).upper(), 0)
            result.findings = [f for f in result.findings if SEVERITY_ORDER.get(f.severity.value, 0) >= min_sev]

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
            from security_scanner import save_pdf_report
            try:
                save_pdf_report(
                    result,
                    args.pdf,
                    api_key=args.api_key,
                    prompt_for_key=not args.no_ai_prompt
                )
            except ImportError as exc:
                print(f"[!] PDF report unavailable: {exc}", file=sys.stderr)
                sys.exit(2)
            print(f"   [*] PDF report saved to: {args.pdf}")

        # Exit code reflects findings based on --fail-on threshold (defaults to CRITICAL)
        threshold_val = SEVERITY_ORDER.get(str(fail_on_threshold).upper(), 4)
        has_violating_issues = any(
            SEVERITY_ORDER.get(f.severity.value, 0) >= threshold_val
            for f in result.findings
        )
        sys.exit(1 if has_violating_issues else 0)

    if args.command == "scan-url":
        if args.max_pages < 1 or args.max_depth < 0 or args.max_requests < 1:
            parser.error("max-pages and max-requests must be positive; max-depth cannot be negative.")
        if args.delay < 0.1 or args.timeout <= 0 or args.timeout > 30:
            parser.error("delay must be at least 0.1 seconds and timeout must be between 0 and 30 seconds.")
        if args.osv and not args.dependencies:
            parser.error("--osv requires --dependencies DIR.")
        try:
            result = scan_remote_url(
                args.url,
                max_pages=args.max_pages,
                max_depth=args.max_depth,
                max_requests=args.max_requests,
                delay=args.delay,
                timeout=args.timeout,
                active=args.active,
                auth_config_path=args.auth_config,
                browser=args.browser,
            )
            if args.dependencies:
                result.findings.extend(scan_dependency_manifests(args.dependencies))
                if args.osv:
                    osv_findings, osv_warnings = scan_osv_advisories(args.dependencies)
                    result.findings.extend(osv_findings)
                    result.warnings.extend(osv_warnings)
        except (ScopeError, OSError, ValueError, requests.RequestException) as exc:
            if args.debug:
                logger.exception("Remote scan failed")
            print(f"[!] Remote scan failed: {exc}", file=sys.stderr)
            sys.exit(2)
        except Exception as exc:
            if args.debug:
                logger.exception("Remote scan failed unexpectedly")
            print(f"[!] Remote scan failed: {exc}", file=sys.stderr)
            sys.exit(2)
        print_report(result)
        if args.json:
            save_json_report(result, args.json)
        if args.html:
            save_html_report(result, args.html)
        if args.sarif:
            save_sarif_report(result, args.sarif)
        if args.pdf:
            from security_scanner import save_pdf_report
            try:
                save_pdf_report(result, args.pdf, prompt_for_key=False)
            except ImportError as exc:
                print(f"[!] PDF report unavailable: {exc}", file=sys.stderr)
                sys.exit(2)
        sys.exit(1 if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings) else 0)


if __name__ == "__main__":
    main()
