"""Main scanner orchestrator — ties everything together."""
import time
from typing import List
from ..models.finding import Finding, Severity, VulnerabilityType
from ..models.scan_result import ScanResult
from .route_discovery import discover_flask_routes, discover_django_routes
from ..analyzers.sql_injection import SQLInjectionAnalyzer
from ..analyzers.xss import XSSAnalyzer
from ..analyzers.secrets import SecretsAnalyzer
from ..analyzers.ssti import SSTIAnalyzer
from ..analyzers.deserialization import DeserializationAnalyzer
from ..analyzers.config import check_flask_config, check_django_config
from ..dynamic.payload_tester import run_dast_tests, run_django_dast_tests
from ..dynamic.response_analyzer import check_security_headers, check_cookie_security


def scan_app(app, dynamic: bool = True, framework: str = "auto") -> ScanResult:
    """
    Main entry point: scan a web application for security vulnerabilities.

    This is the primary public API of the security_scanner library.

    Usage:
        from security_scanner import scan_app
        result = scan_app(app)

    Args:
        app: The Flask/Django application object.
             For Django, pass the result of django.core.wsgi.get_wsgi_application()
             or the Django settings module.
        dynamic: Whether to run dynamic payload testing (DAST).
        framework: "flask", "django", or "auto" (detect automatically).

    Returns:
        ScanResult with all findings.
    """
    start_time = time.time()

    # Detect framework
    detected_framework = _detect_framework(app) if framework == "auto" else framework
    result = ScanResult(app_name=_get_app_name(app))

    # Step 1: Discover routes
    if detected_framework == "flask":
        routes = discover_flask_routes(app)
    elif detected_framework == "django":
        routes = discover_django_routes()
    else:
        raise NotImplementedError(f"Framework '{detected_framework}' not yet supported.")

    result.routes_scanned = len(routes)

    # Step 2: Static Analysis (SAST) on each route
    for route in routes:
        if route.source_code:
            analyzers = [
                SQLInjectionAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                XSSAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                SecretsAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                SSTIAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                DeserializationAnalyzer(route.path, route.file_path or "unknown", route.source_code),
            ]
            for analyzer in analyzers:
                result.findings.extend(analyzer.analyze())

    # Step 3: Global configuration checks
    if detected_framework == "flask":
        result.findings.extend(check_flask_config(app))
    elif detected_framework == "django":
        result.findings.extend(check_django_config())

    # Step 4: Dynamic Analysis (DAST)
    if dynamic:
        try:
            if detected_framework == "flask":
                dast_findings = run_dast_tests(app, routes)
                result.findings.extend(dast_findings)

                # Also check security headers and cookies
                client = app.test_client()
                for route in routes[:3]:
                    try:
                        clean_path = route.path.split("<")[0].rstrip("/") or "/"
                        response = client.get(clean_path)
                        headers = dict(response.headers)
                        result.findings.extend(
                            check_security_headers(headers, route.path)
                        )
                        result.findings.extend(
                            check_cookie_security(headers, route.path)
                        )
                        break
                    except Exception:
                        continue

            elif detected_framework == "django":
                dast_findings = run_django_dast_tests(routes)
                result.findings.extend(dast_findings)

                # Check security headers via Django test client
                from django.test import Client as DjangoClient
                client = DjangoClient()
                for route in routes[:3]:
                    try:
                        clean_path = route.path.split("<")[0].rstrip("/") or "/"
                        response = client.get(clean_path)
                        headers = dict(response.items()) if hasattr(response, 'items') else {}
                        result.findings.extend(
                            check_security_headers(headers, route.path)
                        )
                        break
                    except Exception:
                        continue

        except Exception:
            # DAST errors shouldn't crash the scan
            pass

    # Step 5: Deduplicate
    result.findings = _deduplicate(result.findings)

    result.scan_duration_seconds = time.time() - start_time
    return result


def _detect_framework(app) -> str:
    """Auto-detect which web framework the app uses."""
    module = type(app).__module__.lower()
    class_name = type(app).__name__.lower()

    if "flask" in module:
        return "flask"
    elif "django" in module or "wsgihandler" in class_name:
        return "django"
    elif "fastapi" in module or "starlette" in module:
        return "fastapi"
    else:
        raise ValueError(
            f"Cannot detect framework from {type(app).__name__} ({module}). "
            f"Currently supported: Flask, Django."
        )


def _get_app_name(app) -> str:
    """Get a readable name for the application."""
    # Flask
    if hasattr(app, "import_name"):
        return app.import_name
    # Django
    if hasattr(app, "name"):
        return app.name
    module = type(app).__module__
    return module if module != "builtins" else "unknown_app"


def _deduplicate(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings (same type + endpoint + line + source)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.vuln_type, f.endpoint, f.line, f.code_snippet, f.source)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
