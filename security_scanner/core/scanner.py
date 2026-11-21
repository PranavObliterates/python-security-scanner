"""Main scanner orchestrator — ties everything together."""
import logging
import time
import re
from typing import List
from ..models.finding import Finding, Severity, VulnerabilityType
from ..models.scan_result import ScanResult
from .route_discovery import discover_flask_routes, discover_django_routes, discover_fastapi_routes
from ..analyzers.a03_sql_injection import SQLInjectionAnalyzer
from ..analyzers.a03_cross_site_scripting import XSSAnalyzer
from ..analyzers.a02_hardcoded_secrets import SecretsAnalyzer
from ..analyzers.a03_server_side_template_injection import SSTIAnalyzer
from ..analyzers.a08_insecure_deserialization import DeserializationAnalyzer
from ..analyzers.a03_command_injection import CommandInjectionAnalyzer
from ..analyzers.a01_path_traversal import PathTraversalAnalyzer
from ..analyzers.a10_server_side_request_forgery import SSRFAnalyzer
from ..analyzers.a02_weak_cryptography import WeakCryptoAnalyzer
from ..analyzers.a01_open_redirect import OpenRedirectAnalyzer
from ..analyzers.a07_broken_authentication import JWTAnalyzer
from ..analyzers.a05_security_misconfiguration import check_flask_config, check_django_config, check_fastapi_config
from ..dynamic.payload_tester import run_dast_tests, run_django_dast_tests, run_fastapi_dast_tests
from ..dynamic.response_analyzer import (
    check_security_headers,
    check_cookie_security,
    check_response_hardening,
)
from ..analyzers.a06_vulnerable_components import scan_dependency_manifests, scan_osv_advisories

logger = logging.getLogger(__name__)


def scan_app(
    app,
    dynamic: bool = True,
    framework: str = "auto",
    active_dast: bool = False,
    dependency_root: str = "",
    osv_lookup: bool = False,
) -> ScanResult:
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
        dynamic: Whether to run passive dynamic checks (DAST). No exploit
            payloads are generated or sent.
        framework: "flask", "django", or "auto" (detect automatically).
        active_dast: Enable harmless canary probes in addition to passive checks.
        dependency_root: Optional project path to audit dependency manifests.
        osv_lookup: Query OSV.dev for pinned dependency advisories.

    Returns:
        ScanResult with all findings.
    """
    start_time = time.perf_counter()

    # Detect framework
    detected_framework = _detect_framework(app) if framework == "auto" else framework
    result = ScanResult(app_name=_get_app_name(app))

    # Step 1: Discover routes
    if detected_framework == "flask":
        routes = discover_flask_routes(app)
    elif detected_framework == "django":
        routes = discover_django_routes()
    elif detected_framework == "fastapi":
        routes = discover_fastapi_routes(app)
    else:
        raise NotImplementedError(f"Framework '{detected_framework}' not yet supported.")

    result.routes_scanned = len(routes)
    logger.debug("Discovered %d %s routes for %s", len(routes), detected_framework, result.app_name)
    if dependency_root:
        result.findings.extend(scan_dependency_manifests(dependency_root))
        if osv_lookup:
            osv_findings, osv_warnings = scan_osv_advisories(dependency_root)
            result.findings.extend(osv_findings)
            result.warnings.extend(osv_warnings)

    # Step 2: Static Analysis (SAST) on each route
    for route in routes:
        if route.source_code:
            # Skip third-party framework/library code inside site-packages / dist-packages
            if route.file_path and ("site-packages" in route.file_path or "dist-packages" in route.file_path):
                continue

            route_started = time.perf_counter()
            analyzers = [
                SQLInjectionAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                XSSAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                SecretsAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                SSTIAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                DeserializationAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                CommandInjectionAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                PathTraversalAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                SSRFAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                WeakCryptoAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                OpenRedirectAnalyzer(route.path, route.file_path or "unknown", route.source_code),
                JWTAnalyzer(route.path, route.file_path or "unknown", route.source_code),
            ]
            for analyzer in analyzers:
                result.findings.extend(analyzer.analyze())
            logger.debug(
                "Analyzed route %s with %d rules in %.3fs",
                route.path,
                len(analyzers),
                time.perf_counter() - route_started,
            )

    # Step 3: Global configuration checks
    if detected_framework == "flask":
        result.findings.extend(check_flask_config(app))
    elif detected_framework == "django":
        result.findings.extend(check_django_config())
    elif detected_framework == "fastapi":
        result.findings.extend(check_fastapi_config(app))

    # Step 4: Dynamic Analysis (DAST)
    dast_started = time.perf_counter()
    if dynamic:
        try:
            if detected_framework == "flask":
                dast_findings = run_dast_tests(app, routes, active=active_dast)
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
                        result.findings.extend(
                            check_response_hardening(headers, route.path)
                        )
                        result.routes_tested += 1
                        break
                    except (KeyError, RuntimeError, TypeError, ValueError) as exc:
                        result.warnings.append(f"DAST response check skipped for {route.path}: {exc}")
                        continue

            elif detected_framework == "django":
                dast_findings = run_django_dast_tests(routes, active=active_dast)
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
                        result.findings.extend(check_response_hardening(headers, route.path))
                        result.routes_tested += 1
                        break
                    except (KeyError, RuntimeError, TypeError, ValueError) as exc:
                        result.warnings.append(f"DAST response check skipped for {route.path}: {exc}")
                        continue

            elif detected_framework == "fastapi":
                dast_findings = run_fastapi_dast_tests(app, routes, active=active_dast)
                result.findings.extend(dast_findings)

                try:
                    from fastapi.testclient import TestClient
                    client = TestClient(app)
                    for route in routes[:3]:
                        try:
                            clean_path = re.sub(r"\{(\w+)\}", "1", route.path)
                            response = client.get(clean_path)
                            headers = dict(response.headers)
                            result.findings.extend(
                                check_security_headers(headers, route.path)
                            )
                            result.findings.extend(
                                check_cookie_security(headers, route.path)
                            )
                            result.findings.extend(check_response_hardening(headers, route.path))
                            result.routes_tested += 1
                            break
                        except (KeyError, RuntimeError, TypeError, ValueError) as exc:
                            result.warnings.append(f"DAST response check skipped for {route.path}: {exc}")
                            continue
                except (ImportError, RuntimeError, TypeError) as exc:
                    result.warnings.append(f"FastAPI DAST unavailable: {exc}")

        except (ImportError, RuntimeError, TypeError, ValueError) as exc:
            result.warnings.append(f"DAST checks incomplete: {exc}")
            logger.debug("DAST checks incomplete", exc_info=True)
    if dynamic:
        logger.debug("Completed DAST checks in %.3fs", time.perf_counter() - dast_started)

    # Step 5: Deduplicate
    result.findings = _deduplicate(result.findings)

    result.scan_duration_seconds = time.perf_counter() - start_time
    logger.debug(
        "Scan completed: %d findings, %d/%d routes tested, %.3fs",
        len(result.findings),
        result.routes_tested,
        result.routes_scanned,
        result.scan_duration_seconds,
    )
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
            f"Currently supported: Flask, Django, FastAPI."
        )


def _get_app_name(app) -> str:
    """Get a readable name for the application."""
    # FastAPI / Starlette
    if hasattr(app, "title") and isinstance(app.title, str):
        return app.title
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
