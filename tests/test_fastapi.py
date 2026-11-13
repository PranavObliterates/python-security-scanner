"""Tests for FastAPI application scanning."""
import pytest
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from security_scanner.core.scanner import scan_app
from security_scanner.core.route_discovery import discover_fastapi_routes
from security_scanner.analyzers.config import check_fastapi_config
from security_scanner.models.finding import VulnerabilityType, Severity


def create_vuln_fastapi_app():
    app = FastAPI(title="VulnFastAPIApp", debug=True)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/search")
    def search_users(q: str):
        import sqlite3
        conn = sqlite3.connect("test.db")
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM users WHERE name = '{q}'")
        return {"result": cur.fetchall()}

    @app.get("/download")
    def download_file(file: str):
        with open(file, "r") as f:
            content = f.read()
        return {"data": content}

    @app.get("/fetch")
    def fetch_url(url: str):
        import requests
        resp = requests.get(url)
        return {"status": resp.status_code}

    @app.get("/exec")
    def run_cmd(cmd: str):
        import os
        os.system(cmd)
        return {"status": "executed"}

    return app


def test_discover_fastapi_routes():
    app = create_vuln_fastapi_app()
    routes = discover_fastapi_routes(app)
    paths = [r.path for r in routes]
    assert "/search" in paths
    assert "/download" in paths
    assert "/fetch" in paths
    assert "/exec" in paths
    assert "/docs" not in paths
    assert "/openapi.json" not in paths


def test_check_fastapi_config():
    app = create_vuln_fastapi_app()
    findings = check_fastapi_config(app)
    types = [f.vuln_type for f in findings]
    assert VulnerabilityType.DEBUG_MODE in types
    assert VulnerabilityType.CORS_MISCONFIGURATION in types


def test_scan_fastapi_app():
    app = create_vuln_fastapi_app()
    result = scan_app(app, dynamic=False)

    assert result.routes_scanned >= 4
    vuln_types = [f.vuln_type for f in result.findings]
    assert VulnerabilityType.SQL_INJECTION in vuln_types
    assert VulnerabilityType.PATH_TRAVERSAL in vuln_types
    assert VulnerabilityType.SSRF in vuln_types
    assert VulnerabilityType.COMMAND_INJECTION in vuln_types
    assert VulnerabilityType.DEBUG_MODE in vuln_types
    assert VulnerabilityType.CORS_MISCONFIGURATION in vuln_types
