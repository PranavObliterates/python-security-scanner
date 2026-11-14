from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from security_scanner.dynamic.remote import ScopeError, scan_remote_url, _validate_private_url
from pysecure.cli import main


class _DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if query.get("pysecure_probe") == ["pysecure-canary-9f31"]:
            body = f"<html><body>{query['pysecure_probe'][0]}</body></html>".encode()
        else:
            body = (
                '<html><a href="/about">About</a>'
                '<script>window.addEventListener("DOMContentLoaded",()=>{'
                'document.getElementById("out").innerHTML=new URLSearchParams(location.search).get("pysecure_browser")})'
                '</script><div id="out"></div>'
                '<form action="/search" method="get"><input name="q"></form></html>'
                if urlparse(self.path).path == "/" else (
                    '<html><body><a href="/deep">Deep</a></body></html>'
                    if urlparse(self.path).path == "/about"
                    else "<html><body>Deep</body></html>"
                )
            ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body_length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(body_length)
        if urlparse(self.path).path == "/login":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.send_header("Set-Cookie", "auth=ok; Path=/; HttpOnly; SameSite=Lax")
            self.end_headers()
            return
        self.send_error(404)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def local_http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DemoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_remote_crawler_discovers_pages_and_forms(local_http_server):
    result = scan_remote_url(
        local_http_server,
        max_pages=5,
        max_depth=2,
        max_requests=10,
        delay=0.1,
    )
    assert result.routes_scanned == 3
    assert len(result.forms_discovered) == 1
    assert result.forms_discovered[0]["fields"] == ["q"]


def test_remote_scanner_rejects_public_ip_targets():
    with pytest.raises(ScopeError):
        _validate_private_url("http://8.8.8.8/")


def test_remote_scanner_rejects_non_http_targets():
    with pytest.raises(ScopeError):
        _validate_private_url("file:///etc/passwd")


def test_remote_scanner_rejects_dns_hostnames():
    with pytest.raises(ScopeError):
        _validate_private_url("https://example.com/")


def test_remote_active_probe_uses_non_executable_canary(local_http_server):
    result = scan_remote_url(
        local_http_server,
        max_pages=1,
        max_depth=0,
        max_requests=4,
        delay=0.1,
        active=True,
    )
    reflected = [finding for finding in result.findings if finding.rule_id == "PYSEC-DAST-001"]
    assert len(reflected) == 1
    assert "potential" in reflected[0].explanation


def test_scan_url_cli_runs_bounded_local_scan(local_http_server, capsys):
    with pytest.raises(SystemExit) as exc:
        main([
            "scan-url", local_http_server,
            "--max-pages", "1",
            "--max-requests", "3",
            "--delay", "0.1",
        ])
    assert exc.value.code == 0
    assert "Forms: 1" in capsys.readouterr().out


def test_optional_browser_finds_rendered_pages_and_dom_html_sink(local_http_server):
    pytest.importorskip("playwright")
    result = scan_remote_url(
        local_http_server,
        max_pages=3,
        max_depth=2,
        max_requests=20,
        delay=0.1,
        browser=True,
    )
    if result.browser_pages_tested == 0:
        assert any("Browser scan failed" in warning for warning in result.warnings)
        return
    assert result.browser_pages_tested == 3
    assert any(f.rule_id == "PYSEC-DAST-003" for f in result.findings)


def test_env_backed_auth_workflow_runs_explicit_authorization_check(
    tmp_path, monkeypatch
):
    class AuthHandler(_DemoHandler):
        def do_GET(self):
            if urlparse(self.path).path == "/admin":
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            super().do_GET()

    server = ThreadingHTTPServer(("127.0.0.1", 0), AuthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "auth.json"
    config.write_text(
        '{"login":{"method":"POST","path":"/login","form":{"username":{"env":"PYSECURE_TEST_USER"}}},'
        '"authorization":[{"path":"/admin","unauthenticated_statuses":[401,403],'
        '"authenticated_statuses":[200]}]}',
        encoding="utf-8",
    )
    monkeypatch.setenv("PYSECURE_TEST_USER", "demo-user")
    try:
        result = scan_remote_url(
            f"http://127.0.0.1:{server.server_port}/",
            max_pages=1,
            max_requests=10,
            delay=0.1,
            auth_config_path=str(config),
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert any(f.rule_id == "PYSEC-AUTHZ-001" for f in result.findings)
