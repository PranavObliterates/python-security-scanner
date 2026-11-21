"""Server-Side Request Forgery (SSRF) detection via AST analysis."""
import ast
from typing import List
from .base import BaseAnalyzer
from ..models.finding import Finding, Severity, VulnerabilityType

HTTP_CLIENT_MODULES = {"requests", "httpx", "urllib", "urllib3", "http", "aiohttp", "session", "client"}
HTTP_METHODS = {"get", "post", "put", "delete", "request", "patch", "head"}

HTTP_CALLS = {
    ("requests", "get"),
    ("requests", "post"),
    ("requests", "put"),
    ("requests", "delete"),
    ("requests", "request"),
    ("requests", "patch"),
    ("requests", "head"),
    ("httpx", "get"),
    ("httpx", "post"),
    ("httpx", "put"),
    ("httpx", "delete"),
    ("httpx", "request"),
    ("urllib", "request"),
    ("urllib.request", "urlopen"),
}


class SSRFAnalyzer(BaseAnalyzer):
    """Detects Server-Side Request Forgery risks (OWASP A10:2021)."""

    def analyze(self) -> List[Finding]:
        visitor = _SSRFVisitor(self)
        visitor.visit(self._tree)
        return self.findings

    def _flag(self, line: int, code: str, func_name: str, variable: str) -> None:
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.SSRF,
            severity=Severity.HIGH,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"HTTP request via '{func_name}' appears to fetch a URL controlled by "
                f"user input ('{variable}'). An attacker can trigger requests to internal "
                f"services, cloud metadata endpoints (e.g. 169.254.169.254), or loopback "
                f"addresses to bypass network firewalls and access private infrastructure."
            ),
            fix_recommendation=(
                "Validate URLs against a strict whitelist of allowed domains and protocols. "
                "Disallow private IP ranges (RFC 1918) and link-local cloud metadata IPs."
            ),
            fix_before=f'{func_name}({variable})',
            fix_after=(
                f'from urllib.parse import urlparse\n'
                f'allowed_hosts = {{"api.example.com"}}\n'
                f'if urlparse({variable}).hostname in allowed_hosts:\n'
                f'    {func_name}({variable})'
            ),
            reference="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            source="SAST",
        ))


class _SSRFVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: SSRFAnalyzer):
        self.analyzer = analyzer
        self.tainted_urls = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track URL variables assigned from user input."""
        if self.analyzer._is_node_tainted(node.value, self.tainted_urls):
            for target in node.targets:
                var_name = self.analyzer._extract_var_name(target)
                if var_name:
                    self.tainted_urls.add(var_name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        is_http_call = False

        if isinstance(node.func, ast.Attribute):
            full_attr = self.analyzer._extract_var_name(node.func)
            if isinstance(node.func.value, ast.Name):
                pair = (node.func.value.id, node.func.attr)
                caller = node.func.value.id.lower()
                attr = node.func.attr.lower()
                if pair in HTTP_CALLS or (caller in HTTP_CLIENT_MODULES and attr in HTTP_METHODS):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
                    is_http_call = True
                elif attr == "urlopen":
                    func_name = f"{node.func.value.id}.{node.func.attr}"
                    is_http_call = True
            elif isinstance(node.func.value, ast.Attribute):
                # urllib.request.urlopen
                if node.func.attr == "urlopen" or "urllib" in full_attr:
                    func_name = full_attr or f"{node.func.attr}"
                    is_http_call = True
        elif isinstance(node.func, ast.Name) and node.func.id == "urlopen":
            func_name = "urlopen"
            is_http_call = True

        if is_http_call:
            url_arg = None
            if node.args:
                url_arg = node.args[0]
            else:
                for kw in node.keywords:
                    if kw.arg in ("url", "req", "target") or not kw.arg:
                        url_arg = kw.value
                        break
                if not url_arg and node.keywords:
                    url_arg = node.keywords[0].value

            if url_arg and self.analyzer._is_node_tainted(url_arg, self.tainted_urls):
                var_name = self.analyzer._extract_var_name(url_arg) or "url"
                self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), func_name, var_name)

        self.generic_visit(node)
