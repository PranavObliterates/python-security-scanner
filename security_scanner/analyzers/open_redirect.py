"""Open Redirect detection via AST analysis — finds unvalidated user-controlled redirects."""
import ast
from typing import List
from .base import BaseAnalyzer
from ..models.finding import Finding, Severity, VulnerabilityType


class OpenRedirectAnalyzer(BaseAnalyzer):
    """Detects Unvalidated Redirects and Forwards (OWASP A01:2021)."""

    def analyze(self) -> List[Finding]:
        visitor = _OpenRedirectVisitor(self)
        visitor.visit(self._tree)
        return self.findings

    def _flag(self, line: int, code: str, variable: str) -> None:
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.OPEN_REDIRECT,
            severity=Severity.MEDIUM,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"Application redirects users to a target specified by user input '{variable}' "
                f"without validation. An attacker can construct links redirecting users to malicious "
                f"phishing domains while appearing legitimate."
            ),
            fix_recommendation=(
                "Validate redirect targets against an allowed whitelist or verify that "
                "the URL is relative (e.g., using urllib.parse.urlparse and checking netloc is empty)."
            ),
            fix_before=f'redirect({variable})',
            fix_after=(
                f'from urllib.parse import urlparse\n'
                f'if not urlparse({variable}).netloc:\n'
                f'    return redirect({variable})\n'
                f'return redirect("/")'
            ),
            reference="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            source="SAST",
        ))


class _OpenRedirectVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: OpenRedirectAnalyzer):
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
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect"):
            target_arg = None
            if node.args:
                target_arg = node.args[0]
            else:
                for kw in node.keywords:
                    if kw.arg in ("to", "location", "redirect_to", "url"):
                        target_arg = kw.value
                        break
                if not target_arg and node.keywords:
                    target_arg = node.keywords[0].value

            if target_arg and self.analyzer._is_node_tainted(target_arg, self.tainted_urls):
                var_name = self.analyzer._extract_var_name(target_arg) or "url"
                self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), var_name)

        self.generic_visit(node)
