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
        vars_in_value = self._extract_vars(node.value)
        has_user_input = any(
            self.analyzer._is_user_input_name(v) or v in self.tainted_urls
            for v in vars_in_value
        )
        if has_user_input:
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

        if func_name in ("redirect", "HttpResponseRedirect"):
            if node.args:
                target_arg = node.args[0]
                if isinstance(target_arg, ast.Name):
                    if self.analyzer._is_user_input_name(target_arg.id) or target_arg.id in self.tainted_urls:
                        self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), target_arg.id)
                elif isinstance(target_arg, ast.Call) and isinstance(target_arg.func, (ast.Attribute, ast.Name)):
                    call_name = self.analyzer._extract_var_name(target_arg.func)
                    if any(src in call_name for src in ("request.args", "request.GET", "request.POST", "request.values", "request.form")):
                        self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), call_name)
                elif isinstance(target_arg, ast.JoinedStr):
                    for val in target_arg.values:
                        if isinstance(val, ast.FormattedValue):
                            var_name = self.analyzer._extract_var_name(val.value)
                            if var_name and (self.analyzer._is_user_input_name(var_name) or var_name in self.tainted_urls):
                                self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), var_name)
                                break
                elif isinstance(target_arg, ast.BinOp):
                    vars_in_binop = self._extract_vars(target_arg)
                    for v in vars_in_binop:
                        if self.analyzer._is_user_input_name(v) or v in self.tainted_urls:
                            self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), v)
                            break

        self.generic_visit(node)

    def _extract_vars(self, node: ast.expr) -> List[str]:
        vars_found = []
        if isinstance(node, ast.BinOp):
            vars_found.extend(self._extract_vars(node.left))
            vars_found.extend(self._extract_vars(node.right))
        elif isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    name = self.analyzer._extract_var_name(val.value)
                    if name:
                        vars_found.append(name)
        elif isinstance(node, ast.Call):
            for arg in node.args:
                vars_found.extend(self._extract_vars(arg))
            for kw in node.keywords:
                vars_found.extend(self._extract_vars(kw.value))
        elif isinstance(node, ast.Name):
            vars_found.append(node.id)
        return vars_found
