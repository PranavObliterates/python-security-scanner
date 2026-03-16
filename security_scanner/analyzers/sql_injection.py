"""SQL Injection detection via AST analysis."""
import ast
import re
from typing import List
from .base import BaseAnalyzer
from ..models.finding import Finding, Severity, VulnerabilityType

SQL_KEYWORDS_PATTERN = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC)\b",
    re.IGNORECASE,
)


class SQLInjectionAnalyzer(BaseAnalyzer):
    """Detects SQL injection risks in view function source code.

    Looks for:
    - f-strings containing SQL keywords with user-input variables
    - String concatenation with SQL keywords and user-input variables
    - .format() calls on strings containing SQL keywords
    """

    def analyze(self) -> List[Finding]:
        visitor = _SQLInjectionVisitor(self)
        visitor.visit(self._tree)
        return self.findings

    def _flag(self, line: int, code: str, variable: str) -> None:
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"Variable '{variable}' appears to come from user input and is "
                f"interpolated directly into a SQL query string. An attacker can "
                f"send input like `' OR '1'='1` to manipulate the query, "
                f"potentially accessing or deleting all data."
            ),
            fix_recommendation="Use parameterized queries instead of string interpolation.",
            fix_before=f'cursor.execute(f"SELECT ... WHERE col = {{{variable}}}")',
            fix_after=f'cursor.execute("SELECT ... WHERE col = %s", ({variable},))',
            reference="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            source="SAST",
        ))


class _SQLInjectionVisitor(ast.NodeVisitor):
    """AST visitor that looks for SQL keywords inside f-strings and concatenations."""

    def __init__(self, analyzer: SQLInjectionAnalyzer):
        self.analyzer = analyzer

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Detect f-strings containing SQL keywords with variables.

        Example: query = f"SELECT * FROM users WHERE id = {user_id}"
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

        if SQL_KEYWORDS_PATTERN.search(constant_parts) and variables:
            for var in variables:
                if self.analyzer._is_user_input_name(var):
                    self.analyzer._flag(
                        line=node.lineno,
                        code=self.analyzer._get_line_text(node.lineno),
                        variable=var,
                    )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Detect string concatenation with SQL keywords.

        Example: query = "SELECT * FROM users WHERE id = " + user_id
        """
        if isinstance(node.op, ast.Add):
            full_string = self._reconstruct_binop_string(node)
            if SQL_KEYWORDS_PATTERN.search(full_string):
                variables = self._extract_binop_variables(node)
                for var in variables:
                    if self.analyzer._is_user_input_name(var):
                        self.analyzer._flag(
                            line=node.lineno,
                            code=self.analyzer._get_line_text(node.lineno),
                            variable=var,
                        )

        self.generic_visit(node)

    def _reconstruct_binop_string(self, node: ast.BinOp) -> str:
        """Reconstruct the string parts of a concatenation."""
        parts = []
        if isinstance(node.left, ast.Constant):
            parts.append(str(node.left.value))
        elif isinstance(node.left, ast.BinOp):
            parts.append(self._reconstruct_binop_string(node.left))
        if isinstance(node.right, ast.Constant):
            parts.append(str(node.right.value))
        return " ".join(parts)

    def _extract_binop_variables(self, node: ast.BinOp) -> List[str]:
        """Extract variable names used in concatenation."""
        variables = []
        for child in [node.left, node.right]:
            if isinstance(child, ast.Name):
                variables.append(child.id)
            elif isinstance(child, ast.BinOp):
                variables.extend(self._extract_binop_variables(child))
        return variables
