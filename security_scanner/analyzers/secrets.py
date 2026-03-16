"""Secrets detection via AST analysis — finds hardcoded passwords, API keys, tokens."""
import ast
import re
from typing import List
from .base import BaseAnalyzer
from ..models.finding import Finding, Severity, VulnerabilityType

# Patterns that suggest a variable holds a secret
SECRET_VAR_PATTERNS = re.compile(
    r"(password|passwd|secret|api_key|apikey|token|auth|credential|private_key|"
    r"access_key|secret_key|db_password|database_url|connection_string)",
    re.IGNORECASE,
)

# Common weak/placeholder values
WEAK_VALUES = {
    "password", "password123", "123456", "admin", "test", "secret",
    "changeme", "default", "root", "qwerty", "letmein", "abc123",
    "password1", "12345678", "welcome", "monkey", "dragon",
}


class SecretsAnalyzer(BaseAnalyzer):
    """Detects hardcoded secrets, passwords, and API keys in source code.

    Looks for:
    - Variables with secret-like names assigned string literals
    - Common weak/placeholder passwords
    """

    def analyze(self) -> List[Finding]:
        visitor = _SecretsVisitor(self)
        visitor.visit(self._tree)
        return self.findings

    def _flag(self, line: int, code: str, var_name: str, value: str) -> None:
        is_weak = value.lower() in WEAK_VALUES
        severity = Severity.HIGH if is_weak else Severity.MEDIUM

        self.findings.append(Finding(
            vuln_type=VulnerabilityType.HARDCODED_SECRET,
            severity=severity,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"Variable '{var_name}' appears to contain a hardcoded secret "
                f"(value: '{value[:20]}...' ). Hardcoded credentials can be "
                f"extracted from source code, version control history, or "
                f"compiled binaries. If this is a real credential, it should "
                f"be moved to environment variables or a secrets manager."
            ),
            fix_recommendation="Use environment variables instead of hardcoded secrets.",
            fix_before=f'{var_name} = "{value}"',
            fix_after=f'import os\n{var_name} = os.environ.get("{var_name.upper()}")',
            reference="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
            source="SAST",
        ))


class _SecretsVisitor(ast.NodeVisitor):
    """AST visitor that finds hardcoded secret assignments."""

    def __init__(self, analyzer: SecretsAnalyzer):
        self.analyzer = analyzer

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect assignments like: password = 'secret123' """
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            if len(value) < 3:
                # Too short to be a meaningful secret
                self.generic_visit(node)
                return

            for target in node.targets:
                var_name = self.analyzer._extract_var_name(target)
                if var_name and SECRET_VAR_PATTERNS.search(var_name):
                    self.analyzer._flag(
                        line=node.lineno,
                        code=self.analyzer._get_line_text(node.lineno),
                        var_name=var_name,
                        value=value,
                    )

        self.generic_visit(node)
