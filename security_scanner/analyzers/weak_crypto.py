"""Weak Cryptography & Broken Hashing detection via AST analysis."""
import ast
from typing import List
from .base import BaseAnalyzer
from ..models.finding import Finding, Severity, VulnerabilityType


class WeakCryptoAnalyzer(BaseAnalyzer):
    """Detects usage of broken hash algorithms (MD5, SHA-1) and weak crypto functions."""

    def analyze(self) -> List[Finding]:
        visitor = _WeakCryptoVisitor(self)
        visitor.visit(self._tree)
        return self.findings

    def _flag(self, line: int, code: str, algo: str) -> None:
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.WEAK_CRYPTO,
            severity=Severity.MEDIUM,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"Broken cryptographic hashing function '{algo}' detected. "
                f"MD5 and SHA-1 suffer from known collision attacks and are vulnerable "
                f"to rapid brute-forcing. They should never be used for password hashing, "
                f"integrity verification, or digital signatures."
            ),
            fix_recommendation=(
                "Use modern, salted hashing algorithms such as bcrypt, argon2, or "
                "hashlib.sha256/sha512 for general integrity."
            ),
            fix_before=f'hashlib.{algo}(data.encode()).hexdigest()',
            fix_after='from werkzeug.security import generate_password_hash\ngenerate_password_hash(data)',
            reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            source="SAST",
        ))


class _WeakCryptoVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: WeakCryptoAnalyzer):
        self.analyzer = analyzer

    def visit_Call(self, node: ast.Call) -> None:
        # Check hashlib.md5(), hashlib.sha1(), hashlib.new('md5'), hashlib.new('sha1')
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashlib":
                attr_lower = node.func.attr.lower()
                if attr_lower in ("md5", "sha1", "sha", "md4"):
                    self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), attr_lower)
                elif attr_lower == "new" and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and str(first_arg.value).lower() in ("md5", "sha1", "sha", "md4"):
                        self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), str(first_arg.value).lower())
        # Check md5() or sha1() direct call
        elif isinstance(node.func, ast.Name) and node.func.id.lower() in ("md5", "sha1", "sha", "md4"):
            self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), node.func.id.lower())

        self.generic_visit(node)
