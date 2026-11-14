"""JWT (JSON Web Token) Security Analyzer — OWASP A07:2021 Identification & Authentication Failures.

Detects:
1. Disabling JWT signature verification (verify=False or verify_signature=False).
2. Allowing the 'none' algorithm (insecure unverified tokens).
3. Hardcoded secret keys in jwt.encode / jwt.decode.
"""
import ast
from typing import List
from .base import BaseAnalyzer
from ..models.finding import Finding, Severity, VulnerabilityType


class JWTAnalyzer(BaseAnalyzer):
    """Detects insecure JWT usage in endpoint handlers and view functions."""

    def analyze(self) -> List[Finding]:
        visitor = _JWTVisitor(self)
        visitor.visit(self._tree)
        return self.findings

    def _flag_signature_disabled(self, line: int, code: str) -> None:
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.JWT_VULNERABILITY,
            severity=Severity.CRITICAL,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                "JWT signature verification is explicitly disabled (verify=False or "
                "options={'verify_signature': False}). Any attacker can forge arbitrary "
                "tokens with custom user claims or admin privileges without possessing the secret key."
            ),
            fix_recommendation="Always verify JWT signatures using a secure secret key or public certificate.",
            fix_before="jwt.decode(token, key, options={'verify_signature': False})",
            fix_after="jwt.decode(token, key, algorithms=['HS256'])",
            reference="https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures/",
            source="SAST",
        ))

    def _flag_none_algorithm(self, line: int, code: str) -> None:
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.JWT_VULNERABILITY,
            severity=Severity.CRITICAL,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                "JWT decoding explicitly permits the 'none' algorithm. An attacker can construct "
                "an unsigned token with algorithm 'none' that the server will accept as authentic."
            ),
            fix_recommendation="Disallow the 'none' algorithm. Explicitly specify strong algorithms like ['HS256', 'RS256'].",
            fix_before="jwt.decode(token, key, algorithms=['none'])",
            fix_after="jwt.decode(token, key, algorithms=['HS256'])",
            reference="https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
            source="SAST",
        ))

    def _flag_hardcoded_jwt_secret(self, line: int, code: str, secret_val: str) -> None:
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.HARDCODED_SECRET,
            severity=Severity.HIGH,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"Hardcoded secret string ('{secret_val[:12]}...') is used for JWT signing or verification. "
                f"An attacker with access to the source code can forge valid JWT authentication tokens."
            ),
            fix_recommendation="Retrieve JWT secret keys from environment variables.",
            fix_before=f'jwt.encode(payload, "{secret_val[:10]}...", algorithm="HS256")',
            fix_after='import os\nsecret_key = os.environ.get("JWT_SECRET_KEY")\njwt.encode(payload, secret_key, algorithm="HS256")',
            reference="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            source="SAST",
        ))


class _JWTVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: JWTAnalyzer):
        self.analyzer = analyzer

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self.analyzer._extract_var_name(node.func)
        if func_name in ("jwt.decode", "jose.jwt.decode", "decode"):
            # Check 1: verify=False or verify_signature=False
            for kw in node.keywords:
                if kw.arg in ("verify", "verify_signature") and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.analyzer._flag_signature_disabled(node.lineno, self.analyzer._get_line_text(node.lineno))
                    return

                if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                    for k, v in zip(kw.value.keys, kw.value.values):
                        if isinstance(k, ast.Constant) and k.value in ("verify_signature", "verify_signature_status"):
                            if isinstance(v, ast.Constant) and v.value is False:
                                self.analyzer._flag_signature_disabled(node.lineno, self.analyzer._get_line_text(node.lineno))
                                return

                # Check 2: algorithms containing "none"
                if kw.arg in ("algorithms", "algorithm"):
                    if isinstance(kw.value, ast.Constant) and str(kw.value.value).lower() == "none":
                        self.analyzer._flag_none_algorithm(node.lineno, self.analyzer._get_line_text(node.lineno))
                        return
                    elif isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and str(elt.value).lower() == "none":
                                self.analyzer._flag_none_algorithm(node.lineno, self.analyzer._get_line_text(node.lineno))
                                return

            # Check 3: hardcoded key in args (key is arg 1: jwt.decode(token, key, ...))
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                val = node.args[1].value
                if len(val) > 3:
                    self.analyzer._flag_hardcoded_jwt_secret(node.lineno, self.analyzer._get_line_text(node.lineno), val)

        elif func_name in ("jwt.encode", "jose.jwt.encode", "encode"):
            # Check hardcoded key in args (key is arg 1: jwt.encode(payload, key, ...))
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                val = node.args[1].value
                if len(val) > 3:
                    self.analyzer._flag_hardcoded_jwt_secret(node.lineno, self.analyzer._get_line_text(node.lineno), val)
            for kw in node.keywords:
                if kw.arg in ("key", "secret") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    val = kw.value.value
                    if len(val) > 3:
                        self.analyzer._flag_hardcoded_jwt_secret(node.lineno, self.analyzer._get_line_text(node.lineno), val)

        self.generic_visit(node)
