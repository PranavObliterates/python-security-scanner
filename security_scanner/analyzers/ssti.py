import ast
from .base import BaseAnalyzer
from ..models.finding import Finding, VulnerabilityType, Severity

from typing import List

class SSTIAnalyzer(BaseAnalyzer):
    """Detects Server-Side Template Injection (SSTI)."""
    
    def analyze(self) -> List[Finding]:
        visitor = _SSTIVisitor(self)
        visitor.visit(self._tree)
        return self.findings

class _SSTIVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: SSTIAnalyzer):
        self.analyzer = analyzer
        
    def visit_Call(self, node: ast.Call) -> None:
        """Flag usage of render_template_string when the argument is dynamic."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        else:
            func_name = ""

        if func_name in ("render_template_string", "Template"):
            # Check if the first argument is dynamic (JoinedStr = f-string, Call = .format, BinOp = +)
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.Call, ast.BinOp, ast.Name)):
                self.analyzer.findings.append(Finding(
                    vuln_type=VulnerabilityType.SSTI,
                    severity=Severity.CRITICAL,
                    endpoint=self.analyzer.endpoint,
                    file=self.analyzer.file_path,
                    line=node.lineno,
                    code_snippet=self.analyzer._get_line_text(node.lineno),
                    explanation="Variable appears to come from user input and is interpolated directly into a template string, enabling Server-Side Template Injection.",
                    fix_recommendation="Use render_template() with a static template file instead of rendering strings dynamically. If you must use strings, ensure input is strictly validated or sandboxed.",
                    fix_before="render_template_string(f'Hello {user_input}')",
                    fix_after="render_template('hello.html', name=user_input)",
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html"
                ))
        self.generic_visit(node)
