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
        self.static_vars = set()
        self.dynamic_vars = set()
        self.string_template_imported = False

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "string":
            for alias in node.names:
                if alias.name == "Template":
                    self.string_template_imported = True
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments to distinguish static constants from dynamic expressions."""
        is_constant = isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
        for target in node.targets:
            var_name = self.analyzer._extract_var_name(target)
            if var_name:
                if is_constant:
                    self.static_vars.add(var_name)
                else:
                    self.dynamic_vars.add(var_name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Flag usage of render_template_string when the argument is dynamic."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "string":
            # string.Template is safe standard library formatting, not SSTI
            self.generic_visit(node)
            return

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        else:
            func_name = ""

        if self.string_template_imported and func_name == "Template":
            self.generic_visit(node)
            return

        if func_name in ("render_template_string", "Template"):
            arg = None
            if node.args:
                arg = node.args[0]
            else:
                for kw in node.keywords:
                    if kw.arg in ("source", "template_string", "template"):
                        arg = kw.value
                        break
                if not arg and node.keywords:
                    arg = node.keywords[0].value

            if arg is not None:
                is_dynamic = False
                if isinstance(arg, (ast.JoinedStr, ast.BinOp, ast.Call, ast.Subscript)):
                    is_dynamic = True
                elif isinstance(arg, ast.Name):
                    var_name = arg.id
                    if var_name in self.static_vars and var_name not in self.dynamic_vars:
                        is_dynamic = False
                    else:
                        is_dynamic = True

                if is_dynamic:
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
