import ast
from .base import BaseAnalyzer
from ..models.finding import Finding, VulnerabilityType, Severity

from typing import List

class DeserializationAnalyzer(BaseAnalyzer):
    """Detects Insecure Deserialization via pickle or yaml."""
    
    def analyze(self) -> List[Finding]:
        visitor = _DeserializationVisitor(self)
        visitor.visit(self._tree)
        return self.findings

class _DeserializationVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: DeserializationAnalyzer):
        self.analyzer = analyzer
        
    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                
                if module_name == "pickle" and func_name == "loads":
                    self.analyzer.findings.append(Finding(
                        vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION,
                        severity=Severity.CRITICAL,
                        endpoint=self.analyzer.endpoint,
                        file=self.analyzer.file_path,
                        line=node.lineno,
                        code_snippet=self.analyzer._get_line_text(node.lineno),
                        explanation="Usage of pickle.loads() detected. This function is inherently unsafe and can execute arbitrary code during deserialization.",
                        fix_recommendation="Use safer serialization formats like JSON (json.loads()) instead of pickle for untrusted data.",
                        fix_before="pickle.loads(user_data)",
                        fix_after="json.loads(user_data)",
                        reference="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
                    ))
                elif module_name == "yaml" and func_name == "load":
                    self.analyzer.findings.append(Finding(
                        vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION,
                        severity=Severity.CRITICAL,
                        endpoint=self.analyzer.endpoint,
                        file=self.analyzer.file_path,
                        line=node.lineno,
                        code_snippet=self.analyzer._get_line_text(node.lineno),
                        explanation="Usage of yaml.load() detected. This function is unsafe and can execute arbitrary code during deserialization.",
                        fix_recommendation="Use yaml.safe_load() instead.",
                        fix_before="yaml.load(user_data, Loader=yaml.Loader)",
                        fix_after="yaml.safe_load(user_data)",
                        reference="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
                    ))
        self.generic_visit(node)
