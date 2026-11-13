"""Command Injection detection via AST analysis — finds os.system, subprocess calls with untrusted input."""
import ast
from typing import List
from .base import BaseAnalyzer
from ..models.finding import Finding, Severity, VulnerabilityType

DANGEROUS_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
}


class CommandInjectionAnalyzer(BaseAnalyzer):
    """Detects OS command injection vulnerabilities in view functions."""

    def analyze(self) -> List[Finding]:
        visitor = _CommandInjectionVisitor(self)
        visitor.visit(self._tree)
        return self.findings

    def _flag(self, line: int, code: str, func_name: str, variable: str = "") -> None:
        detail = f" with variable '{variable}'" if variable else ""
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"Call to '{func_name}' appears to execute shell commands{detail} "
                f"derived from untrusted user input without sanitization. An attacker "
                f"can use shell metacharacters (e.g., ';', '|', '&') to execute arbitrary "
                f"system commands on the host operating system."
            ),
            fix_recommendation=(
                "Avoid passing user input to shell commands. If execution is necessary, "
                "pass argument lists with shell=False and validate input against a strict whitelist."
            ),
            fix_before=f'{func_name}(f"cmd {{{variable or "input"}}}")',
            fix_after=f'import subprocess, shlex\nsubprocess.run(["cmd", {variable or "input"}], shell=False, check=True)',
            reference="https://owasp.org/www-community/attacks/Command_Injection",
            source="SAST",
        ))


class _CommandInjectionVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: CommandInjectionAnalyzer):
        self.analyzer = analyzer
        self.tainted_cmds = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track command strings constructed with user input."""
        if self.analyzer._is_node_tainted(node.value, self.tainted_cmds):
            for target in node.targets:
                var_name = self.analyzer._extract_var_name(target)
                if var_name:
                    self.tainted_cmds.add(var_name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_pair = self._resolve_call(node.func)
        if call_pair in DANGEROUS_CALLS or (isinstance(node.func, ast.Name) and node.func.id in ("system", "popen")):
            func_name = f"{call_pair[0]}.{call_pair[1]}" if call_pair else getattr(node.func, "id", "command")
            if node.args:
                cmd_arg = node.args[0]
                if self.analyzer._is_node_tainted(cmd_arg, self.tainted_cmds):
                    var_name = self.analyzer._extract_var_name(cmd_arg) or "input"
                    self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), func_name, var_name)

        self.generic_visit(node)

    def _resolve_call(self, func_node: ast.expr):
        if isinstance(func_node, ast.Attribute) and isinstance(func_node.value, ast.Name):
            return (func_node.value.id, func_node.attr)
        return None
