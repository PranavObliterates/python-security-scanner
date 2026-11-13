"""Path Traversal detection via AST analysis — finds unsafe file opening and path usage."""
import ast
from typing import List
from .base import BaseAnalyzer
from ..models.finding import Finding, Severity, VulnerabilityType

FILE_ACCESS_FUNCS = {"open", "send_file", "send_from_directory"}
FILE_ACCESS_MODULES = {"os", "io", "flask", "django", "pathlib", "tarfile", "zipfile", "shutil"}
FILE_ACCESS_ATTRS = {
    ("os", "remove"), ("os", "unlink"), ("shutil", "rmtree"),
    ("os", "open"), ("io", "open"),
    ("flask", "send_file"), ("flask", "send_from_directory"),
}


class PathTraversalAnalyzer(BaseAnalyzer):
    """Detects path traversal risks where user input is used in file operations."""

    def analyze(self) -> List[Finding]:
        visitor = _PathTraversalVisitor(self)
        visitor.visit(self._tree)
        return self.findings

    def _flag(self, line: int, code: str, func_name: str, variable: str) -> None:
        self.findings.append(Finding(
            vuln_type=VulnerabilityType.PATH_TRAVERSAL,
            severity=Severity.HIGH,
            endpoint=self.endpoint,
            file=self.file_path,
            line=line,
            code_snippet=code,
            explanation=(
                f"File operation '{func_name}' appears to use user input '{variable}' "
                f"directly in a file path without sanitization. An attacker could supply "
                f"relative paths like `../../etc/passwd` to view, overwrite, or delete "
                f"sensitive files outside the designated directory."
            ),
            fix_recommendation=(
                "Sanitize filenames using `werkzeug.utils.secure_filename()` or verify that "
                "the canonical resolved path is strictly within the allowed base directory."
            ),
            fix_before=f'{func_name}(f"uploads/{{{variable}}}")',
            fix_after=f'from werkzeug.utils import secure_filename\nsafe_name = secure_filename({variable})\n{func_name}(os.path.join(SAFE_DIR, safe_name))',
            reference="https://owasp.org/www-community/attacks/Path_Traversal",
            source="SAST",
        ))


class _PathTraversalVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: PathTraversalAnalyzer):
        self.analyzer = analyzer
        self.tainted_paths = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track path variables assigned from user input or os.path.join."""
        is_sanitized = False
        if isinstance(node.value, ast.Call):
            call_func = self.analyzer._extract_var_name(node.value.func)
            if "secure_filename" in call_func:
                is_sanitized = True

        if not is_sanitized and self.analyzer._is_node_tainted(node.value, self.tainted_paths):
            for target in node.targets:
                var_name = self.analyzer._extract_var_name(target)
                if var_name:
                    self.tainted_paths.add(var_name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        is_target = False

        if isinstance(node.func, ast.Name) and node.func.id in FILE_ACCESS_FUNCS:
            func_name = node.func.id
            is_target = True
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            pair = (node.func.value.id, node.func.attr)
            if pair in FILE_ACCESS_ATTRS or (node.func.value.id in FILE_ACCESS_MODULES and node.func.attr in FILE_ACCESS_FUNCS):
                func_name = f"{node.func.value.id}.{node.func.attr}"
                is_target = True

        if is_target and node.args:
            path_arg = node.args[0]
            is_sanitized = False
            if isinstance(path_arg, ast.Call):
                call_func = self.analyzer._extract_var_name(path_arg.func)
                if "secure_filename" in call_func:
                    is_sanitized = True

            if not is_sanitized and self.analyzer._is_node_tainted(path_arg, self.tainted_paths):
                var_name = self.analyzer._extract_var_name(path_arg) or "input"
                self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), func_name, var_name)

        self.generic_visit(node)
