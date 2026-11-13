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
        vars_in_value = self._extract_vars(node.value)
        has_user_input = any(
            self.analyzer._is_user_input_name(v) or v in self.tainted_paths
            for v in vars_in_value
        )
        is_sanitized = False
        if isinstance(node.value, ast.Call):
            call_func = self.analyzer._extract_var_name(node.value.func)
            if "secure_filename" in call_func:
                is_sanitized = True

        if has_user_input and not is_sanitized:
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
            # f-string path
            if isinstance(path_arg, ast.JoinedStr):
                for val in path_arg.values:
                    if isinstance(val, ast.FormattedValue):
                        var_name = self.analyzer._extract_var_name(val.value)
                        if var_name and (self.analyzer._is_user_input_name(var_name) or var_name in self.tainted_paths):
                            self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), func_name, var_name)
                            break
            # string concat path
            elif isinstance(path_arg, ast.BinOp) and isinstance(path_arg.op, ast.Add):
                vars_in_binop = self._extract_vars(path_arg)
                for v in vars_in_binop:
                    if self.analyzer._is_user_input_name(v) or v in self.tainted_paths:
                        self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), func_name, v)
                        break
            # direct user input or tainted variable
            elif isinstance(path_arg, ast.Name):
                if self.analyzer._is_user_input_name(path_arg.id) or path_arg.id in self.tainted_paths:
                    self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), func_name, path_arg.id)
            # call to path constructor or join, e.g. os.path.join(DIR, filename)
            elif isinstance(path_arg, ast.Call):
                call_func = self.analyzer._extract_var_name(path_arg.func)
                if "secure_filename" not in call_func:
                    vars_in_call = self._extract_vars(path_arg)
                    for v in vars_in_call:
                        if self.analyzer._is_user_input_name(v) or v in self.tainted_paths:
                            self.analyzer._flag(node.lineno, self.analyzer._get_line_text(node.lineno), func_name, v)
                            break

        self.generic_visit(node)

    def _extract_vars(self, node: ast.expr) -> List[str]:
        vars_found = []
        if isinstance(node, ast.BinOp):
            vars_found.extend(self._extract_vars(node.left))
            vars_found.extend(self._extract_vars(node.right))
        elif isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    name = self.analyzer._extract_var_name(val.value)
                    if name:
                        vars_found.append(name)
        elif isinstance(node, ast.Call):
            for arg in node.args:
                vars_found.extend(self._extract_vars(arg))
            for kw in node.keywords:
                vars_found.extend(self._extract_vars(kw.value))
        elif isinstance(node, ast.Name):
            vars_found.append(node.id)
        return vars_found
