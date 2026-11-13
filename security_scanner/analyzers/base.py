"""Base class for all AST-based security analyzers."""
import ast
import textwrap
from abc import ABC, abstractmethod
from typing import List, Set, Optional, Any
from ..models.finding import Finding


# Common patterns that indicate user input in Flask and Django
USER_INPUT_SOURCES = [
    # Flask patterns
    "request.args", "request.form", "request.json",
    "request.values", "request.data", "request.get_json",
    "request.cookies", "request.headers",
    # Django patterns
    "request.POST", "request.GET", "request.FILES",
    "request.body", "request.META", "request.COOKIES",
    "request.query_params",
]


class BaseAnalyzer(ABC):
    """Base class that all rule analyzers inherit from."""

    def __init__(self, endpoint: str, file_path: str, source_code: str):
        self.endpoint = endpoint
        self.file_path = file_path
        self.source_code = textwrap.dedent(source_code)
        self.findings: List[Finding] = []
        self._tree: ast.Module = ast.parse(self.source_code)

    @abstractmethod
    def analyze(self) -> List[Finding]:
        """Run analysis and return findings."""
        ...

    def _get_line_text(self, lineno: int) -> str:
        """Get the source code text at a given line number."""
        lines = self.source_code.splitlines()
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1].strip()
        return ""

    def _is_user_input_name(self, name: str) -> bool:
        """Check if a variable name likely comes from user input.

        Uses flexible regex/patterns to detect assignments like
        `name = request.args.get(...)` even with irregular spacing.
        """
        import re
        if not name:
            return False
        if name.startswith("request."):
            return True

        escaped = re.escape(name)
        if re.search(rf"\b{escaped}\s*=\s*.*request\.", self.source_code):
            return True

        for pattern in USER_INPUT_SOURCES:
            if re.search(rf"\b{escaped}\s*=\s*.*{re.escape(pattern)}", self.source_code):
                return True
        return False

    def _extract_var_name(self, node: ast.AST) -> str:
        """Extract variable name or dotted attribute chain from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        elif isinstance(node, ast.Call):
            return self._extract_var_name(node.func)
        elif isinstance(node, ast.Subscript):
            return self._extract_var_name(node.value)
        return ""

    def _is_direct_user_input(self, node: ast.AST) -> bool:
        """Check if an AST node directly represents user input."""
        if isinstance(node, ast.Attribute):
            full_name = self._extract_var_name(node)
            if any(full_name.startswith(src) for src in USER_INPUT_SOURCES):
                return True
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                return True
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ("get", "getlist", "get_json") and self._is_direct_user_input(node.func.value):
                    return True
                full_func = self._extract_var_name(node.func)
                if any(full_func.startswith(src) for src in USER_INPUT_SOURCES) or full_func.startswith("request."):
                    return True
        elif isinstance(node, ast.Subscript):
            if self._is_direct_user_input(node.value):
                return True
        elif isinstance(node, ast.Name):
            if node.id == "request" or self._is_user_input_name(node.id):
                return True
        return False

    def _is_node_tainted(self, node: ast.AST, tainted_vars: Optional[Set[str]] = None) -> bool:
        """Check if an AST expression derives from untrusted user input."""
        if node is None:
            return False
        tainted = tainted_vars if tainted_vars is not None else set()

        if self._is_direct_user_input(node):
            return True

        if isinstance(node, ast.Name):
            return node.id in tainted or self._is_user_input_name(node.id)

        if isinstance(node, ast.Attribute):
            return self._is_direct_user_input(node) or self._is_node_tainted(node.value, tainted)

        if isinstance(node, ast.Subscript):
            return self._is_direct_user_input(node) or self._is_node_tainted(node.value, tainted)

        if isinstance(node, ast.Call):
            if self._is_direct_user_input(node):
                return True
            call_name = self._extract_var_name(node.func)
            # Respect sanitization functions and safe internal URL/type generators
            if any(san in call_name for san in ("secure_filename", "escape", "int", "float", "url_for", "reverse", "reverse_lazy", "resolve_url")):
                return False
            # Method call on tainted object, e.g. user_input.strip()
            if isinstance(node.func, ast.Attribute) and self._is_node_tainted(node.func.value, tainted):
                return True
            # Arguments passed to functions (e.g. os.path.join(DIR, user_input))
            if any(self._is_node_tainted(arg, tainted) for arg in node.args):
                return True
            if any(self._is_node_tainted(kw.value, tainted) for kw in node.keywords):
                return True

        if isinstance(node, ast.JoinedStr):
            return any(
                isinstance(v, ast.FormattedValue) and self._is_node_tainted(v.value, tainted)
                for v in node.values
            )

        if isinstance(node, ast.BinOp):
            return self._is_node_tainted(node.left, tainted) or self._is_node_tainted(node.right, tainted)

        if isinstance(node, ast.Dict):
            return any(v is not None and self._is_node_tainted(v, tainted) for v in node.values)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_node_tainted(elt, tainted) for elt in node.elts)

        if isinstance(node, ast.UnaryOp):
            return self._is_node_tainted(node.operand, tainted)

        return False

