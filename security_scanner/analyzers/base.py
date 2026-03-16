"""Base class for all AST-based security analyzers."""
import ast
import textwrap
from abc import ABC, abstractmethod
from typing import List
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

        Uses a simple heuristic: looks for assignments like
        `name = request.args.get(...)` in the source code.
        """
        for pattern in USER_INPUT_SOURCES:
            # Check if  variable = request.args.get(...)  or similar
            if f"{name} = {pattern}" in self.source_code or \
               f"{name} = request." in self.source_code:
                return True
        return False

    def _extract_var_name(self, node: ast.expr) -> str:
        """Extract variable name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # e.g., request.args → return "request.args"
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""
