# Contributing to PySecure

Thank you for contributing to PySecure! As an open-source security tool, high code quality, low false-positive rates, and rigorous AST testing are our highest priorities.

## Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/PranavObliterates/python-security-scanner.git
   cd python-security-scanner
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   pip install pytest fastapi httpx
   ```

3. Install pre-commit hooks:
   ```bash
   pip install pre-commit
   pre-commit install
   ```

## Adding New Analyzers

When adding a new OWASP analyzer:
1. Inherit from `security_scanner.analyzers.base.BaseAnalyzer`.
2. Implement `analyze(self) -> List[Finding]`.
3. Use `self._is_node_tainted(node, tainted_vars)` to track untrusted user input from request sources.
4. Add unit tests in `tests/` covering both **True Positives** (should trigger) and **True Negatives** (safe patterns that should NOT trigger).
5. Map the vulnerability to the proper OWASP Top 10 category in `security_scanner/models/finding.py`.

## Running Verification

Ensure all tests and evaluation benchmarks pass with 100% precision:
```bash
pytest
python evaluate_flask.py
python evaluate_django.py
python evaluate_fastapi.py
python run_test_suite.py
```

## Pull Request Guidelines

- Provide a clear description of the vulnerability pattern being added or fixed.
- Include CVE / CWE references and OWASP cheat sheet links in your analyzer.
- Ensure no sensitive keys, credentials, or mock API keys are permanently committed to the repository.
