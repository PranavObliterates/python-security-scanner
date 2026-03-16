"""Dynamic Application Security Testing (DAST) module."""
from .payload_tester import run_dast_tests, load_payloads
from .response_analyzer import (
    check_response_for_sqli,
    check_response_for_xss,
    check_security_headers,
    check_cookie_security,
)

__all__ = [
    "run_dast_tests", "load_payloads",
    "check_response_for_sqli", "check_response_for_xss",
    "check_security_headers", "check_cookie_security",
]
