"""OWASP Top 10 static analyzers for Python web applications.

Each module is prefixed with its OWASP 2021 category number for instant recognition:
  A01 – Broken Access Control       : a01_path_traversal, a01_open_redirect
  A02 – Cryptographic Failures      : a02_hardcoded_secrets, a02_weak_cryptography
  A03 – Injection                   : a03_sql_injection, a03_cross_site_scripting,
                                      a03_command_injection, a03_server_side_template_injection
  A05 – Security Misconfiguration   : a05_security_misconfiguration
  A06 – Vulnerable Components       : a06_vulnerable_components
  A07 – Auth Failures               : a07_broken_authentication (JWT)
  A08 – Software Integrity Failures : a08_insecure_deserialization
  A10 – SSRF                        : a10_server_side_request_forgery
"""
from .a03_sql_injection import SQLInjectionAnalyzer
from .a03_cross_site_scripting import XSSAnalyzer
from .a02_hardcoded_secrets import SecretsAnalyzer
from .a03_server_side_template_injection import SSTIAnalyzer
from .a08_insecure_deserialization import DeserializationAnalyzer
from .a03_command_injection import CommandInjectionAnalyzer
from .a01_path_traversal import PathTraversalAnalyzer
from .a10_server_side_request_forgery import SSRFAnalyzer
from .a02_weak_cryptography import WeakCryptoAnalyzer
from .a01_open_redirect import OpenRedirectAnalyzer
from .a05_security_misconfiguration import check_flask_config, check_django_config, check_fastapi_config
from .a07_broken_authentication import JWTAnalyzer
from .a06_vulnerable_components import scan_dependency_manifests, scan_osv_advisories

__all__ = [
    "SQLInjectionAnalyzer",
    "XSSAnalyzer",
    "SecretsAnalyzer",
    "SSTIAnalyzer",
    "DeserializationAnalyzer",
    "CommandInjectionAnalyzer",
    "PathTraversalAnalyzer",
    "SSRFAnalyzer",
    "WeakCryptoAnalyzer",
    "OpenRedirectAnalyzer",
    "JWTAnalyzer",
    "check_flask_config",
    "check_django_config",
    "check_fastapi_config",
    "scan_dependency_manifests",
    "scan_osv_advisories",
]
