"""Static analyzers for SQL injection, XSS, secrets, SSTI, deserialization, command injection, path traversal, SSRF, weak crypto, and configuration."""
from .sql_injection import SQLInjectionAnalyzer
from .xss import XSSAnalyzer
from .secrets import SecretsAnalyzer
from .ssti import SSTIAnalyzer
from .deserialization import DeserializationAnalyzer
from .command_injection import CommandInjectionAnalyzer
from .path_traversal import PathTraversalAnalyzer
from .ssrf import SSRFAnalyzer
from .weak_crypto import WeakCryptoAnalyzer
from .open_redirect import OpenRedirectAnalyzer
from .config import check_flask_config, check_django_config

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
    "check_flask_config",
    "check_django_config",
]
