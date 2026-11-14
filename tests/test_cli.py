"""Tests for PySecure CLI argument parsing, filtering, and exit codes."""
import pytest
import os
import json
from unittest.mock import patch
from pysecure.cli import main, load_app_from_path, load_cli_config


def test_cli_load_config_from_pyproject(tmp_path):
    """Test loading configuration from pyproject.toml [tool.pysecure]."""
    toml_content = b"""
[tool.pysecure]
severity = "HIGH"
fail_on = "CRITICAL"
ignore = ["DEBUG_MODE", "WEAK_CRYPTO"]
"""
    pyproj = tmp_path / "pyproject.toml"
    pyproj.write_bytes(toml_content)

    cfg = load_cli_config(str(tmp_path))
    assert cfg.get("severity") == "HIGH"
    assert cfg.get("fail_on") == "CRITICAL"
    assert "DEBUG_MODE" in cfg.get("ignore", [])


def test_cli_load_config_from_rc(tmp_path):
    """Test loading configuration from .pysecurerc JSON."""
    rc_content = {
        "severity": "MEDIUM",
        "fail_on": "HIGH",
        "ignore": ["CSRF_MISSING"]
    }
    rc_file = tmp_path / ".pysecurerc"
    rc_file.write_text(json.dumps(rc_content), encoding="utf-8")

    cfg = load_cli_config(str(tmp_path))
    assert cfg.get("severity") == "MEDIUM"
    assert cfg.get("fail_on") == "HIGH"
    assert "CSRF_MISSING" in cfg.get("ignore", [])


def test_cli_help(capsys):
    """CLI should print help and exit 0 when passed --help."""
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "PySecure" in captured.out


def test_scan_url_help_does_not_get_rewritten_as_local_scan(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan-url", "--help"])
    assert exc.value.code == 0
    assert "private IP address" in capsys.readouterr().out


def test_loaded_flask_app_resolves_templates_next_to_source():
    app = load_app_from_path("demos/vulnerable-flask/app.py")
    assert app.test_client().get("/login").status_code == 200


def test_cli_scan_fail_on_critical():
    """CLI should exit 1 when critical findings are discovered."""
    with pytest.raises(SystemExit) as exc:
        main(["scan", "demos/vulnerable-flask/app.py", "--static-only", "--fail-on", "CRITICAL"])
    assert exc.value.code == 1


def test_cli_scan_safe_app_passes():
    """CLI should exit 0 when scanning safe app with fail-on CRITICAL."""
    with pytest.raises(SystemExit) as exc:
        main(["scan", "examples/safe_flask_app.py", "--static-only", "--fail-on", "CRITICAL"])
    assert exc.value.code == 0


def test_cli_scan_ignore_filters_vulnerabilities(capsys):
    """CLI --ignore flag should filter out ignored vulnerability types."""
    with pytest.raises(SystemExit):
        main([
            "scan", "demos/vulnerable-flask/app.py",
            "--static-only",
            "--ignore", "SQL_INJECTION,INSECURE_DESERIALIZATION,SSTI,XSS,HARDCODED_SECRET,CSRF_MISSING",
            "--fail-on", "CRITICAL"
        ])
        captured = capsys.readouterr()
        assert "No security issues found!" in captured.out


def test_scan_url_audits_dependency_manifests_once(tmp_path):
    from security_scanner.models.scan_result import ScanResult

    with patch("pysecure.cli.scan_remote_url", return_value=ScanResult("test")):
        with patch("pysecure.cli.scan_dependency_manifests", return_value=[]) as audit:
            with pytest.raises(SystemExit) as exc:
                main([
                    "scan-url",
                    "http://127.0.0.1/",
                    "--dependencies",
                    str(tmp_path),
                ])
    assert exc.value.code == 0
    audit.assert_called_once_with(str(tmp_path))


def test_debug_flag_enables_scanner_diagnostics(caplog):
    import logging
    from security_scanner.models.scan_result import ScanResult

    def scan_with_debug_log(*_args, **_kwargs):
        logging.getLogger("security_scanner.dynamic.remote").debug("debug scan marker")
        return ScanResult("debug-test")

    caplog.set_level(logging.DEBUG)
    with patch("pysecure.cli.scan_remote_url", side_effect=scan_with_debug_log):
        with pytest.raises(SystemExit) as exc:
            main(["scan-url", "http://127.0.0.1/", "--max-pages", "1", "--debug"])
    assert exc.value.code == 0
    assert "debug scan marker" in caplog.text
