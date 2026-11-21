from security_scanner.analyzers.a06_vulnerable_components import scan_dependency_manifests, scan_osv_advisories
from security_scanner.models.finding import VulnerabilityType
from unittest.mock import patch


def test_unpinned_requirements_are_reported(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask\nrequests==2.32.0\n", encoding="utf-8")

    findings = scan_dependency_manifests(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.UNPINNED_DEPENDENCY
    assert findings[0].file == str(manifest)


def test_dependency_scan_skips_virtual_environments(tmp_path):
    ignored = tmp_path / ".venv"
    ignored.mkdir()
    (ignored / "requirements.txt").write_text("bad-package\n", encoding="utf-8")

    assert scan_dependency_manifests(str(tmp_path)) == []


def test_pyproject_exact_pin_and_range_are_distinguished(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[project]\ndependencies = ["safe-lib==1.2.3", "loose-lib>=2.0"]\n',
        encoding="utf-8",
    )

    findings = scan_dependency_manifests(str(tmp_path))

    assert len(findings) == 1
    assert "loose-lib" in findings[0].code_snippet


def test_osv_query_reports_advisory_for_pinned_package(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("demo-package==1.2.3\n", encoding="utf-8")

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"vulns": [{"id": "OSV-TEST-1", "severity": [{"score": "8.0"}]}]}

    with patch("requests.post", return_value=Response()) as post:
        findings, warnings = scan_osv_advisories(str(tmp_path))

    post.assert_called_once()
    assert not warnings
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.DEPENDENCY_VULNERABILITY
    assert findings[0].severity.value == "HIGH"
