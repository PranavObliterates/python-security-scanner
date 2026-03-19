"""Dynamic testing: send attack payloads via Flask test client and analyze responses."""
import os
import re
from typing import List
from ..models.finding import Finding, Severity, VulnerabilityType
from .response_analyzer import check_response_for_sqli, check_response_for_xss

PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "payloads")


def load_payloads(filename: str) -> List[str]:
    """Load payloads from a text file in the payloads directory."""
    filepath = os.path.join(PAYLOADS_DIR, filename)
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _extract_param_names(path: str) -> List[str]:
    """Extract parameter names from a Flask route rule.

    E.g., '/user/<id>' -> ['id']
    E.g., '/user' -> ['id', 'q', 'name', 'search', 'input']  (common defaults)
    """
    # Find named parameters in angle brackets
    params = re.findall(r"<(?:\w+:)?(\w+)>", path)
    if params:
        return params
    # If no path params, use common query parameter names
    return ["id", "q", "name", "search", "input", "user", "query"]


def run_dast_tests(app, routes) -> List[Finding]:
    """Run all dynamic tests against the app using Flask's test client.

    Tests each route with SQL injection and XSS payloads,
    analyzing responses for signs of vulnerability.
    """
    findings = []
    client = app.test_client()

    for route in routes:
        path = route.path
        methods = route.methods
        param_names = _extract_param_names(path)

        # Clean path: replace <param> with a safe default value
        clean_path = re.sub(r"<(?:\w+:)?(\w+)>", "1", path)

        # Test SQL injection
        sqli_findings = _test_sqli(client, clean_path, methods, param_names)
        findings.extend(sqli_findings)

        # Test XSS
        xss_findings = _test_xss(client, clean_path, methods, param_names)
        findings.extend(xss_findings)

        # Test SSTI
        ssti_findings = _test_ssti(client, clean_path, methods, param_names, is_django=False)
        findings.extend(ssti_findings)

        # Test Deserialization
        deser_findings = _test_deserialization(client, clean_path, methods, param_names, is_django=False)
        findings.extend(deser_findings)

    return findings


def _test_sqli(client, path: str, methods: List[str], param_names: List[str]) -> List[Finding]:
    """Test an endpoint for SQL injection using payloads."""
    findings = []
    payloads = load_payloads("sqli_payloads.txt")

    for param in param_names:
        found_sqli = False
        for payload in payloads:
            if found_sqli:
                break

            try:
                if "GET" in methods:
                    response = client.get(f"{path}?{param}={payload}")
                    body = response.data.decode("utf-8", errors="ignore")

                    if check_response_for_sqli(body):
                        findings.append(Finding(
                            vuln_type=VulnerabilityType.SQL_INJECTION,
                            severity=Severity.CRITICAL,
                            endpoint=path,
                            file="(dynamic test)",
                            line=0,
                            code_snippet=f"GET {path}?{param}={payload}",
                            explanation=(
                                f"Sending payload '{payload}' as parameter '{param}' "
                                f"caused a database error in the response, confirming "
                                f"SQL injection is possible. Response status: {response.status_code}."
                            ),
                            fix_recommendation="Use parameterized queries instead of string interpolation.",
                            fix_before=f'cursor.execute(f"SELECT ... WHERE col = {{{param}}}")',
                            fix_after=f'cursor.execute("SELECT ... WHERE col = %s", ({param},))',
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            source="DAST",
                            confidence="HIGH",
                        ))
                        found_sqli = True

                if "POST" in methods and not found_sqli:
                    response = client.post(path, data={param: payload})
                    body = response.data.decode("utf-8", errors="ignore")

                    if check_response_for_sqli(body):
                        findings.append(Finding(
                            vuln_type=VulnerabilityType.SQL_INJECTION,
                            severity=Severity.CRITICAL,
                            endpoint=path,
                            file="(dynamic test)",
                            line=0,
                            code_snippet=f"POST {path} [{param}={payload}]",
                            explanation=(
                                f"Sending payload '{payload}' as POST parameter '{param}' "
                                f"caused a database error, confirming SQL injection."
                            ),
                            fix_recommendation="Use parameterized queries.",
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            source="DAST",
                            confidence="HIGH",
                        ))
                        found_sqli = True

            except Exception:
                # Skip payloads that cause connection errors
                continue

    return findings


def _test_xss(client, path: str, methods: List[str], param_names: List[str]) -> List[Finding]:
    """Test an endpoint for XSS by checking if payloads are reflected."""
    findings = []
    payloads = load_payloads("xss_payloads.txt")

    for param in param_names:
        found_xss = False
        for payload in payloads:
            if found_xss:
                break

            try:
                if "GET" in methods:
                    response = client.get(f"{path}?{param}={payload}")
                    body = response.data.decode("utf-8", errors="ignore")

                    if check_response_for_xss(body, payload):
                        findings.append(Finding(
                            vuln_type=VulnerabilityType.XSS,
                            severity=Severity.CRITICAL,
                            endpoint=path,
                            file="(dynamic test)",
                            line=0,
                            code_snippet=f"GET {path}?{param}={payload[:60]}",
                            explanation=(
                                f"XSS payload '{payload[:40]}...' sent as parameter "
                                f"'{param}' was reflected unescaped in the HTML response. "
                                f"An attacker can inject malicious scripts."
                            ),
                            fix_recommendation="Escape all user input before including in HTML output.",
                            fix_before=f'return f"...{{{param}}}..."',
                            fix_after=f'from markupsafe import escape\nreturn f"...{{escape({param})}}..."',
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            source="DAST",
                            confidence="HIGH",
                        ))
                        found_xss = True

            except Exception:
                continue

    return findings


def run_django_dast_tests(routes) -> List[Finding]:
    """Run all dynamic tests against a Django app using Django's test client.

    Tests each route with SQL injection and XSS payloads,
    analyzing responses for signs of vulnerability.
    """
    from django.test import Client as DjangoClient

    findings = []
    client = DjangoClient()

    for route in routes:
        path = route.path
        methods = route.methods
        param_names = _extract_param_names(path)

        # Clean path: replace <param> patterns with safe default
        clean_path = re.sub(r"<(?:\w+:)?(\w+)>", "1", path)

        # Test SQL injection
        sqli_findings = _test_sqli_django(client, clean_path, methods, param_names)
        findings.extend(sqli_findings)

        # Test XSS
        xss_findings = _test_xss_django(client, clean_path, methods, param_names)
        findings.extend(xss_findings)

        # Test SSTI
        ssti_findings = _test_ssti(client, clean_path, methods, param_names, is_django=True)
        findings.extend(ssti_findings)

        # Test Deserialization
        deser_findings = _test_deserialization(client, clean_path, methods, param_names, is_django=True)
        findings.extend(deser_findings)

    return findings


def _test_sqli_django(client, path: str, methods: List[str], param_names: List[str]) -> List[Finding]:
    """Test a Django endpoint for SQL injection using payloads."""
    findings = []
    payloads = load_payloads("sqli_payloads.txt")

    for param in param_names:
        found_sqli = False
        for payload in payloads:
            if found_sqli:
                break

            try:
                if "GET" in methods:
                    response = client.get(f"{path}?{param}={payload}")
                    body = response.content.decode("utf-8", errors="ignore")

                    if check_response_for_sqli(body):
                        findings.append(Finding(
                            vuln_type=VulnerabilityType.SQL_INJECTION,
                            severity=Severity.CRITICAL,
                            endpoint=path,
                            file="(dynamic test)",
                            line=0,
                            code_snippet=f"GET {path}?{param}={payload}",
                            explanation=(
                                f"Sending payload '{payload}' as parameter '{param}' "
                                f"caused a database error in the response, confirming "
                                f"SQL injection is possible. Response status: {response.status_code}."
                            ),
                            fix_recommendation="Use parameterized queries or Django ORM.",
                            fix_before=f'cursor.execute(f"SELECT ... WHERE col = {{{param}}}")',
                            fix_after=f'cursor.execute("SELECT ... WHERE col = %s", ({param},))',
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            source="DAST",
                            confidence="HIGH",
                        ))
                        found_sqli = True

                if "POST" in methods and not found_sqli:
                    response = client.post(path, data={param: payload})
                    body = response.content.decode("utf-8", errors="ignore")

                    if check_response_for_sqli(body):
                        findings.append(Finding(
                            vuln_type=VulnerabilityType.SQL_INJECTION,
                            severity=Severity.CRITICAL,
                            endpoint=path,
                            file="(dynamic test)",
                            line=0,
                            code_snippet=f"POST {path} [{param}={payload}]",
                            explanation=(
                                f"Sending payload '{payload}' as POST parameter '{param}' "
                                f"caused a database error, confirming SQL injection."
                            ),
                            fix_recommendation="Use parameterized queries or Django ORM.",
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            source="DAST",
                            confidence="HIGH",
                        ))
                        found_sqli = True

            except Exception:
                continue

    return findings


def _test_xss_django(client, path: str, methods: List[str], param_names: List[str]) -> List[Finding]:
    """Test a Django endpoint for XSS by checking if payloads are reflected."""
    findings = []
    payloads = load_payloads("xss_payloads.txt")

    for param in param_names:
        found_xss = False
        for payload in payloads:
            if found_xss:
                break

            try:
                if "GET" in methods:
                    response = client.get(f"{path}?{param}={payload}")
                    body = response.content.decode("utf-8", errors="ignore")

                    if check_response_for_xss(body, payload):
                        findings.append(Finding(
                            vuln_type=VulnerabilityType.XSS,
                            severity=Severity.CRITICAL,
                            endpoint=path,
                            file="(dynamic test)",
                            line=0,
                            code_snippet=f"GET {path}?{param}={payload[:60]}",
                            explanation=(
                                f"XSS payload '{payload[:40]}...' sent as parameter "
                                f"'{param}' was reflected unescaped in the HTML response. "
                                f"An attacker can inject malicious scripts."
                            ),
                            fix_recommendation="Escape all user input before including in HTML output.",
                            fix_before=f'HttpResponse(f"...{{{param}}}...")',
                            fix_after=f'from django.utils.html import escape\nHttpResponse(f"...{{escape({param})}}...")',
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            source="DAST",
                            confidence="HIGH",
                        ))
                        found_xss = True

            except Exception:
                continue

    return findings


def _test_ssti(client, path: str, methods: List[str], param_names: List[str], is_django: bool = False) -> List[Finding]:
    """Test an endpoint for SSTI."""
    findings = []
    ssti_payloads = ["{{ 7 * 7 }}", "${7 * 7}", "{{ 7|add:7 }}"]
    
    for param in param_names:
        for payload in ssti_payloads:
            try:
                if "GET" in methods:
                    response = client.get(f"{path}?{param}={payload}")
                    body = response.content.decode("utf-8", errors="ignore") if is_django else response.data.decode("utf-8", errors="ignore")
                    
                    if "49" in body or "14" in body:
                        findings.append(Finding(
                            vuln_type=VulnerabilityType.SSTI,
                            severity=Severity.CRITICAL,
                            endpoint=path,
                            file="(dynamic test)",
                            line=0,
                            code_snippet=f"GET {path}?{param}={payload}",
                            explanation=f"SSTI payload '{payload}' sent as parameter '{param}' was evaluated to '49', confirming Server-Side Template Injection.",
                            fix_recommendation="Do not dynamically evaluate user input as templates.",
                            fix_before="",
                            fix_after="",
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html",
                            source="DAST",
                            confidence="HIGH",
                        ))
                        break
            except Exception:
                pass
    return findings


def _test_deserialization(client, path: str, methods: List[str], param_names: List[str], is_django: bool = False) -> List[Finding]:
    """Test an endpoint for Insecure Deserialization."""
    findings = []
    deser_payload = "gASVJAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwKcHJpbnQoJzEnKZSFlFKULg=="
    
    for param in param_names:
        try:
            if "GET" in methods:
                response = client.get(f"{path}?{param}={deser_payload}")
                if response.status_code == 500:
                    findings.append(Finding(
                        vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION,
                        severity=Severity.CRITICAL,
                        endpoint=path,
                        file="(dynamic test)",
                        line=0,
                        code_snippet=f"GET {path}?{param}=<Base64_Pickle>",
                        explanation=f"Sending a serialized payload as parameter '{param}' caused a 500 error, indicating the server might be insecurely deserializing data.",
                        fix_recommendation="Do not use unsafe deserialization formats like pickle.",
                        fix_before="pickle.loads(data)",
                        fix_after="json.loads(data)",
                        reference="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
                        source="DAST",
                        confidence="MEDIUM",
                    ))
        except Exception:
            pass
    return findings
