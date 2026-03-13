from examples.vulnerable_app import app
from security_scanner import scan_app
from security_scanner.dynamic import DynamicTester
from security_scanner.analyzers.headers import analyze_headers
from security_scanner.reporting.json_report import save_json_report

result = scan_app(app)

print("=" * 60)
print(f" SECURITY SCAN REPORT — {result.app_name}")
print(f" Routes scanned: {result.routes_scanned}")
print(f" Scan time: {result.scan_duration_seconds:.3f}s")
print("=" * 60)

if not result.findings:
    print("\n ✅ No vulnerabilities found. Great job!")
else:
    for i, finding in enumerate(result.findings, 1):
        icon = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪"
        }.get(finding.severity.value, "⚪")

        print(f"\n {icon} [{i}] {finding.severity.value}: {finding.vuln_type.value}")
        print(f" Endpoint: {finding.endpoint}")
        if finding.line > 0:
            print(f" Line: {finding.line}")
        print(f" Code: {finding.code_snippet}")
        print(f" Why: {finding.explanation}")
        print(f" Fix: {finding.fix_recommendation}")
        if finding.fix_before:
            print(f" Before: {finding.fix_before}")
        if finding.fix_after:
            print(f" After: {finding.fix_after}")
        if finding.reference:
            print(f" Ref: {finding.reference}")

print(f"\n {'=' * 40}")
print(
    f" Summary: {result.critical_count} Critical | "
    f"{result.high_count} High | {result.medium_count} Medium"
)
print(f" Total issues: {len(result.findings)}")
print("=" * 60)

save_json_report(result, "scan_report.json")

base_url = "http://127.0.0.1:5000"
tester = DynamicTester(base_url)
sql_dynamic_findings = tester.run_sql_tests()
xss_dynamic_findings = tester.run_xss_tests()
header_issues = analyze_headers(base_url)

print("\n DYNAMIC TESTING")
print("-" * 60)
print(f" SQL injection findings: {len(sql_dynamic_findings)}")
for f in sql_dynamic_findings:
    print(
        f"  [SQLi] {f['endpoint']} "
        f"(status={f.get('status_code')}, payload={f['payload']})"
    )

print(f"\n XSS findings: {len(xss_dynamic_findings)}")
for f in xss_dynamic_findings:
    print(
        f"  [XSS] {f['endpoint']} "
        f"(status={f.get('status_code')}, payload={f['payload']})"
    )

print("\n SECURITY HEADERS")
print("-" * 60)
if not header_issues:
    print(f" All required headers present on {base_url}")
else:
    for issue in header_issues:
        t = issue.get("type")
        if t == "HEADER_MISSING":
            print(
                f"  [{issue['severity']}] Missing header: "
                f"{issue['header']}"
            )
        elif t == "HEADER_WEAK":
            print(
                f"  [{issue['severity']}] Weak header {issue['header']}: "
                f"{issue['value']}"
            )
        else:
            print(
                f"  [{issue.get('severity', 'INFO')}] "
                f"{issue.get('detail', str(issue))}"
            )
