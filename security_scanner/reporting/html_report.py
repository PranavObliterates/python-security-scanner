"""Generate HTML report from scan results."""
from datetime import datetime
from ..models.scan_result import ScanResult
from ..models.finding import Severity

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#17a2b8",
    "INFO": "#6c757d",
}


def generate_html_report(result: ScanResult) -> str:
    """Generate a styled HTML report from scan results."""
    findings_html = ""
    for i, finding in enumerate(result.findings, 1):
        color = SEVERITY_COLORS.get(finding.severity.value, "#6c757d")
        source_badge = (
            f'<span style="background:#28a745;color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:0.75em;margin-left:8px;">'
            f'{finding.source}</span>'
        )

        fix_html = ""
        if finding.fix_before and finding.fix_after:
            fix_html = f"""
            <div style="margin-top:8px;">
                <div style="background:#fff0f0;padding:8px;border-radius:4px;margin:4px 0;">
                    <strong>Before:</strong> <code>{_escape(finding.fix_before)}</code>
                </div>
                <div style="background:#f0fff0;padding:8px;border-radius:4px;margin:4px 0;">
                    <strong>After:</strong> <code>{_escape(finding.fix_after)}</code>
                </div>
            </div>"""

        ref_html = ""
        if finding.reference:
            ref_html = f'<p>📖 <a href="{finding.reference}" target="_blank">OWASP Reference</a></p>'

        findings_html += f"""
        <div class="finding {finding.severity.value.lower()}" style="border:1px solid #e0e0e0;border-left:4px solid {color};
                    border-radius:8px;padding:16px;margin:12px 0;
                    background:#fff;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
            <div style="display:flex;align-items:center;margin-bottom:8px;">
                <span style="background:{color};color:#fff;padding:4px 12px;
                             border-radius:4px;font-weight:bold;font-size:0.85em;">
                    {finding.severity.value}
                </span>
                {source_badge}
                <span style="margin-left:auto;color:#888;">#{i}</span>
            </div>
            <h3 style="margin:8px 0 4px 0;color:#333;">{finding.vuln_type.value}</h3>
            <p style="color:#666;margin:4px 0;">
                📍 <strong>{finding.endpoint}</strong>
                {f' (line {finding.line})' if finding.line > 0 else ''}
                → {finding.file}
            </p>
            <div style="background:#f8f9fa;padding:8px 12px;border-radius:4px;
                        font-family:monospace;font-size:0.9em;margin:8px 0;">
                {_escape(finding.code_snippet)}
            </div>
            <p><strong>⚠️ Why:</strong> {_escape(finding.explanation)}</p>
            <p><strong>✅ Fix:</strong> {_escape(finding.fix_recommendation)}</p>
            {fix_html}
            {ref_html}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report — {_escape(result.app_name)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        .container {{ max-width: 900px; margin: 0 auto; padding: 20px; }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: #fff;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
        }}
        .header h1 {{ font-size: 1.5em; margin-bottom: 12px; }}
        .stats {{
            display: flex;
            gap: 20px;
            margin-top: 12px;
        }}
        .stat {{
            background: rgba(255,255,255,0.1);
            padding: 8px 16px;
            border-radius: 8px;
        }}
        .summary-bar {{
            display: flex;
            gap: 10px;
            margin: 16px 0;
            flex-wrap: wrap;
        }}
        .summary-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            color: #fff;
            font-weight: bold;
            font-size: 0.9em;
        }}
        code {{
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Scan Report</h1>
            <p><strong>Application:</strong> {_escape(result.app_name)}</p>
            <div class="stats">
                <div class="stat">📍 Routes: {result.routes_scanned}</div>
                <div class="stat">🔍 Issues: {len(result.findings)}</div>
                <div class="stat">⏱️ Time: {result.scan_duration_seconds:.3f}s</div>
                <div class="stat">📅 {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
            </div>
        </div>

        <div class="summary-bar">
            <button id="btn-all" class="summary-badge active" style="background:#333;color:#fff;" onclick="filterSeverity('all')">
                All
            </button>
            <button id="btn-critical" class="summary-badge" style="background:#dc3545;" onclick="filterSeverity('critical')">
                {result.critical_count} Critical
            </button>
            <button id="btn-high" class="summary-badge" style="background:#fd7e14;" onclick="filterSeverity('high')">
                {result.high_count} High
            </button>
            <button id="btn-medium" class="summary-badge" style="background:#ffc107;color:#333;" onclick="filterSeverity('medium')">
                {result.medium_count} Medium
            </button>
            <button id="btn-low" class="summary-badge" style="background:#17a2b8;" onclick="filterSeverity('low')">
                {result.low_count} Low
            </button>
        </div>

        {findings_html if findings_html else '<p style="text-align:center;padding:40px;color:#28a745;font-size:1.2em;">✅ No security issues found!</p>'}
    </div>
    <script>
        function filterSeverity(sev) {{
            document.querySelectorAll('.summary-badge').forEach(b => b.classList.remove('active'));
            document.getElementById('btn-' + sev).classList.add('active');
            
            const findings = document.querySelectorAll('.finding');
            findings.forEach(f => {{
                if (sev === 'all' || f.classList.contains(sev)) {{
                    f.style.display = 'block';
                }} else {{
                    f.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""
    return html


def save_html_report(result: ScanResult, filepath: str) -> None:
    """Save scan results as an HTML file."""
    html = generate_html_report(result)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"   [*] HTML report saved to: {filepath}")


def _escape(text: str) -> str:
    """Escape HTML special characters."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))
