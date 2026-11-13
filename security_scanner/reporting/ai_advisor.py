"""Gemini AI Security Advisor — provides AI-powered analysis of scan findings.

Uses session-only API keys that are never persisted to disk.
"""
import os
import sys
import getpass
from typing import Optional, Dict, Any
from ..models.scan_result import ScanResult


def get_session_api_key(api_key: Optional[str] = None, prompt_if_missing: bool = True) -> Optional[str]:
    """Retrieve the Gemini API key for this session only.

    The key is stored only in memory for the life of the process.
    It is never written to disk, config files, or git.
    """
    if api_key and api_key.strip():
        return api_key.strip()

    # Check session environment variable
    env_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if env_key:
        return env_key

    # Prompt user interactively from terminal if allowed
    if prompt_if_missing and sys.stdin.isatty():
        try:
            print("\n[AI Security Advisor] Gemini API key required for AI-generated PDF executive report.")
            print("(Note: The key is kept in process memory for this session only and will NOT be saved to disk)")
            entered = getpass.getpass("Enter Gemini API Key (press Enter to skip): ").strip()
            if entered:
                return entered
        except (KeyboardInterrupt, EOFError):
            return None

    return None


def generate_ai_security_summary(result: ScanResult, api_key: Optional[str] = None) -> Dict[str, str]:
    """Generate an AI security analysis using Google Gemini.

    Returns a dictionary with:
    - 'executive_summary': High-level overview of the application's posture.
    - 'risk_assessment': Critical risk analysis.
    - 'remediation_plan': Prioritized roadmap for remediation.
    """
    key = get_session_api_key(api_key, prompt_if_missing=False)
    if not key:
        return _generate_fallback_summary(result)

    # Format findings summary for the prompt
    findings_text = []
    for i, f in enumerate(result.findings[:25], 1):
        findings_text.append(
            f"{i}. [{f.severity.value}] {f.vuln_type.value} at {f.endpoint} ({f.file}:{f.line})\n"
            f"   OWASP: {f.vuln_type.owasp_category}\n"
            f"   Snippet: {f.code_snippet}\n"
            f"   Why: {f.explanation[:150]}..."
        )

    findings_summary = "\n".join(findings_text) or "No vulnerabilities detected."

    prompt = f"""You are a Principal Application Security Architect. Analyze the following security scan results from an automated SAST/DAST audit:

Application: {result.app_name}
Total Findings: {len(result.findings)}
Critical: {result.critical_count} | High: {result.high_count} | Medium: {result.medium_count} | Low: {result.low_count}
Scan Duration: {result.scan_duration_seconds:.2f}s

Vulnerabilities Discovered:
{findings_summary}

Please provide a structured, professional security assessment with exactly three sections:
### 1. Executive Summary
Provide a 2-3 paragraph executive summary of the security posture, overall risk level, and business impact.

### 2. Threat & Attack Surface Analysis
Explain the primary attack vectors, how an attacker might chain these vulnerabilities (e.g. SQLi or Deserialization into RCE), and the most urgent threats.

### 3. Prioritized Remediation Roadmap
Provide an immediate, actionable 3-step action plan for developers to harden this application.

Format cleanly with clear prose suitable for a formal security report.
"""

    try:
        # Try google.genai SDK first
        from google import genai
        client = genai.Client(api_key=key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        text = response.text or ""
        return _parse_ai_sections(text, result)
    except Exception as e:
        # Try direct REST API fallback
        try:
            import json
            import urllib.request
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}]
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return _parse_ai_sections(text, result)
        except Exception as inner_e:
            return _generate_fallback_summary(result, error_msg=f"Gemini API call failed: {str(e)}")


def _parse_ai_sections(text: str, result: ScanResult) -> Dict[str, str]:
    """Parse the AI response into structured sections."""
    sections = {
        "executive_summary": "",
        "risk_assessment": "",
        "remediation_plan": "",
        "full_text": text,
    }

    current_sec = "executive_summary"
    lines = text.splitlines()
    buffer = []

    for line in lines:
        lower = line.lower()
        if "### 1" in lower or "executive summary" in lower:
            if buffer:
                sections[current_sec] = "\n".join(buffer).strip()
                buffer = []
            current_sec = "executive_summary"
        elif "### 2" in lower or "threat" in lower or "attack surface" in lower:
            if buffer:
                sections[current_sec] = "\n".join(buffer).strip()
                buffer = []
            current_sec = "risk_assessment"
        elif "### 3" in lower or "remediation" in lower or "roadmap" in lower:
            if buffer:
                sections[current_sec] = "\n".join(buffer).strip()
                buffer = []
            current_sec = "remediation_plan"
        else:
            buffer.append(line)

    if buffer:
        sections[current_sec] = "\n".join(buffer).strip()

    # Fallbacks if sections were empty
    if not sections["executive_summary"]:
        sections["executive_summary"] = text[:500]
    if not sections["risk_assessment"]:
        sections["risk_assessment"] = "High priority review required for critical and high severity findings."
    if not sections["remediation_plan"]:
        sections["remediation_plan"] = "Address critical injection and authentication flaws immediately."

    return sections


def _generate_fallback_summary(result: ScanResult, error_msg: str = "") -> Dict[str, str]:
    """Generate default expert rules-based summary when API key is not supplied."""
    posture = "CRITICAL RISK" if result.critical_count > 0 else ("HIGH RISK" if result.high_count > 0 else "MODERATE")
    exec_summary = (
        f"Automated security assessment of '{result.app_name}' identified {len(result.findings)} potential "
        f"vulnerabilities across {result.routes_scanned} routes. The overall security posture is evaluated as "
        f"{posture}. "
    )
    if result.critical_count > 0:
        exec_summary += (
            f"The scan detected {result.critical_count} CRITICAL severity flaws (e.g. SQL Injection, Insecure Deserialization, "
            f"or Command Injection) that could allow unauthenticated remote code execution or complete database compromise."
        )
    else:
        exec_summary += "No critical remote compromise vectors were observed during this audit."

    if error_msg:
        exec_summary += f"\n\n[Note: {error_msg}]"

    risk_assessment = (
        "Primary exposure points include input handling in route handlers and dynamic query/template rendering. "
        "Any finding with CRITICAL or HIGH severity should be considered an active attack surface vector."
    )

    remediation_plan = (
        "1. Parameterize all SQL queries and template renderings to prevent injection.\n"
        "2. Replace insecure deserializers (such as pickle) with structured schemas (JSON).\n"
        "3. Enforce CSRF protection and add security headers (CSP, HSTS, X-Frame-Options)."
    )

    return {
        "executive_summary": exec_summary,
        "risk_assessment": risk_assessment,
        "remediation_plan": remediation_plan,
        "full_text": exec_summary,
    }
