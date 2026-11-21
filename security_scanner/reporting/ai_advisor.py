"""Gemini AI Security Advisor — grounded, per-finding security analysis.

Produces detailed, code-specific remediation guidance based on the actual
vulnerable code snippets captured by the scanner. API keys are session-only
and never persisted to disk, environment variables, or configuration files.
"""
import os
import sys
import json
import getpass
import urllib.request
from typing import Optional, Dict, List, Any
from ..models.scan_result import ScanResult
from ..models.finding import Finding, Severity


def get_session_api_key(api_key: Optional[str] = None, prompt_if_missing: bool = True) -> Optional[str]:
    """Retrieve the Gemini API key for this session only.

    The key is stored only in memory for the life of the process.
    It is never written to disk, config files, or git.
    """
    if api_key and api_key.strip():
        return api_key.strip()

    env_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if env_key:
        return env_key

    if prompt_if_missing and sys.stdin.isatty():
        try:
            print("\n[AI Security Advisor] Gemini API key required for AI-generated PDF report.")
            print("(The key is kept in process memory for this session only — never saved to disk.)")
            entered = getpass.getpass("Enter Gemini API Key (press Enter to skip): ").strip()
            if entered:
                return entered
        except (KeyboardInterrupt, EOFError):
            return None

    return None


def _call_gemini(prompt: str, key: str, timeout: int = 30) -> str:
    """Send a prompt to Gemini and return the response text.

    Tries the google-genai SDK first, falls back to direct REST.
    """
    try:
        from google import genai
        client = genai.Client(api_key=key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return response.text or ""
    except Exception:
        pass

    # REST fallback
    url = (
        "https://generativelanguage.googleapis.com/v1beta/"
        f"models/gemini-2.5-flash:generateContent?key={key}"
    )
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return data["candidates"][0]["content"]["parts"][0]["text"]


# ─────────────────────────────────────────────────────────────────────────────
# HIGH-LEVEL SUMMARY  (executive + risk + roadmap)
# ─────────────────────────────────────────────────────────────────────────────

def generate_ai_security_summary(result: ScanResult, api_key: Optional[str] = None) -> Dict[str, str]:
    """Generate a high-level AI security assessment: executive summary,
    attack-surface analysis, and prioritised remediation roadmap.

    Returns a dict with keys:
        executive_summary, risk_assessment, remediation_plan, full_text
    """
    key = get_session_api_key(api_key, prompt_if_missing=False)
    if not key:
        return _generate_fallback_summary(result)

    # Build a tightly structured finding digest (capped at 30 findings)
    finding_lines = []
    for i, f in enumerate(result.findings[:30], 1):
        finding_lines.append(
            f"{i}. [{f.severity.value}] {f.vuln_type.value}  "
            f"endpoint={f.endpoint}  file={f.file}:{f.line}\n"
            f"   OWASP: {f.vuln_type.owasp_category}\n"
            f"   Code:  {f.code_snippet}\n"
            f"   Why:   {(f.explanation or '')[:200]}"
        )
    finding_digest = "\n\n".join(finding_lines) or "No vulnerabilities found."

    prompt = f"""You are a Principal Application Security Architect producing a formal security audit report.

APPLICATION: {result.app_name}
SCAN COVERAGE: {result.routes_scanned} routes  |  {result.routes_tested} dynamically tested
FINDINGS: {len(result.findings)} total — CRITICAL: {result.critical_count}  HIGH: {result.high_count}  MEDIUM: {result.medium_count}  LOW: {result.low_count}
SCAN DURATION: {result.scan_duration_seconds:.2f}s

VULNERABILITY DIGEST:
{finding_digest}

Write a professional security audit report with EXACTLY these three sections.
Ground every statement in the actual findings above. Do not invent issues not listed.

### 1. Executive Summary
Two to three paragraphs for a non-technical audience. State the overall security
posture, the most severe finding categories, and the business risk if left unaddressed.
Reference specific endpoints and vulnerability types from the digest above.

### 2. Attack Surface & Risk Analysis
For each CRITICAL and HIGH finding: explain the specific source-to-sink data flow
in the detected code snippet, the conditions under which exploitation is realistic,
and the blast radius (data exposure, privilege escalation, service disruption).
Use precise security terminology. Ground analysis in the actual code shown.

### 3. Prioritised Remediation Roadmap
A numbered, sprint-ready action plan. Order items by severity and exploitability.
For each action, state: what to change, where (file/endpoint), and why it closes
the vulnerability. Reference specific findings by their number above.

Write in clear, formal prose. Do not add sections, preamble, or commentary outside
these three headings.
"""

    try:
        text = _call_gemini(prompt, key)
        return _parse_ai_sections(text, result)
    except Exception as exc:
        return _generate_fallback_summary(result, error_msg=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# PER-FINDING DEEP ANALYSIS  (the new, code-specific layer)
# ─────────────────────────────────────────────────────────────────────────────

def generate_per_finding_analysis(
    findings: List[Finding],
    app_name: str,
    api_key: Optional[str] = None,
    max_findings: int = 20,
) -> Dict[int, Dict[str, str]]:
    """For each finding, ask Gemini to produce a detailed, code-specific analysis.

    Returns a dict keyed by finding index (0-based) with:
        - 'technical_detail': precise explanation of the vulnerability in the
          detected code — not generic advice
        - 'fixed_code': a corrected version of the detected snippet
        - 'why_fix_works': why the specific fix closes this vulnerability class
        - 'owasp_context': OWASP Top 10 (2021) chapter and CWE mapping
        - 'effort': estimated remediation effort (Low / Medium / High)
    """
    key = get_session_api_key(api_key, prompt_if_missing=False)
    if not key:
        return {}

    results: Dict[int, Dict[str, str]] = {}
    targets = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    targets = targets[:max_findings]

    for idx, finding in enumerate(targets):
        original_idx = findings.index(finding)
        prompt = f"""You are a senior application security engineer writing a security advisory for a developer.

APPLICATION: {app_name}
FILE: {finding.file}  LINE: {finding.line}
ENDPOINT: {finding.endpoint}
VULNERABILITY CLASS: {finding.vuln_type.value}  ({finding.vuln_type.owasp_category})
SEVERITY: {finding.severity.value}
DETECTION METHOD: {finding.source}

DETECTED CODE SNIPPET:
```python
{finding.code_snippet}
```

SCANNER EXPLANATION:
{finding.explanation or "N/A"}

SCANNER'S SUGGESTED FIX (before/after):
BEFORE: {finding.fix_before or "N/A"}
AFTER:  {finding.fix_after or "N/A"}

Write a concise, technically accurate developer advisory in EXACTLY these four sections.
Every statement must be grounded in the code snippet above.

### Technical Detail
In 3–5 sentences: explain precisely what makes this specific line of code vulnerable.
Reference the variable names and API calls present in the snippet. Do not write
generic advice — explain this exact code path.

### Corrected Implementation
Provide a corrected Python code block that fixes the vulnerability while preserving
the endpoint's intended behaviour. Use the same variable names and framework as the
original. Show the full corrected function or the relevant lines with enough context
to be unambiguous.

### Why This Fix Works
In 2–3 sentences: explain the security property the fix introduces (e.g., query
parameterisation separates data from control flow) and why it closes this specific
vulnerability class — not injection in general, but *this* instance.

### OWASP & CWE Mapping
State the OWASP Top 10 (2021) category, the CWE identifier(s), and the estimated
developer effort to apply the fix (Low / Medium / High) with a one-sentence rationale.

Respond only with these four sections. No preamble or closing remarks.
"""

        try:
            text = _call_gemini(prompt, key, timeout=25)
            results[original_idx] = _parse_finding_sections(text)
        except Exception as exc:
            results[original_idx] = _fallback_finding_analysis(finding, str(exc))

    return results


def _parse_finding_sections(text: str) -> Dict[str, str]:
    """Parse a per-finding Gemini response into structured fields."""
    sections: Dict[str, str] = {
        "technical_detail": "",
        "fixed_code": "",
        "why_fix_works": "",
        "owasp_context": "",
    }

    key_map = {
        "technical detail": "technical_detail",
        "corrected implementation": "fixed_code",
        "why this fix works": "why_fix_works",
        "owasp": "owasp_context",
        "cwe": "owasp_context",
    }

    current = "technical_detail"
    buffer: List[str] = []

    for line in text.splitlines():
        lower = line.lower().lstrip("# ").strip()
        matched = False
        for keyword, field in key_map.items():
            if keyword in lower:
                if buffer:
                    sections[current] = "\n".join(buffer).strip()
                    buffer = []
                current = field
                matched = True
                break
        if not matched:
            buffer.append(line)

    if buffer:
        sections[current] = "\n".join(buffer).strip()

    # Fallback: if any section is still empty, fill from full text
    if not sections["technical_detail"]:
        sections["technical_detail"] = text[:600]

    return sections


def _fallback_finding_analysis(finding: Finding, error: str = "") -> Dict[str, str]:
    """Rules-based fallback when the Gemini call fails for a specific finding."""
    detail = (
        f"The variable involved in this {finding.vuln_type.value} finding is used "
        f"at line {finding.line} of {finding.file} without adequate sanitisation "
        f"before it reaches a sensitive sink. {finding.explanation or ''}"
    )
    fixed = finding.fix_after or "(See scanner fix recommendation above.)"
    why = (
        f"The recommended fix introduces a security boundary between user-controlled "
        f"data and the sensitive operation, closing the {finding.vuln_type.value} "
        f"vector at this endpoint."
    )
    owasp = (
        f"OWASP 2021: {finding.vuln_type.owasp_category}. "
        f"Refer to the OWASP Cheat Sheet for this vulnerability class. "
        f"Remediation effort: Medium."
    )
    if error:
        owasp += f" [AI analysis unavailable: {error[:120]}]"
    return {
        "technical_detail": detail,
        "fixed_code": fixed,
        "why_fix_works": why,
        "owasp_context": owasp,
    }


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _parse_ai_sections(text: str, result: ScanResult) -> Dict[str, str]:
    """Parse a high-level Gemini response into the three report sections."""
    sections: Dict[str, str] = {
        "executive_summary": "",
        "risk_assessment": "",
        "remediation_plan": "",
        "full_text": text,
    }

    key_map = {
        "executive summary": "executive_summary",
        "attack surface": "risk_assessment",
        "risk analysis": "risk_assessment",
        "threat": "risk_assessment",
        "remediation": "remediation_plan",
        "roadmap": "remediation_plan",
    }

    current = "executive_summary"
    buffer: List[str] = []

    for line in text.splitlines():
        lower = line.lower()
        matched = False
        for keyword, field in key_map.items():
            if keyword in lower and (line.startswith("#") or line.startswith("**")):
                if buffer:
                    sections[current] = "\n".join(buffer).strip()
                    buffer = []
                current = field
                matched = True
                break
        if not matched:
            buffer.append(line)

    if buffer:
        sections[current] = "\n".join(buffer).strip()

    if not sections["executive_summary"]:
        sections["executive_summary"] = text[:600]
    if not sections["risk_assessment"]:
        sections["risk_assessment"] = "High priority review required for all critical and high severity findings."
    if not sections["remediation_plan"]:
        sections["remediation_plan"] = "Address critical injection and authentication flaws immediately."

    return sections


def _generate_fallback_summary(result: ScanResult, error_msg: str = "") -> Dict[str, str]:
    """Rules-based summary when no API key is supplied or the call fails."""
    posture = (
        "CRITICAL RISK" if result.critical_count > 0
        else "HIGH RISK" if result.high_count > 0
        else "MODERATE RISK" if result.medium_count > 0
        else "LOW RISK"
    )

    exec_summary = (
        f"The automated security assessment of '{result.app_name}' identified "
        f"{len(result.findings)} potential vulnerabilities across {result.routes_scanned} routes. "
        f"The overall security posture is evaluated as {posture}. "
    )
    if result.critical_count > 0:
        exec_summary += (
            f"The scan detected {result.critical_count} CRITICAL severity flaw(s) — including "
            f"injection-class vulnerabilities (SQL Injection, Command Injection, SSTI) and "
            f"insecure deserialisation — that could allow unauthenticated remote code execution "
            f"or complete database compromise if exploited."
        )
    elif result.high_count > 0:
        exec_summary += (
            f"The scan detected {result.high_count} HIGH severity flaw(s) requiring "
            f"remediation in the current development sprint."
        )
    else:
        exec_summary += "No critical remote compromise vectors were observed during this audit."

    if error_msg:
        exec_summary += f"\n\n[Note: AI-enhanced analysis unavailable — {error_msg[:200]}]"

    risk_assessment = (
        "Primary exposure points are the endpoints and source-to-sink flows listed in the "
        "detailed findings section. Prioritise critical and high findings for immediate code "
        "review. Each finding includes the exact vulnerable code snippet, its file location, "
        "and a before/after remediation example."
    )

    remediation_plan = (
        "1. Parameterise all SQL queries and template renderings to eliminate injection vectors.\n"
        "2. Replace insecure deserialisers (pickle, yaml.load) with safe structured formats (JSON, yaml.safe_load).\n"
        "3. Enforce CSRF tokens, rotate all hardcoded secrets to environment variables, and "
        "add security response headers (CSP, HSTS, X-Frame-Options)."
    )

    return {
        "executive_summary": exec_summary,
        "risk_assessment": risk_assessment,
        "remediation_plan": remediation_plan,
        "full_text": exec_summary,
    }
