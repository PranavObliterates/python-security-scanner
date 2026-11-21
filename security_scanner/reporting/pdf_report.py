"""PDF Report Generator with Gemini AI per-finding analysis.

Produces a professional, multi-section security audit PDF:
  - Cover metadata and severity breakdown table
  - AI-generated executive summary and attack-surface analysis
  - Detailed findings with AI-generated, code-specific remediation
  - Per-finding corrected code blocks grounded in the actual detected snippet
"""
import os
import datetime
import xml.sax.saxutils
from typing import Optional, Any, Dict, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    KeepTogether, PageBreak, HRFlowable,
)
from reportlab.pdfgen import canvas

from ..models.scan_result import ScanResult
from ..models.finding import Finding, Severity
from .ai_advisor import (
    generate_ai_security_summary,
    generate_per_finding_analysis,
    get_session_api_key,
)


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _esc(val: Any) -> str:
    """Safely escape text for ReportLab XML/HTML Paragraph parsing."""
    if val is None:
        return ""
    return xml.sax.saxutils.escape(str(val), {'"': '&quot;'})


def _wrap_code(text: str, max_line: int = 90) -> str:
    """Word-wrap long code lines so they fit inside a fixed-width PDF column."""
    lines = []
    for raw in str(text).splitlines():
        while len(raw) > max_line:
            lines.append(raw[:max_line])
            raw = "    " + raw[max_line:]
        lines.append(raw)
    return "\n".join(lines)


class _Styles:
    """Centralised typography palette."""

    def __init__(self):
        base = getSampleStyleSheet()

        self.cover_title = ParagraphStyle(
            "CoverTitle", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=26, leading=30,
            textColor=colors.HexColor("#1A202C"),
        )
        self.cover_sub = ParagraphStyle(
            "CoverSub", parent=base["Normal"],
            fontName="Helvetica", fontSize=11, leading=15,
            textColor=colors.HexColor("#4A5568"),
        )
        self.h1 = ParagraphStyle(
            "H1", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=15, leading=19,
            textColor=colors.HexColor("#2B6CB0"),
            spaceBefore=14, spaceAfter=5,
        )
        self.h2 = ParagraphStyle(
            "H2", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=11, leading=15,
            textColor=colors.HexColor("#2D3748"),
            spaceBefore=8, spaceAfter=3,
        )
        self.h3 = ParagraphStyle(
            "H3", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=9.5, leading=13,
            textColor=colors.HexColor("#4A5568"),
            spaceBefore=5, spaceAfter=2,
        )
        self.body = ParagraphStyle(
            "Body", parent=base["Normal"],
            fontName="Helvetica", fontSize=9.5, leading=13.5,
            textColor=colors.HexColor("#2D3748"),
        )
        self.body_sm = ParagraphStyle(
            "BodySm", parent=base["Normal"],
            fontName="Helvetica", fontSize=8.5, leading=12,
            textColor=colors.HexColor("#4A5568"),
        )
        self.code_dark = ParagraphStyle(
            "CodeDark", parent=base["Normal"],
            fontName="Courier", fontSize=8, leading=11,
            textColor=colors.HexColor("#E2E8F0"),
        )
        self.code_light = ParagraphStyle(
            "CodeLight", parent=base["Normal"],
            fontName="Courier", fontSize=8, leading=11,
            textColor=colors.HexColor("#2D3748"),
        )
        self.ai_badge = ParagraphStyle(
            "AIBadge", parent=base["Normal"],
            fontName="Helvetica-Oblique", fontSize=8, leading=11,
            textColor=colors.HexColor("#553C9A"),
        )
        self.tag_red = ParagraphStyle(
            "TagRed", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=8.5,
            textColor=colors.HexColor("#E53E3E"),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Canvas with page numbers + header/footer
# ─────────────────────────────────────────────────────────────────────────────

class _NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_decorations(total)
            super().showPage()
        super().save()

    def _draw_decorations(self, total: int):
        self.saveState()
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#718096"))

        if self._pageNumber > 1:
            self.drawString(54, letter[1] - 34, "WEBVENOM — APPLICATION SECURITY ASSESSMENT REPORT")
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.4)
            self.line(54, letter[1] - 40, letter[0] - 54, letter[1] - 40)

        self.drawRightString(letter[0] - 54, 34, f"Page {self._pageNumber} of {total}")
        self.drawString(54, 34, "CONFIDENTIAL — FOR INTERNAL SECURITY REMEDIATION ONLY")
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.4)
        self.line(54, 44, letter[0] - 54, 44)
        self.restoreState()


# ─────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ─────────────────────────────────────────────────────────────────────────────

_SEV_COLOR = {
    Severity.CRITICAL: colors.HexColor("#E53E3E"),
    Severity.HIGH:     colors.HexColor("#DD6B20"),
    Severity.MEDIUM:   colors.HexColor("#D69E2E"),
    Severity.LOW:      colors.HexColor("#3182CE"),
    Severity.INFO:     colors.HexColor("#718096"),
}

_SEV_BG = {
    Severity.CRITICAL: colors.HexColor("#FFF5F5"),
    Severity.HIGH:     colors.HexColor("#FFFAF0"),
    Severity.MEDIUM:   colors.HexColor("#FFFFF0"),
    Severity.LOW:      colors.HexColor("#EBF8FF"),
    Severity.INFO:     colors.HexColor("#F7FAFC"),
}

_SEV_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1,
    Severity.MEDIUM: 2,   Severity.LOW: 3, Severity.INFO: 4,
}


def _grade(result: ScanResult) -> str:
    if result.critical_count > 0:   return "F  —  Critical Risk"
    if result.high_count > 2:        return "D  —  High Risk"
    if result.high_count > 0:        return "C  —  Moderate Risk"
    if result.medium_count > 0:      return "B  —  Low Risk"
    return "A  —  Secure"


# ─────────────────────────────────────────────────────────────────────────────
# Section builders
# ─────────────────────────────────────────────────────────────────────────────

def _build_cover(result: ScanResult, s: _Styles, ai_active: bool) -> list:
    now = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M")
    grade = _grade(result)
    story = [
        Paragraph("SECURITY AUDIT REPORT", s.cover_title),
        Spacer(1, 6),
        Paragraph(
            f"Target: <b>{_esc(result.app_name)}</b> &nbsp;|&nbsp; "
            f"SAST + DAST  &nbsp;|&nbsp;  OWASP Top 10 (2021)",
            s.cover_sub,
        ),
        Spacer(1, 16),
    ]

    meta = [
        [
            Paragraph(f"<b>Scan Date:</b> {_esc(now)}", s.body),
            Paragraph(f"<b>Routes Scanned:</b> {result.routes_scanned}", s.body),
        ],
        [
            Paragraph(f"<b>Duration:</b> {result.scan_duration_seconds:.2f}s", s.body),
            Paragraph(f"<b>Overall Posture:</b> <b>{_esc(grade)}</b>", s.body),
        ],
        [
            Paragraph(
                f"<b>AI Analysis:</b> {'Gemini 2.5 Flash' if ai_active else 'Rule Engine (no key)'}",
                s.body,
            ),
            Paragraph(f"<b>Tool:</b> WebVenom Security Scanner", s.body),
        ],
    ]
    t = Table(meta, colWidths=[252, 252])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ("BOX",        (0, 0), (-1, -1), 1,   colors.HexColor("#E2E8F0")),
        ("INNERGRID",  (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
        ("PADDING",    (0, 0), (-1, -1), 7),
    ]))
    story += [t, Spacer(1, 16)]
    return story


def _build_severity_table(result: ScanResult, s: _Styles) -> list:
    story = [Paragraph("Vulnerability Severity Breakdown", s.h1)]
    rows = [
        ["Severity", "Count", "Risk Level", "Response SLA"],
        ["CRITICAL", str(result.critical_count), "Urgent",   "Patch within 24 hours"],
        ["HIGH",     str(result.high_count),     "Severe",   "Remediate in current sprint"],
        ["MEDIUM",   str(result.medium_count),   "Moderate", "Address in release cycle"],
        ["LOW / INFO", str(result.low_count),    "Minor",    "Harden as best practice"],
        ["TOTAL",    str(len(result.findings)),  "—",        result.summary()],
    ]
    t = Table(rows, colWidths=[80, 55, 90, 279])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),  colors.HexColor("#2B6CB0")),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("ALIGN",      (0, 0), (-1, -1), "LEFT"),
        ("TEXTCOLOR",  (0, 1), (0, 1),   colors.HexColor("#E53E3E")),
        ("TEXTCOLOR",  (0, 2), (0, 2),   colors.HexColor("#DD6B20")),
        ("TEXTCOLOR",  (0, 3), (0, 3),   colors.HexColor("#D69E2E")),
        ("TEXTCOLOR",  (0, 4), (0, 4),   colors.HexColor("#3182CE")),
        ("FONTNAME",   (0, 1), (0, -1),  "Helvetica-Bold"),
        ("FONTNAME",   (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#EDF2F7")),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("PADDING",    (0, 0), (-1, -1), 5),
    ]))
    story += [t, Spacer(1, 16)]
    return story


def _build_ai_summary(ai: Dict[str, str], s: _Styles, ai_active: bool) -> list:
    badge = "Gemini 2.5 Flash" if ai_active else "Expert Rule Engine"
    story = [Paragraph(f"Executive Security Insights  <font color='#553C9A' size='9'>({badge})</font>", s.h1)]

    for section_key, label in [
        ("executive_summary",  "1. Executive Summary"),
        ("risk_assessment",    "2. Attack Surface &amp; Risk Analysis"),
        ("remediation_plan",   "3. Prioritised Remediation Roadmap"),
    ]:
        story.append(Paragraph(f"<b>{label}</b>", s.h2))
        content = ai.get(section_key, "")
        for para in content.split("\n\n"):
            para = para.strip()
            if not para:
                continue
            # Render numbered list items with a slight indent
            if para[0].isdigit() and ". " in para[:4]:
                story.append(Paragraph(_esc(para).replace("\n", "<br/>"), s.body_sm))
            else:
                story.append(Paragraph(_esc(para).replace("\n", "<br/>"), s.body))
            story.append(Spacer(1, 4))

    story.append(Spacer(1, 10))
    return story


def _build_code_box(code: str, s: _Styles, dark: bool = True) -> Table:
    """Render a code block as a dark (vulnerable) or light (fixed) table cell."""
    wrapped = _wrap_code(code)
    style = s.code_dark if dark else s.code_light
    bg = colors.HexColor("#1A202C") if dark else colors.HexColor("#F0FFF4")
    border = colors.HexColor("#0D1117") if dark else colors.HexColor("#9AE6B4")
    t = Table(
        [[Paragraph(_esc(wrapped).replace("\n", "<br/>"), style)]],
        colWidths=[504],
    )
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX",        (0, 0), (-1, -1), 1, border),
        ("PADDING",    (0, 0), (-1, -1), 6),
    ]))
    return t


def _build_findings(
    result: ScanResult,
    per_finding_ai: Dict[int, Dict[str, str]],
    s: _Styles,
) -> list:
    story = [
        Paragraph("Detailed Vulnerability Findings", s.h1),
        Spacer(1, 6),
    ]

    if not result.findings:
        story.append(Paragraph("No vulnerabilities identified during this security scan.", s.body))
        return story

    sorted_findings = sorted(
        enumerate(result.findings),
        key=lambda x: (_SEV_ORDER.get(x[1].severity, 99), x[1].vuln_type.value),
    )

    for display_num, (orig_idx, f) in enumerate(sorted_findings, 1):
        sev_col = _SEV_COLOR.get(f.severity, colors.HexColor("#718096"))
        sev_bg  = _SEV_BG.get(f.severity,   colors.HexColor("#F7FAFC"))
        ai_data = per_finding_ai.get(orig_idx)

        blocks = []

        # ── Finding header ────────────────────────────────────────────
        header = (
            f"<b>#{display_num} &nbsp; [{_esc(f.severity.value)}] &nbsp; "
            f"{_esc(f.vuln_type.value)}</b>"
            f"<font color='{sev_col.hexval()}'> &nbsp; {_esc(f.vuln_type.owasp_category)}</font>"
            f" &nbsp; <font size='8' color='#718096'>({_esc(f.source)})</font>"
        )

        loc_row = Table(
            [[
                Paragraph(f"<b>Endpoint:</b> {_esc(f.endpoint)}", s.body_sm),
                Paragraph(f"<b>File:</b> {_esc(f.file)}:{f.line}", s.body_sm),
            ]],
            colWidths=[252, 252],
        )
        loc_row.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_bg),
            ("BOX",        (0, 0), (-1, -1), 0.5, sev_col),
            ("PADDING",    (0, 0), (-1, -1), 4),
        ]))

        blocks.append(KeepTogether([
            Paragraph(header, s.h2),
            loc_row,
        ]))
        blocks.append(Spacer(1, 5))

        # ── Detected code ─────────────────────────────────────────────
        if f.code_snippet:
            blocks.append(Paragraph("<b>Detected Vulnerable Code:</b>", s.h3))
            blocks.append(_build_code_box(f.code_snippet, s, dark=True))
            blocks.append(Spacer(1, 5))

        # ── Scanner explanation ───────────────────────────────────────
        if f.explanation:
            blocks.append(Paragraph(
                f"<b>Risk Explanation:</b> {_esc(f.explanation)}", s.body
            ))
            blocks.append(Spacer(1, 4))

        # ── AI deep-dive analysis (per-finding) ───────────────────────
        if ai_data:
            blocks.append(Paragraph(
                "<b>AI Security Analysis</b> "
                "<font color='#553C9A' size='8'>(Gemini 2.5 Flash — grounded in detected code)</font>",
                s.h3,
            ))

            if ai_data.get("technical_detail"):
                blocks.append(Paragraph(
                    _esc(ai_data["technical_detail"]).replace("\n", "<br/>"), s.body_sm
                ))
                blocks.append(Spacer(1, 5))

            if ai_data.get("fixed_code"):
                blocks.append(Paragraph("<b>Corrected Implementation:</b>", s.h3))
                blocks.append(_build_code_box(ai_data["fixed_code"], s, dark=False))
                blocks.append(Spacer(1, 4))

            if ai_data.get("why_fix_works"):
                blocks.append(Paragraph(
                    f"<b>Why This Fix Works:</b> {_esc(ai_data['why_fix_works']).replace(chr(10), '<br/>')}",
                    s.body_sm,
                ))
                blocks.append(Spacer(1, 4))

            if ai_data.get("owasp_context"):
                blocks.append(Paragraph(
                    f"<b>OWASP &amp; CWE:</b> {_esc(ai_data['owasp_context']).replace(chr(10), '<br/>')}",
                    s.body_sm,
                ))
                blocks.append(Spacer(1, 4))

        else:
            # Fallback: scanner's own fix_before / fix_after
            if f.fix_recommendation:
                blocks.append(Paragraph(
                    f"<b>Remediation:</b> {_esc(f.fix_recommendation)}", s.body
                ))
            if f.fix_before or f.fix_after:
                fix_rows = []
                if f.fix_before:
                    fix_rows.append([
                        Paragraph("<b>Vulnerable:</b>", s.body_sm),
                        Paragraph(f"<code>{_esc(f.fix_before).replace(chr(10), '<br/>')}</code>", s.body_sm),
                    ])
                if f.fix_after:
                    fix_rows.append([
                        Paragraph("<b>Fixed:</b>", s.body_sm),
                        Paragraph(f"<code>{_esc(f.fix_after).replace(chr(10), '<br/>')}</code>", s.body_sm),
                    ])
                ft = Table(fix_rows, colWidths=[70, 434])
                ft.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EDF2F7")),
                    ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("PADDING",    (0, 0), (-1, -1), 4),
                ]))
                blocks.append(Spacer(1, 4))
                blocks.append(ft)

        if f.reference:
            blocks.append(Spacer(1, 2))
            blocks.append(Paragraph(
                f"<b>Reference:</b> <font color='#2B6CB0'>{_esc(f.reference)}</font>",
                s.body_sm,
            ))

        blocks.append(HRFlowable(width="100%", thickness=0.4, color=colors.HexColor("#E2E8F0")))
        blocks.append(Spacer(1, 10))

        for b in blocks:
            story.append(b)

    return story


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def save_pdf_report(
    result: ScanResult,
    filepath: str = "security_report.pdf",
    api_key: Optional[str] = None,
    prompt_for_key: bool = False,
) -> str:
    """Generate and save a professional PDF security audit report.

    With a Gemini API key the report includes:
      - Grounded executive summary and attack-surface analysis (whole scan)
      - Per-finding AI analysis with a corrected code implementation,
        explanation of why the fix works, and OWASP/CWE mapping

    Without a key all sections fall back to rules-based content derived
    directly from the scanner's findings.

    Args:
        result:          ScanResult from scanning the application.
        filepath:        Destination PDF path.
        api_key:         Session-only Gemini key (never saved to disk).
        prompt_for_key:  If True, prompt interactively when key is absent.

    Returns:
        The output filepath.
    """
    key = get_session_api_key(api_key, prompt_if_missing=prompt_for_key)
    ai_active = bool(key)

    # ── Fetch AI content (can take a few seconds per finding) ────────
    ai_summary = generate_ai_security_summary(result, api_key=key)
    per_finding_ai: Dict[int, Dict[str, str]] = {}
    if ai_active:
        per_finding_ai = generate_per_finding_analysis(
            result.findings, result.app_name, api_key=key
        )

    s = _Styles()

    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        leftMargin=54, rightMargin=54,
        topMargin=54,  bottomMargin=54,
    )

    story: list = []
    story += _build_cover(result, s, ai_active)
    story += _build_severity_table(result, s)
    story += _build_ai_summary(ai_summary, s, ai_active)
    story.append(PageBreak())
    story += _build_findings(result, per_finding_ai, s)

    doc.build(story, canvasmaker=_NumberedCanvas)
    return filepath
