"""PDF Report Generator with Gemini AI Security Advisor integration.

Generates professional, styled security audit reports for stakeholders and engineers.
"""
import os
import datetime
from typing import Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak
)
from reportlab.pdfgen import canvas

from ..models.scan_result import ScanResult
from ..models.finding import Severity
from .ai_advisor import generate_ai_security_summary, get_session_api_key


class NumberedCanvas(canvas.Canvas):
    """Custom canvas that adds page numbers and running header/footer."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#718096"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, letter[1] - 36, "PYSECURE — APPLICATION SECURITY ASSESSMENT REPORT")
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # Running Footer
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(letter[0] - 54, 36, page_str)
        self.drawString(54, 36, "CONFIDENTIAL — FOR INTERNAL SECURITY REMEDIATION ONLY")
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(54, 46, letter[0] - 54, 46)

        self.restoreState()


def _get_severity_color(severity: Severity) -> colors.Color:
    mapping = {
        Severity.CRITICAL: colors.HexColor("#E53E3E"),
        Severity.HIGH: colors.HexColor("#DD6B20"),
        Severity.MEDIUM: colors.HexColor("#D69E2E"),
        Severity.LOW: colors.HexColor("#3182CE"),
        Severity.INFO: colors.HexColor("#718096"),
    }
    return mapping.get(severity, colors.HexColor("#718096"))


def _compute_grade(result: ScanResult) -> str:
    if result.critical_count > 0:
        return "F (Critical Risk)"
    elif result.high_count > 2:
        return "D (High Risk)"
    elif result.high_count > 0:
        return "C (Moderate Risk)"
    elif result.medium_count > 0:
        return "B (Low Risk)"
    return "A (Secure)"


def save_pdf_report(
    result: ScanResult,
    filepath: str = "security_report.pdf",
    api_key: Optional[str] = None,
    prompt_for_key: bool = False
) -> str:
    """Generate and save a professional PDF security report.

    Args:
        result: The ScanResult from scanning the application.
        filepath: Destination file path for the PDF report.
        api_key: Optional session-only Gemini API key (never saved to disk).
        prompt_for_key: If True, prompt for API key from terminal if not already provided.

    Returns:
        The output filepath.
    """
    key = get_session_api_key(api_key, prompt_if_missing=prompt_for_key)
    ai_insights = generate_ai_security_summary(result, api_key=key)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#1A202C"),
    )

    subtitle_style = ParagraphStyle(
        "CoverSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#4A5568"),
    )

    h1_style = ParagraphStyle(
        "Heading1_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#2B6CB0"),
        spaceBefore=12,
        spaceAfter=6,
    )

    h2_style = ParagraphStyle(
        "Heading2_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#2D3748"),
        spaceBefore=8,
        spaceAfter=4,
    )

    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#2D3748"),
    )

    code_style = ParagraphStyle(
        "Code_Custom",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#E2E8F0"),
    )

    story = []

    # ─────────────────────────────────────────────────────────────
    # COVER / HEADER BANNER
    # ─────────────────────────────────────────────────────────────
    story.append(Paragraph("SECURITY AUDIT REPORT", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Target Application: <b>{result.app_name}</b> | SAST & DAST OWASP Top 10 Scan", subtitle_style))
    story.append(Spacer(1, 14))

    # Meta Overview Box
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    grade = _compute_grade(result)
    meta_data = [
        [
            Paragraph(f"<b>Scan Date:</b> {now_str}", body_style),
            Paragraph(f"<b>Routes Scanned:</b> {result.routes_scanned}", body_style),
        ],
        [
            Paragraph(f"<b>Duration:</b> {result.scan_duration_seconds:.2f} seconds", body_style),
            Paragraph(f"<b>Overall Posture:</b> <b>{grade}</b>", body_style),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[250, 250])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # ─────────────────────────────────────────────────────────────
    # METRICS TABLE
    # ─────────────────────────────────────────────────────────────
    story.append(Paragraph("Vulnerability Severity Breakdown", h1_style))
    metrics_data = [
        ["Severity", "Findings Count", "Risk Level", "Action Required"],
        ["CRITICAL", str(result.critical_count), "Urgent", "Immediate patch required (within 24 hours)"],
        ["HIGH", str(result.high_count), "Severe", "Remediate in current sprint"],
        ["MEDIUM", str(result.medium_count), "Moderate", "Address during regular release cycle"],
        ["LOW / INFO", str(result.low_count), "Minor", "Harden configuration best practices"],
        ["TOTAL", str(len(result.findings)), "-", f"{result.summary()}"],
    ]
    metrics_table = Table(metrics_data, colWidths=[90, 90, 80, 240])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor("#E53E3E")),
        ("TEXTCOLOR", (0, 2), (0, 2), colors.HexColor("#DD6B20")),
        ("TEXTCOLOR", (0, 3), (0, 3), colors.HexColor("#D69E2E")),
        ("TEXTCOLOR", (0, 4), (0, 4), colors.HexColor("#3182CE")),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#EDF2F7")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 14))

    # ─────────────────────────────────────────────────────────────
    # GEMINI AI EXECUTIVE SUMMARY & THREAT ANALYSIS
    # ─────────────────────────────────────────────────────────────
    ai_badge = " (Powered by Gemini AI)" if key else " (Expert Rule Engine)"
    story.append(Paragraph(f"Executive Security Insights{ai_badge}", h1_style))

    story.append(Paragraph("<b>1. Executive Summary:</b>", h2_style))
    for p in ai_insights["executive_summary"].split("\n\n"):
        if p.strip():
            story.append(Paragraph(p.strip().replace("\n", "<br/>"), body_style))
            story.append(Spacer(1, 4))

    story.append(Paragraph("<b>2. Threat & Attack Surface Analysis:</b>", h2_style))
    for p in ai_insights["risk_assessment"].split("\n\n"):
        if p.strip():
            story.append(Paragraph(p.strip().replace("\n", "<br/>"), body_style))
            story.append(Spacer(1, 4))

    story.append(Paragraph("<b>3. Prioritized Remediation Roadmap:</b>", h2_style))
    for p in ai_insights["remediation_plan"].split("\n\n"):
        if p.strip():
            story.append(Paragraph(p.strip().replace("\n", "<br/>"), body_style))
            story.append(Spacer(1, 4))

    story.append(Spacer(1, 14))

    # ─────────────────────────────────────────────────────────────
    # DETAILED VULNERABILITY FINDINGS
    # ─────────────────────────────────────────────────────────────
    story.append(Paragraph("Detailed Vulnerability Findings", h1_style))
    story.append(Spacer(1, 6))

    if not result.findings:
        story.append(Paragraph("No vulnerabilities were identified during this security scan.", body_style))
    else:
        # Group by severity order
        sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_findings = sorted(result.findings, key=lambda f: (sev_order.get(f.severity, 99), f.vuln_type.value))

        for idx, finding in enumerate(sorted_findings, 1):
            finding_blocks = []
            sev_color = _get_severity_color(finding.severity)

            header_text = (
                f"<b>#{idx}. [{finding.severity.value}] {finding.vuln_type.value}</b> "
                f"— <font color='{sev_color.hexval()}'><b>{finding.vuln_type.owasp_category}</b></font> "
                f"({finding.source})"
            )
            finding_blocks.append(Paragraph(header_text, h2_style))

            details_data = [
                [
                    Paragraph(f"<b>Endpoint:</b> {finding.endpoint}", body_style),
                    Paragraph(f"<b>Location:</b> {finding.file}:{finding.line}", body_style),
                ]
            ]
            d_table = Table(details_data, colWidths=[250, 250])
            d_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]))
            finding_blocks.append(d_table)
            finding_blocks.append(Spacer(1, 4))

            # Code snippet box if present
            if finding.code_snippet:
                snippet_table = Table(
                    [[Paragraph(f"<code>{finding.code_snippet}</code>", code_style)]],
                    colWidths=[500]
                )
                snippet_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#2D3748")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#1A202C")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]))
                finding_blocks.append(snippet_table)
                finding_blocks.append(Spacer(1, 4))

            # Explanation
            finding_blocks.append(Paragraph(f"<b>Risk Explanation:</b> {finding.explanation}", body_style))
            finding_blocks.append(Spacer(1, 3))

            # Fix recommendation
            finding_blocks.append(Paragraph(f"<b>Remediation:</b> {finding.fix_recommendation}", body_style))

            # Before / After patch if available
            if finding.fix_before or finding.fix_after:
                fix_data = []
                if finding.fix_before:
                    fix_data.append([Paragraph("<b>Vulnerable:</b>", body_style), Paragraph(f"<code>{finding.fix_before}</code>", body_style)])
                if finding.fix_after:
                    fix_data.append([Paragraph("<b>Recommended:</b>", body_style), Paragraph(f"<code>{finding.fix_after}</code>", body_style)])
                fix_table = Table(fix_data, colWidths=[90, 410])
                fix_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EDF2F7")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("PADDING", (0, 0), (-1, -1), 3),
                ]))
                finding_blocks.append(Spacer(1, 3))
                finding_blocks.append(fix_table)

            if finding.reference:
                finding_blocks.append(Spacer(1, 2))
                finding_blocks.append(Paragraph(f"<b>Reference:</b> <font color='#2B6CB0'>{finding.reference}</font>", body_style))

            finding_blocks.append(Spacer(1, 8))
            story.append(KeepTogether(finding_blocks))

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
    return filepath
