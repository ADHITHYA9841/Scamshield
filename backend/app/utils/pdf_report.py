import io
import re
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from app.models.schemas import StandardResult


def mask_sensitive_data(text: str) -> str:
    """Masks phone numbers, card digits, and email usernames for privacy."""
    # Mask Indian 10-digit phone numbers
    text = re.sub(r'(\b[6-9]\d{2})\d{4}(\d{3}\b)', r'\1****\2', text)
    # Mask Credit/Debit card numbers
    text = re.sub(r'(\b\d{4})[\s-]?\d{4}[\s-]?\d{4}[\s-]?(\d{4}\b)', r'\1-****-****-\2', text)
    # Mask Aadhaar numbers
    text = re.sub(r'(\b\d{4})[\s-]?\d{4}[\s-]?(\d{4}\b)', r'XXXX-XXXX-\2', text)
    return text


def generate_pdf_report(result: StandardResult) -> bytes:
    """
    Generates a formal PDF Incident Investigation Report for ScamShield analysis.
    Returns bytes buffer of the PDF file.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#475569'),
        spaceAfter=15
    )
    section_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=8
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155')
    )

    story = []

    # Title & Header
    story.append(Paragraph("🛡 ScamShield Forensic Assessment Report", title_style))
    story.append(Paragraph(f"Scan Reference: <b>{result.scan_id}</b> | Timestamp: {result.timestamp}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#CBD5E1"), spaceAfter=15))

    # Summary Table with Verdict and Risk Score
    verdict_color = "#DC2626" if result.verdict == "SCAM" else ("#F59E0B" if result.verdict == "SUSPICIOUS" else "#16A34A")
    summary_data = [
        [Paragraph("<b>Assessment Metric</b>", body_style), Paragraph("<b>Finding / Value</b>", body_style)],
        [Paragraph("Verdict", body_style), Paragraph(f"<font color='{verdict_color}'><b>{result.verdict}</b></font>", body_style)],
        [Paragraph("ScamShield Risk Score", body_style), Paragraph(f"<b>{result.risk_score} / 100</b>", body_style)],
        [Paragraph("Confidence Level", body_style), Paragraph(f"{int(result.confidence * 100)}%", body_style)],
        [Paragraph("Identified Threat Category", body_style), Paragraph(f"<b>{result.scam_type}</b>", body_style)],
        [Paragraph("Input Classification", body_style), Paragraph(result.input_type.upper(), body_style)],
        [Paragraph("Language Detected", body_style), Paragraph(result.language.upper(), body_style)],
    ]

    t_summary = Table(summary_data, colWidths=[180, 340])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 15))

    # Explanation Section
    story.append(Paragraph("Executive Summary & Analysis", section_style))
    clean_explanation = mask_sensitive_data(result.explanation)
    story.append(Paragraph(clean_explanation, body_style))
    story.append(Spacer(1, 15))

    # Evidence Items Table
    story.append(Paragraph("Identified Risk Indicators & Forensic Evidence", section_style))
    evidence_rows = [
        [Paragraph("<b>Indicator</b>", body_style), Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Source</b>", body_style), Paragraph("<b>Evidence Snippet</b>", body_style)]
    ]

    if result.evidence:
        for ev in result.evidence[:8]:  # Limit top 8 for clean layout
            clean_snippet = mask_sensitive_data(ev.evidence[:80])
            evidence_rows.append([
                Paragraph(ev.type, body_style),
                Paragraph(ev.severity.upper(), body_style),
                Paragraph(ev.source.upper(), body_style),
                Paragraph(clean_snippet, body_style)
            ])
    else:
        evidence_rows.append([Paragraph("None", body_style), Paragraph("LOW", body_style), Paragraph("N/A", body_style), Paragraph("No indicators triggered", body_style)])

    t_evidence = Table(evidence_rows, colWidths=[110, 65, 65, 280])
    t_evidence.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_evidence)
    story.append(Spacer(1, 15))

    # Recommended Actions
    story.append(Paragraph("Recommended Protective Actions", section_style))
    for action in result.recommended_actions:
        story.append(Paragraph(f"• {action}", body_style))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0"), spaceAfter=10))

    # Legal Disclaimer
    disclaimer_text = (
        "<b>Disclaimer:</b> ScamShield provides an automated security assessment using multi-engine heuristics, "
        "reputation signals, and language models. It cannot guarantee 100% detection or safety. "
        "Sensitive personal data has been masked for privacy in this export."
    )
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#64748B')
    )
    story.append(Paragraph(disclaimer_text, disclaimer_style))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
