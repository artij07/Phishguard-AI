import json
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def build_report_document(scan_record: dict) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title="PhishGuard AI Report")
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("PhishGuard AI", styles["Title"]))
    story.append(Paragraph("Threat Analysis Report", styles["Heading2"]))
    story.append(Spacer(1, 12))

    scan_meta = [
        ("Scan ID", scan_record.get("scan_id", "N/A")),
        ("Scanner Type", scan_record.get("scanner_type", "N/A")),
        ("Risk Score", f"{scan_record.get('risk_score', 0)}/100"),
        ("Threat Level", scan_record.get("threat_level", "LOW RISK")),
        ("Confidence Score", f"{scan_record.get('confidence_score', 0)}/100"),
        ("Created", scan_record.get("created_at", "N/A")),
    ]

    table = Table(scan_meta, colWidths=[140, 320])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.8, colors.HexColor("#1e293b")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 18))

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(scan_record.get("summary", "No summary available."), styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Findings", styles["Heading2"]))
    for item in scan_record.get("findings", []):
        story.append(Paragraph(f"• {item}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Recommended Remediation", styles["Heading2"]))
    for item in scan_record.get("recommendations", []):
        story.append(Paragraph(f"• {item}", styles["BodyText"]))

    story.append(Spacer(1, 18))
    story.append(Paragraph("Threat Intelligence Sources: Local deterministic rules, URL heuristics, and content analysis.", styles["BodyText"]))
    story.append(Paragraph("AI Assessment: Available only when configured in the environment; otherwise AI support is marked as unavailable.", styles["BodyText"]))
    doc.build(story)
    return buffer.getvalue()
