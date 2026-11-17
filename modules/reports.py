"""Executive HTML/PDF reports from selected tenant evidence."""
import io
from html import escape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import landscape, A4


def build_report(records, summary, tenant_id, period):
    styles = getSampleStyleSheet()
    columns = ["Timestamp", "Target UPN", "Attack vector", "Severity", "Response"]
    values = [[str(row.get("created_at", "")), str(row.get("TargetUserName", "")), str(row.get("attack_type") or row.get("AuthMethod", "Unknown")), str(row.get("severity", "Unknown")), str(row.get("status", "New")) + ": " + str(row.get("action_taken") or "None")] for row in records]
    high = sum(str(row.get("severity", "")).lower() in {"high", "critical"} for row in records)
    unresolved = sum(row.get("status") != "Remediated" for row in records)
    recommendations = f"Review {unresolved} unresolved records. Prioritize {high} high or critical records. Validate MFA and conditional access for observed target accounts. Retain response evidence for compliance review; telemetry alone does not establish compliance."
    heading = "Argus ITDR Security Audit Report"
    metadata = f"Tenant: {tenant_id} | Period: {period} | Records: {len(records)}"
    markup = "<h1>" + heading + "</h1><p>" + escape(metadata) + "</p><h2>Executive Summary</h2><p>" + escape(summary) + "</p><h2>Incident Breakdown</h2><table><thead><tr>" + "".join("<th>" + c + "</th>" for c in columns) + "</tr></thead><tbody>" + "".join("<tr>" + "".join("<td>" + escape(cell) + "</td>" for cell in row) + "</tr>" for row in values) + "</tbody></table><h2>Compliance &amp; Posture Recommendations</h2><p>" + escape(recommendations) + "</p>"
    output = io.BytesIO()
    story = [Paragraph(heading, styles["Title"]), Paragraph(escape(metadata), styles["Normal"]), Spacer(1, 16), Paragraph("Executive Summary", styles["Heading2"]), Paragraph(escape(summary), styles["Normal"]), Paragraph("Incident Breakdown", styles["Heading2"])]
    data = [[Paragraph(escape(cell), styles["Normal"]) for cell in row] for row in [columns] + values]
    table = Table(data, repeatRows=1, colWidths=[140, 175, 145, 65, 220])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dce8f0")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), .3, colors.lightgrey)]))
    story.extend([table, Paragraph("Compliance & Posture Recommendations", styles["Heading2"]), Paragraph(escape(recommendations), styles["Normal"])])
    SimpleDocTemplate(output, pagesize=landscape(A4), rightMargin=30, leftMargin=30).build(story)
    return markup, output.getvalue()
