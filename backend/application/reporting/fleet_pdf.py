"""Render the bounded, authorized fleet report as a printable PDF."""

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle


def render_fleet_pdf(report):
    output = BytesIO()
    title = "Machine evidence report" if report["scope"]["kind"] == "endpoint" else "Fleet evidence report"
    document = SimpleDocTemplate(output, pagesize=A4, topMargin=43, bottomMargin=45,
                                 leftMargin=40, rightMargin=40, title=title, author="RAVEN-X")
    styles = getSampleStyleSheet()
    styles["Title"].alignment = 0
    styles["Normal"].spaceAfter = 5

    def paragraph(value, style="Normal"):
        text = "Unavailable" if value is None else str(value)
        text = "".join(
            character for character in text
            if character in "\t\r\n" or 32 <= ord(character) < 0xD800 or 0xE000 <= ord(character) <= 0x10FFFF
        )
        return Paragraph(escape(text).replace("\n", "<br/>"), styles[style])

    def table(headers, rows, shares):
        data = [[paragraph(header, "Heading5") for header in headers]]
        data.extend([paragraph(cell, "BodyText") for cell in row] for row in rows)
        result = LongTable(data, colWidths=[document.width * part for part in shares], repeatRows=1,
                           hAlign="LEFT", splitInRow=1)
        result.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf1f3")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fa")]),
            ("LINEBELOW", (0, 0), (-1, 0), 0.55, colors.HexColor("#587480")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return result

    def label(value):
        return str(value or "unknown").replace("_", " ").capitalize()

    def timestamp(value):
        if not value:
            return "No assessment"
        try:
            stamp = datetime.fromisoformat(value)
        except ValueError:
            return value
        return (stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)).astimezone(
            timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC")

    summary = report["summary"]
    story = [
        paragraph("RAVEN-X", "Heading4"),
        paragraph(title, "Title"),
        paragraph(f"Generated {timestamp(report['generated_at'])}"),
        paragraph(report["advisory_note"]),
        paragraph("Assessment coverage", "Heading2"),
        table(("Registered", "Fully scanned", "Partial", "Without completed evidence", "Findings"),
              [(summary["total_enrolled"], summary["scanned"], summary["partial"],
                summary["not_scanned"], summary["findings_from_completed_scans"])],
              (.17, .18, .14, .29, .22)),
        paragraph("Machines", "Heading2"),
    ]
    endpoints = report["endpoints"]
    if endpoints:
        story.append(table(
            ("Machine", "Trust and presence", "Coverage", "Last attempt", "Findings"),
            [(row["hostname"], f"{label(row['lifecycle_status'])} / {label(row['presence_state'])}",
              label(row["scan_status"]), timestamp((row["latest_assessment"] or {}).get("requested_at")),
              row["findings_count"] if row["latest_assessment"] else None) for row in endpoints],
            (.24, .2, .17, .25, .14),
        ))
    else:
        story.append(paragraph("No machines are registered in this scope."))

    if report["scope"]["kind"] == "endpoint":
        for row in endpoints:
            story.append(paragraph(f"{row['hostname']} — assessment evidence", "Heading2"))
            latest = row["latest_assessment"]
            if latest:
                story.append(paragraph(f"Assessment {latest['assessment_id']}"))
            if row["scanner_results"]:
                story.append(table(("Scanner", "Outcome", "Findings"), [
                    (scanner["scanner_id"], label(scanner["status"]) + (" (error reported)" if scanner["has_error"] else ""),
                     scanner["finding_count"]) for scanner in row["scanner_results"]
                ], (.48, .35, .17)))
            if row["partial_evidence"]:
                story.append(paragraph("Coverage is incomplete. Uncollected settings remain unknown."))
            if not row["findings"]:
                story.append(paragraph("No confirmed findings are included in the returned evidence."))
            if row["findings_omitted"] or row["malformed_findings"]:
                story.append(paragraph(f"{row['findings_omitted']} omitted and {row['malformed_findings']} malformed finding records."))
            for finding in row["findings"]:
                story.extend([
                    paragraph(f"{label(finding['severity'])} — {finding['title']}", "Heading3"),
                    paragraph(finding["description"]),
                ])
                for item in finding["evidence"]:
                    for key, value in item.items():
                        story.append(paragraph(f"{label(key)}: {value}"))
                story.append(Spacer(1, 5))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#415d68"))
        canvas.drawString(doc.leftMargin, 25, title)
        canvas.drawRightString(A4[0] - doc.rightMargin, 25, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
