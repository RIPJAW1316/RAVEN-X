"""Render the bounded, authorized fleet report as a printable PDF."""

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import KeepTogether, LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle


def render_fleet_pdf(report, *, review=None):
    output = BytesIO()
    title = "Machine evidence report" if report["scope"]["kind"] == "endpoint" else "Fleet evidence report"
    if review is not None:
        title = "Reviewed machine report" if report["scope"]["kind"] == "endpoint" else "Reviewed fleet report"
    document = SimpleDocTemplate(output, pagesize=A4, topMargin=43, bottomMargin=45,
                                 leftMargin=40, rightMargin=40, title=title, author="RAVEN-X")
    styles = getSampleStyleSheet()
    styles["Title"].alignment = 0
    styles["Normal"].spaceAfter = 5
    styles["Title"].textColor = colors.HexColor("#10272e")
    styles["Heading2"].textColor = colors.HexColor("#205760")
    styles["Heading3"].textColor = colors.HexColor("#18363d")

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
    ]
    if review is not None:
        story.append(paragraph("Assessment review", "Heading2"))
        provider = {
            "lm_studio": "AI-assisted priorities via LM Studio",
            "google_cloud": "AI-assisted priorities via Google Gemini",
            "offline": "Prioritization by offline rules",
        }.get(review["provider"], "Analysis unavailable")
        if review["provider"] in {"lm_studio", "google_cloud"} and review["model"]:
            provider = f"{provider} ({review['model']})"
        story.extend([paragraph(provider, "Heading4"), paragraph(review["note"])])
        if review.get("generated_at"):
            story.append(paragraph(f"Review generated {timestamp(review['generated_at'])}"))
        if review.get("executive_summary"):
            story.extend([paragraph("Executive summary", "Heading3"), paragraph(review["executive_summary"])])
        if review["priorities"]:
            shown = len(review["priorities"])
            story.append(paragraph(f"Priority findings ({shown} of {review['finding_count']})", "Heading3"))
            story.append(table(
                ("Priority / finding", "Recommended action", "Source"),
                [(f"{index}. {label(item['severity'])} - {item['title']}",
                  f"{item['action']}\n{item['rationale']}",
                  f"{item['hostname']}\nAssessment {item['assessment_id']}")
                 for index, item in enumerate(review["priorities"], start=1)],
                (.29, .47, .24),
            ))
        if review["unverified"]:
            shown = len(review["unverified"])
            story.append(paragraph(f"Unverified checks ({shown} of {review['unverified_count']})", "Heading3"))
            story.append(table(("Machine", "Check", "Reason"),
                               [(item["hostname"], item["scanner_id"], item["reason"])
                                for item in review["unverified"]], (.24, .35, .41)))

    story.append(paragraph("Machines", "Heading2"))
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
                finding_block = [
                    paragraph(f"{label(finding['severity'])} — {finding['title']}", "Heading3"),
                    paragraph(finding["description"]),
                ]
                for item in finding["evidence"]:
                    for key, value in item.items():
                        finding_block.append(paragraph(f"{label(key)}: {value}"))
                story.append(KeepTogether([*finding_block, Spacer(1, 5)]))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#415d68"))
        canvas.drawString(doc.leftMargin, 25, title)
        canvas.drawRightString(A4[0] - doc.rightMargin, 25, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
