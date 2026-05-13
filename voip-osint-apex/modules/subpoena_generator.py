"""
Automated Subpoena PDF Generator
Produces a properly formatted legal document for LEA use.
Requires: reportlab
"""

import os
import hashlib
import logging
from datetime import datetime
from pathlib import Path

# pyrefly: ignore [missing-import]
from reportlab.lib.pagesizes  import LETTER
# pyrefly: ignore [missing-import]
from reportlab.lib.styles     import getSampleStyleSheet, ParagraphStyle
# pyrefly: ignore [missing-import]
from reportlab.lib.units       import inch
# pyrefly: ignore [missing-import]
from reportlab.lib             import colors
# pyrefly: ignore [missing-import]
from reportlab.platypus        import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable,
)

log = logging.getLogger("subpoena_generator")

OUTPUT_DIR = Path("outputs/subpoenas")


def generate_subpoena(data: dict) -> str:
    """
    Generate a formatted subpoena PDF.

    data keys:
        case_id, number, platform, ip, domain,
        date_range_start, date_range_end,
        agency_name, officer_name, badge_number,
        requested_records (list[str])
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    case_id  = data.get("case_id", "UNKNOWN")
    ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = str(OUTPUT_DIR / f"subpoena_{case_id}_{ts}.pdf")

    doc   = SimpleDocTemplate(out_path, pagesize=LETTER,
                               topMargin=1*inch, bottomMargin=1*inch)
    story = _build_story(data)
    doc.build(story)

    # SHA-256 integrity hash
    sha = _sha256(out_path)
    log.info(f"[Subpoena] Generated: {out_path}  SHA-256: {sha}")
    return out_path


# ── story builder ────────────────────────────────────────────

def _build_story(data: dict) -> list:
    styles   = getSampleStyleSheet()
    story    = []

    TITLE    = ParagraphStyle("Title",    fontSize=14, fontName="Helvetica-Bold",
                              spaceAfter=6, alignment=1)
    HEADING  = ParagraphStyle("Heading",  fontSize=11, fontName="Helvetica-Bold",
                              spaceAfter=4, spaceBefore=10)
    BODY     = ParagraphStyle("Body",     fontSize=10, fontName="Helvetica",
                              spaceAfter=4, leading=14)
    SMALL    = ParagraphStyle("Small",    fontSize=8,  fontName="Helvetica",
                              textColor=colors.grey)

    now  = datetime.utcnow().strftime("%B %d, %Y")
    case = data.get("case_id", "N/A")

    # Header block
    story += [
        Paragraph("LAW ENFORCEMENT REQUEST FOR RECORDS", TITLE),
        Paragraph(f"Case Reference: {case}", TITLE),
        HRFlowable(width="100%", thickness=2, color=colors.black),
        Spacer(1, 0.15*inch),
    ]

    # Addressee
    platform = data.get("platform", "[Service Provider]")
    story += [
        Paragraph(f"To: Legal Department — {platform}", HEADING),
        Paragraph(f"Date: {now}", BODY),
        Paragraph(
            f"From: {data.get('officer_name','[Officer Name]')}, "
            f"Badge #{data.get('badge_number','N/A')}, "
            f"{data.get('agency_name','[Agency Name]')}",
            BODY,
        ),
        Spacer(1, 0.15*inch),
    ]

    # Subject
    story += [
        Paragraph("Subject of Investigation", HEADING),
        _kv_table([
            ("Virtual Number",   data.get("number",  "N/A")),
            ("IP Address",       data.get("ip",      "N/A")),
            ("Domain",           data.get("domain",  "N/A")),
            ("Date Range Start", data.get("date_range_start", "N/A")),
            ("Date Range End",   data.get("date_range_end",   "N/A")),
        ]),
        Spacer(1, 0.15*inch),
    ]

    # Requested records
    records = data.get("requested_records") or [
        "Account registration IP address and timestamp",
        "Device fingerprint, IMEI, and hardware identifiers",
        "Payment records and billing information",
        "Full login history with timestamps and source IPs",
        "SIP registration logs for the specified number",
        "Any linked accounts or associated phone numbers",
    ]
    story += [
        Paragraph("Requested Records", HEADING),
    ]
    for i, rec in enumerate(records, 1):
        story.append(Paragraph(f"{i}. {rec}", BODY))

    # Legal basis
    story += [
        Spacer(1, 0.15*inch),
        Paragraph("Legal Basis", HEADING),
        Paragraph(
            "This request is made pursuant to applicable law enforcement "
            "authority. The records requested are necessary for an active "
            "criminal investigation. Please respond within 72 hours or "
            "contact the requesting officer for emergency provisions.",
            BODY,
        ),
        Spacer(1, 0.3*inch),
    ]

    # Signature block
    story += [
        HRFlowable(width="40%", thickness=1, color=colors.black, hAlign="LEFT"),
        Paragraph(data.get("officer_name", "[Officer Name]"), BODY),
        Paragraph(data.get("agency_name",  "[Agency Name]"),  BODY),
        Spacer(1, 0.3*inch),
        Paragraph(
            f"Document generated: {datetime.utcnow().isoformat()} UTC  |  "
            f"Case: {case}",
            SMALL,
        ),
    ]

    return story


# ── helpers ──────────────────────────────────────────────────

def _kv_table(rows: list[tuple]) -> Table:
    data   = [[k, v] for k, v in rows]
    table  = Table(data, colWidths=[2.2*inch, 4*inch])
    table.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",  (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",  (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.whitesmoke, colors.white]),
        ("GRID",      (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    return table


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
