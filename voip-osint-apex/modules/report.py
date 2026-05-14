"""
VoIP OSINT APEX v3.0 — Reporting Engine
Generates forensic PDF reports with SHA-256 hashes.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import hashlib

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from utils.config import get_config

log = logging.getLogger("report")

def generate_pdf(case_id: str, data: Dict[str, Any]) -> str:
    """Generate a forensic PDF report."""
    cfg = get_config()
    out_dir = cfg.output_dir / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    filename = f"{case_id}.pdf"
    filepath = out_dir / filename
    
    doc = SimpleDocTemplate(str(filepath), pagesize=letter)
    styles = getSampleStyleSheet()
    Story = []
    
    # Title
    Story.append(Paragraph(f"VoIP OSINT APEX v3.0 — Forensic Report", styles["Title"]))
    Story.append(Spacer(1, 12))
    Story.append(Paragraph(f"Case ID: {case_id}", styles["Heading2"]))
    Story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
    Story.append(Spacer(1, 12))
    
    # Correlation Summary
    corr = data.get("correlation", {})
    Story.append(Paragraph("Executive Summary", styles["Heading2"]))
    Story.append(Paragraph(f"Risk Level: {corr.get('risk_level', 'UNKNOWN')}", styles["Normal"]))
    Story.append(Paragraph(f"Confidence Score: {corr.get('confidence_score', 0)}/100", styles["Normal"]))
    Story.append(Spacer(1, 6))
    for ev in corr.get("evidence", []):
        Story.append(Paragraph(f"• {ev}", styles["Normal"]))
    Story.append(Spacer(1, 12))
    
    # Targets
    num = data.get("number", {}).get("number", {}).get("international_format", "N/A")
    ip = data.get("ip", {}).get("ip", "N/A")
    dom = data.get("domain", {}).get("domain", "N/A")
    
    Story.append(Paragraph("Targets Analysed", styles["Heading2"]))
    Story.append(Paragraph(f"Phone Number: {num}", styles["Normal"]))
    Story.append(Paragraph(f"IP Address: {ip}", styles["Normal"]))
    Story.append(Paragraph(f"Domain: {dom}", styles["Normal"]))
    Story.append(Spacer(1, 12))
    
    doc.build(Story)
    
    # Generate SHA-256 for integrity
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        hasher.update(f.read())
    file_hash = hasher.hexdigest()
    
    log.info(f"[Report] PDF generated: {filepath} (SHA256: {file_hash})")
    return str(filepath)
    
def generate_json(case_id: str, data: Dict[str, Any]) -> str:
    """Export full raw JSON."""
    cfg = get_config()
    filepath = cfg.output_dir / "reports" / f"{case_id}.json"
    
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)
        
    return str(filepath)
