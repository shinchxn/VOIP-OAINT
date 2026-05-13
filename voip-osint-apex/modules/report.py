import json
import os
import csv
from datetime import datetime
import hashlib
import logging
# pyrefly: ignore [missing-import]
from reportlab.pdfgen import canvas
# pyrefly: ignore [missing-import]
from reportlab.lib.pagesizes import letter

log = logging.getLogger("report")
os.makedirs("outputs/reports", exist_ok=True)


def generate_json(data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"outputs/reports/report_{timestamp}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=4, default=str)
    log.info(f"[Report] JSON → {path}")
    return path


def generate_pdf(data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"outputs/reports/report_{timestamp}.pdf"
    c = canvas.Canvas(path, pagesize=letter)
    
    # Page 1: Summary
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "VoIP OSINT APEX - Investigation Report")
    c.setFont("Helvetica", 12)
    # Use SHA-256 for forensic-grade case IDs (not MD5)
    case_hash = hashlib.sha256(str(timestamp).encode()).hexdigest()[:12].upper()
    c.drawString(50, 730, f"Case ID: {case_hash}")
    c.drawString(50, 710, f"Date: {timestamp}")
    c.drawString(50, 690, "Tool version: 3.0")
    
    risk = "LOW"
    conf = 0
    if "correlation" in data:
        conf = data["correlation"].get("confidence", 0)
        risk = "CRITICAL" if conf > 80 else "HIGH" if conf > 50 else "MEDIUM" if conf > 30 else "LOW"
    elif "number" in data:
        risk = data["number"].get("risk_level", "LOW")
        
    c.drawString(50, 670, f"Overall Risk Level: {risk}")
    c.drawString(50, 650, f"Confidence Score: {conf}%")
    
    # Next pages
    y = 610
    for section, content in data.items():
        if y < 100:
            c.showPage()
            y = 750
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, f"--- {str(section).upper()} ---")
        y -= 20
        c.setFont("Helvetica", 10)
        if isinstance(content, dict):
            for k, v in content.items():
                if y < 50:
                    c.showPage()
                    y = 750
                c.drawString(70, y, f"{k}: {str(v)[:80]}")
                y -= 15
        elif isinstance(content, list):
            for item in content:
                if y < 50:
                    c.showPage()
                    y = 750
                c.drawString(70, y, f"- {str(item)[:80]}")
                y -= 15
        y -= 10
        
    c.setFont("Helvetica-Oblique", 10)
    c.drawString(50, 30, "FOR LAW ENFORCEMENT USE ONLY")
    c.save()
    
    # SHA-256 evidence integrity hash
    file_hash = _sha256_file(path)
    log.info(f"[Report] PDF → {path}  SHA-256: {file_hash}")
    
    # Evidence log
    generate_evidence_log({"pdf_path": path, "sha256": file_hash})
        
    return path


def generate_csv(data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"outputs/reports/report_{timestamp}.csv"
    
    flat_data = {}
    for k, v in data.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                flat_data[f"{k}_{k2}"] = v2
        else:
            flat_data[k] = v
            
    with open(path, "w", newline='') as f:
        w = csv.writer(f)
        w.writerow(flat_data.keys())
        w.writerow([str(v) for v in flat_data.values()])
    log.info(f"[Report] CSV → {path}")
    return path


def generate_evidence_log(data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"outputs/reports/audit_{timestamp}.log"
    with open(path, "a") as f:
        f.write(f"[{timestamp}] AUDIT RECORD\n")
        f.write(json.dumps(data, indent=2, default=str))
        f.write("\n")
    return path


def _sha256_file(path: str) -> str:
    """Compute SHA-256 hash of a file for forensic integrity verification."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
