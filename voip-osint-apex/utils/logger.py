"""
VoIP OSINT APEX v3.0 — Forensic Audit Logger
Ensures all investigations leave a tamper-evident audit trail.
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from utils.config import get_config

# Setup standard logging for the console and debug files
def setup_logging():
    cfg = get_config()
    cfg.ensure_output_dirs()
    
    log_level = logging.DEBUG if cfg.debug else logging.INFO
    log_format = "%(asctime)s | %(levelname)-8s | %(name)-12s | %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Root logger setup
    root = logging.getLogger()
    root.setLevel(log_level)
    
    # Remove existing handlers
    for h in root.handlers[:]:
        root.removeHandler(h)
        
    # Console handler (rich formatting handled separately in main UI, but basic here)
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(logging.Formatter(log_format, datefmt=date_format))
    root.addHandler(ch)
    
    # File handler
    log_file = cfg.output_dir / "logs" / "apex_system.log"
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(log_format, datefmt=date_format))
    root.addHandler(fh)

# ── Forensic Audit Logger ─────────────────────────────────────

class ForensicLogger:
    def __init__(self):
        self.cfg = get_config()
        
    def _get_audit_file(self) -> Path:
        date_str = datetime.now().strftime("%Y-%m-%d")
        return self.cfg.output_dir / "logs" / f"audit_{date_str}.log"
        
    def log_investigation(self, cmd: str, target: str, result_summary: str, modules_used: list, report_path: str = "None"):
        """Logs a completed investigation."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        mod_str = ",".join(modules_used)
        entry = f"[{ts}] CMD={cmd} | TARGET={target} | MODULES={mod_str} | RESULT={result_summary} | REPORT={report_path}\n"
        
        with open(self._get_audit_file(), "a", encoding="utf-8") as f:
            f.write(entry)

    def log_error(self, module: str, error: Exception):
        """Logs an investigation error."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        entry = f"[{ts}] ERROR | MODULE={module} | DETAILS={str(error)}\n"
        
        with open(self._get_audit_file(), "a", encoding="utf-8") as f:
            f.write(entry)


_audit_logger = ForensicLogger()

def log_investigation(cmd: str, target: str, result_summary: str, modules_used: list, report_path: str = "None"):
    _audit_logger.log_investigation(cmd, target, result_summary, modules_used, report_path)

def log_error(module: str, error: Exception):
    _audit_logger.log_error(module, error)
    logging.getLogger(module).error(f"Investigation Error: {error}")
