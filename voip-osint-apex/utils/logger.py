"""
VoIP OSINT APEX — Structured Audit Logger
JSON-formatted logs with rotation for forensic compliance.
"""

import logging
import logging.handlers
import json
import os
from datetime import datetime
from pathlib import Path

LOG_DIR = Path("outputs/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

date_str = datetime.now().strftime("%Y-%m-%d")
log_file = LOG_DIR / f"audit_{date_str}.log"


class JSONFormatter(logging.Formatter):
    """Structured JSON log format for forensic audit trails."""

    def format(self, record):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


# ── Configure root logger ──────────────────────────────────

_configured = False

def _ensure_configured():
    global _configured
    if _configured:
        return
    _configured = True

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # File handler — rotates at 10 MB, keeps last 5 files
    file_handler = logging.handlers.RotatingFileHandler(
        str(log_file), maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(JSONFormatter())
    file_handler.setLevel(logging.DEBUG)

    # Console handler — human-readable
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    console_handler.setLevel(logging.INFO)

    root.addHandler(file_handler)
    root.addHandler(console_handler)


# Auto-configure on import
_ensure_configured()


def log_action(cmd, input_val, result, modules, report_file=None):
    """Log an investigative action for the audit trail."""
    log = logging.getLogger("audit")
    entry = {
        "action": cmd,
        "input": str(input_val),
        "result": str(result),
        "modules": modules,
    }
    if report_file:
        entry["report_file"] = report_file
    log.info(f"CMD:{cmd}  INPUT:{input_val}  RESULT:{result}  MODULES:{modules}")
