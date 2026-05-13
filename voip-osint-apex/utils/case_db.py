"""
VoIP OSINT APEX — Asynchronous Case Management
Robust local persistence for investigations with forensic integrity tracking.
"""

import aiosqlite
import json
import csv
import logging
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from utils.config import get_config

log = logging.getLogger("case_db")
config = get_config()

DB_PATH = config.output_dir / "cases.db"

# ── Schema ──────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS investigations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    number       TEXT,
    ip           TEXT,
    domain       TEXT,
    risk_level   TEXT,
    confidence   INTEGER,
    report_path  TEXT,
    report_hash  TEXT,   -- SHA-256 of the generated report
    findings     TEXT,   -- JSON blob of full result
    tags         TEXT    -- comma-separated operator tags
);

CREATE INDEX IF NOT EXISTS idx_number ON investigations(number);
CREATE INDEX IF NOT EXISTS idx_ip     ON investigations(ip);
CREATE INDEX IF NOT EXISTS idx_risk   ON investigations(risk_level);

-- Initial metadata
INSERT OR IGNORE INTO meta (key, value) VALUES ('version', '3.0');
"""

class CaseDB:
    """
    Async database manager for investigation cases.
    """
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._initialized = False

    async def _ensure_db(self):
        """Initialize database and schema if not already done."""
        if self._initialized:
            return
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(SCHEMA)
            await db.commit()
        self._initialized = True

    async def save_case(
        self,
        data: Dict[str, Any],
        report_path: str = "",
        report_hash: str = "",
        tags: List[str] = None
    ) -> int:
        """
        Persist an investigation result asynchronously.
        Returns the new case ID.
        """
        await self._ensure_db()
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO investigations
                (timestamp, number, ip, domain, risk_level,
                 confidence, report_path, report_hash, findings, tags)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    datetime.utcnow().isoformat() + "Z",
                    data.get("number"),
                    data.get("ip"),
                    data.get("domain"),
                    data.get("risk_level"),
                    int(data.get("confidence", 0)),
                    report_path,
                    report_hash,
                    json.dumps(data),
                    ",".join(tags or []),
                ),
            )
            case_id = cursor.lastrowid
            await db.commit()
        log.info(f"[CaseDB] Saved case #{case_id}")
        return case_id

    async def list_cases(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve the most recent cases."""
        await self._ensure_db()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT id, timestamp, number, ip, domain,
                       risk_level, confidence, report_hash, tags
                FROM investigations
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def get_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single case by ID."""
        await self._ensure_db()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM investigations WHERE id = ?", (case_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                result = dict(row)
                result["findings"] = json.loads(result["findings"] or "{}")
                return result

    async def search_cases(self, query: str) -> List[Dict[str, Any]]:
        """Search cases by number, IP, or domain substring."""
        await self._ensure_db()
        pattern = f"%{query}%"
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT id, timestamp, number, ip, domain, risk_level
                FROM investigations
                WHERE number LIKE ? OR ip LIKE ? OR domain LIKE ?
                ORDER BY id DESC
                """,
                (pattern, pattern, pattern),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

# ── Singleton Instance ─────────────────────────────────────

_case_db = CaseDB()

async def save_case(data, report_path="", report_hash="", tags=None):
    return await _case_db.save_case(data, report_path, report_hash, tags)

async def list_cases(limit=50):
    return await _case_db.list_cases(limit)

async def get_case(case_id):
    return await _case_db.get_case(case_id)

async def search_cases(query):
    return await _case_db.search_cases(query)

# ── Export & UI (Sync wrappers for CLI) ──────────────────────

def export_csv_sync(output_path: str = "outputs/all_cases.csv") -> str:
    """Synchronous wrapper for exporting to CSV (CLI use)."""
    loop = asyncio.get_event_loop()
    cases = loop.run_until_complete(_case_db.list_cases(limit=99999))
    if not cases:
        log.warning("[CaseDB] No cases to export.")
        return ""
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        if cases:
            writer = csv.DictWriter(f, fieldnames=cases[0].keys())
            writer.writeheader()
            writer.writerows(cases)
    return output_path

def print_cases_table(cases: List[Dict[str, Any]]):
    from rich.table  import Table
    from rich.console import Console
    from rich        import box

    console = Console()
    table   = Table(title="Investigation History", box=box.SIMPLE_HEAVY)
    table.add_column("ID",         style="cyan",   width=5)
    table.add_column("Timestamp",  style="dim",    width=22)
    table.add_column("Number",     style="white",  width=16)
    table.add_column("IP",         style="white",  width=16)
    table.add_column("Domain",     style="white",  width=20)
    table.add_column("Risk",       style="bold",   width=10)
    table.add_column("Score",      style="yellow", width=7)

    COLORS = {"CRITICAL": "bold red", "HIGH": "red",
              "MEDIUM": "yellow", "LOW": "green", "CLEAN": "dim green"}

    for c in cases:
        risk  = (c.get("risk_level") or "?").upper()
        color = COLORS.get(risk, "white")
        table.add_row(
            str(c["id"]),
            c["timestamp"][:19],
            c.get("number")  or "—",
            c.get("ip")      or "—",
            c.get("domain")  or "—",
            f"[{color}]{risk}[/]",
            str(c.get("confidence") or 0),
        )
    console.print(table)
