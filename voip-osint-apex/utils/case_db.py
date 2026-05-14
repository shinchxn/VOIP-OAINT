"""
VoIP OSINT APEX v3.0 — Case Management DB
Async SQLite storage using aiosqlite for investigations.
"""

import aiosqlite
import json
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from utils.config import get_config

log = logging.getLogger("case_db")

class CaseDB:
    def __init__(self):
        self.cfg = get_config()
        self.db_path = self.cfg.output_dir / "cases.db"
        
    async def init_db(self):
        """Initialize SQLite DB schema."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    number TEXT,
                    ip TEXT,
                    domain TEXT,
                    risk_level TEXT,
                    confidence INTEGER,
                    report_path TEXT,
                    findings_json TEXT
                )
            """)
            await db.commit()
            log.debug(f"[CaseDB] Initialized at {self.db_path}")

    def _generate_case_id(self) -> str:
        date_str = datetime.now().strftime("%Y%m%d")
        uuid_str = str(uuid.uuid4())[:8].upper()
        return f"CASE-{date_str}-{uuid_str}"

    async def save_case(self, data: Dict[str, Any], report_path: str = "") -> str:
        """Save investigation findings. Returns the new case_id."""
        case_id = self._generate_case_id()
        ts = datetime.now().isoformat()
        
        # Extract basic info
        number = data.get("number", {}).get("number", "")
        ip = data.get("ip", {}).get("ip", "")
        domain = data.get("domain", {}).get("domain", "")
        
        # Correlation might have these
        corr = data.get("correlation", {})
        risk_level = corr.get("risk_level", "UNKNOWN")
        confidence = corr.get("confidence_score", 0)
        
        findings_str = json.dumps(data, default=str)
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO investigations (
                    case_id, timestamp, number, ip, domain, 
                    risk_level, confidence, report_path, findings_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (case_id, ts, number, ip, domain, risk_level, confidence, report_path, findings_str))
            await db.commit()
            
        log.info(f"[CaseDB] Saved case {case_id}")
        return case_id

    async def get_case(self, case_id: str) -> Dict[str, Any]:
        """Retrieve a full case by ID."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM investigations WHERE case_id = ?", (case_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return {}

    async def list_cases(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent cases (metadata only)."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT case_id, timestamp, number, ip, domain, risk_level, confidence FROM investigations ORDER BY id DESC LIMIT ?", 
                (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def search_cases(self, query: str) -> List[Dict[str, Any]]:
        """Search cases by number, ip, domain, or case_id."""
        search_term = f"%{query}%"
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("""
                SELECT case_id, timestamp, number, ip, domain, risk_level, confidence 
                FROM investigations 
                WHERE number LIKE ? OR ip LIKE ? OR domain LIKE ? OR case_id LIKE ?
                ORDER BY id DESC LIMIT 50
            """, (search_term, search_term, search_term, search_term)) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]
                
    async def export_cases(self, format: str = "json") -> str:
        """Export all case data."""
        # Simple JSON export
        cases = []
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM investigations ORDER BY id DESC") as cursor:
                rows = await cursor.fetchall()
                cases = [dict(r) for r in rows]
                
        out_path = self.cfg.output_dir / "reports" / f"export_{datetime.now().strftime('%Y%m%d')}.json"
        with open(out_path, "w") as f:
            json.dump(cases, f, indent=2, default=str)
        return str(out_path)

# Singleton instance
_db = CaseDB()

async def init_db():
    await _db.init_db()

async def save_case(data: Dict[str, Any], report_path: str = "") -> str:
    return await _db.save_case(data, report_path)

async def get_case(case_id: str) -> Dict[str, Any]:
    return await _db.get_case(case_id)

async def list_cases(limit: int = 20) -> List[Dict[str, Any]]:
    return await _db.list_cases(limit)

async def search_cases(query: str) -> List[Dict[str, Any]]:
    return await _db.search_cases(query)

async def export_cases(format: str = "json") -> str:
    return await _db.export_cases(format)
