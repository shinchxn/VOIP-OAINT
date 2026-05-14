"""
VoIP OSINT APEX v3.0 — Carrier Intelligence
Focused strictly on Numverify (HLR Lookups was removed).
Maps MCC/MNC codes and provides line type forensics.
"""

import asyncio
import logging
from typing import Dict, Any

from modules.number_lookup import numverify_check, parse_number

log = logging.getLogger("carrier_intel")

# Simplified MCC mapping for forensics
MCC_TABLE = {
    "310": "United States",
    "311": "United States",
    "234": "United Kingdom",
    "235": "United Kingdom",
    "302": "Canada",
    "505": "Australia",
    "262": "Germany",
    "208": "France",
    "404": "India",
    "405": "India",
}


async def run_carrier_intel(number: str) -> Dict[str, Any]:
    """Execute carrier intelligence pipeline."""
    log.info(f"[Carrier] Running deep intelligence for {number}")
    
    # 1. Base parsing
    parsed = parse_number(number)
    
    # 2. Live API check (Numverify only)
    nv_data = await numverify_check(number)
    
    # 3. Correlation
    is_voip = parsed.get("number_type") == "VOIP" or nv_data.get("line_type", "").lower() == "voip"
    carrier_name = nv_data.get("carrier") or parsed.get("carrier") or "Unknown"
    
    return {
        "number": number,
        "valid": nv_data.get("valid", parsed.get("is_valid", False)),
        "carrier": carrier_name,
        "line_type": nv_data.get("line_type", parsed.get("number_type")),
        "country": nv_data.get("country_code", parsed.get("country")),
        "is_voip": is_voip,
        "mcc_hint": "Check full IMSI if available in SIP PCAP",
        "api_source": "Numverify"
    }

