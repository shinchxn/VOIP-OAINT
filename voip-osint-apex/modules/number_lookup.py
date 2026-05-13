"""
VoIP OSINT APEX — Number Intelligence Plugin
Refactored v3.0 modular plugin.
"""

import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import aiohttp
import asyncio
import logging
from typing import Any, Dict

from core.base_plugin import BasePlugin, PluginMetadata
from utils.config import get_keys
from utils.rate_limiter import async_acquire
from utils.exceptions import APIError, NetworkError

log = logging.getLogger("number_plugin")
keys = get_keys()

class NumberPlugin(BasePlugin):
    """
    Plugin for analyzing phone numbers for carrier data, fraud scores, and line types.
    """

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="number_lookup",
            version="3.0",
            description="Analyzes phone numbers for carrier intelligence and fraud risk.",
            author="Antigravity",
            category="intel",
            requires_api_key="ipqs"
        )

    async def run(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {
            "number": target,
            "country": "Unknown",
            "carrier": "Unknown",
            "timezone": "Unknown",
            "valid": False,
            "line_type": "Unknown",
            "fraud_score": 0,
            "disposable": False,
            "active": False,
            "vpn": False,
            "tor": False,
            "leaked": False,
            "recent_abuse": False,
            "risk_level": "LOW",
            "risk_reason": "No high risk indicators found"
        }
        
        # ── Phonenumbers parsing (Sync but fast) ────────────────
        try:
            parsed = phonenumbers.parse(target)
            result["country"] = geocoder.description_for_number(parsed, "en") or result["country"]
            result["carrier"] = carrier.name_for_number(parsed, "en") or result["carrier"]
            tz = timezone.time_zones_for_number(parsed)
            result["timezone"] = tz[0] if tz else result["timezone"]
            result["valid"] = phonenumbers.is_valid_number(parsed)
            num_type = phonenumbers.number_type(parsed)
            if num_type == phonenumbers.PhoneNumberType.MOBILE: result["line_type"] = "mobile"
            elif num_type == phonenumbers.PhoneNumberType.FIXED_LINE: result["line_type"] = "fixed"
            elif num_type == phonenumbers.PhoneNumberType.VOIP: result["line_type"] = "voip"
        except Exception as e:
            log.warning(f"[NumberLookup] Failed to parse '{target}': {e}")

        # ── IPQualityScore (Async) ──────────────────────────────
        if keys.ipqs:
            if await async_acquire("ipqs"):
                try:
                    async with aiohttp.ClientSession() as session:
                        url = f"https://www.ipqualityscore.com/api/json/phone/{keys.ipqs}/{target}"
                        async with session.get(url, timeout=10) as r:
                            if r.status == 200:
                                data = await r.json()
                                if data.get("success"):
                                    result["fraud_score"] = data.get("fraud_score", 0)
                                    result["disposable"] = data.get("VOIP", False) or data.get("disposable", False)
                                    result["active"] = data.get("active", False)
                                    result["line_type"] = data.get("line_type", result["line_type"])
                                    result["vpn"] = data.get("vpn", False)
                                    result["tor"] = data.get("tor", False)
                                    result["recent_abuse"] = data.get("recent_abuse", False)
                                    result["leaked"] = data.get("leaked", False)
                                    if data.get("carrier"):
                                        result["carrier"] = data.get("carrier")
                            elif r.status == 429:
                                log.warning("[NumberLookup] IPQualityScore rate limited (429)")
                except Exception as e:
                    log.warning(f"[NumberLookup] IPQS request error: {e}")

        # ── Risk scoring ────────────────────────────────────────
        score = result["fraud_score"]
        if score > 85:
            result["risk_level"] = "CRITICAL"
            result["risk_reason"] = "Extremely high fraud score"
        elif score > 75:
            result["risk_level"] = "HIGH"
            result["risk_reason"] = "High fraud score"
        
        if result["tor"]:
            result["risk_level"] = "CRITICAL"
            result["risk_reason"] += " (Tor connection)"

        return result

# Async internal logic
async def _async_analyze_number(number: str) -> Dict[str, Any]:
    plugin = NumberPlugin()
    return await plugin.run(number)

# Legacy wrapper for compatibility
def analyze_number(number: str) -> dict:
    """Synchronous wrapper for legacy CLI commands."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're already in a loop, we can't use run_until_complete.
            # Create a new thread to run the async function.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, _async_analyze_number(number))
                return future.result()
    except Exception:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(_async_analyze_number(number))
