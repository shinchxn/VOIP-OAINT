"""
VoIP OSINT APEX — IMSI / SS7 Awareness (Carrier Intel)
Checks if a number is roaming, ported, or active using HLR lookup APIs.
Refactored v3.0 modular plugin.
"""

import logging
import aiohttp
import asyncio
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict

from core.base_plugin import BasePlugin, PluginMetadata
from utils.config import get_keys
from utils.rate_limiter import async_acquire
from realtime import emit

log = logging.getLogger("carrier_intel")
keys = get_keys()



@dataclass
class CarrierResult:
    number:           str
    mcc:              Optional[str] = None
    mnc:              Optional[str] = None
    country:          Optional[str] = None
    original_carrier: Optional[str] = None
    current_carrier:  Optional[str] = None
    ported:           bool = False
    roaming:          bool = False
    valid:            bool = False
    line_type:        Optional[str] = None # mobile / landline / voip
    error:            Optional[str] = None

class CarrierPlugin(BasePlugin):
    """
    Plugin for carrier intelligence and HLR lookup.
    """

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="carrier_intel",
            version="3.0",
            description="HLR lookup and carrier data analysis.",
            author="Antigravity",
            category="intel"
        )

    async def run(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        number = self._normalize(target)
        
        # Numverify is now the primary carrier/HLR intelligence source.
        # Primary HLR (hlr-lookups.com) removed per user request.
        result = await self._try_numverify(number)
        
        if not result.valid:
            log.warning(f"[HLR] Numverify lookup failed for {number}: {result.error}")

        self._log_result(result)
        result_dict = asdict(result)

        # Real-time broadcast
        is_suspicious = result.ported or result.roaming or result.error
        severity   = "WARNING" if is_suspicious else "INFO"
        event_type = "HLR_ALERT" if is_suspicious else "HLR_RESULT"
        await emit(event_type, {
            "number":   result.number,
            "carrier":  result.current_carrier,
            "country":  result.country,
            "ported":   result.ported,
            "roaming":  result.roaming,
            "valid":    result.valid,
            "error":    result.error,
        }, severity=severity)

        return result_dict



    async def _try_numverify(self, number: str) -> CarrierResult:
        """
        Uses Numverify (apilayer.net) for carrier intelligence.
        Free tier: 100 requests/month. Set NUMVERIFY_KEY in .env.
        """
        if not keys.numverify:
            return CarrierResult(number=number, error="No Numverify key")

        if not await async_acquire("numverify"):
            return CarrierResult(number=number, error="Rate limit hit")

        # Numverify uses HTTP (not HTTPS) for free-tier requests
        url = "http://apilayer.net/api/validate"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params={"access_key": keys.numverify, "number": number},
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as r:
                    if r.status != 200:
                        return CarrierResult(number=number, error=f"HTTP {r.status}")
                    d = await r.json()
                    if d.get("error"):
                        err = d["error"]
                        return CarrierResult(number=number, error=f"Numverify: {err.get('info', err)}")
                    return CarrierResult(
                        number           = number,
                        country          = d.get("country_name"),
                        original_carrier = d.get("carrier"),
                        current_carrier  = d.get("carrier"),
                        valid            = bool(d.get("valid", False)),
                        line_type        = d.get("line_type"),
                    )
        except aiohttp.ClientError as e:
            return CarrierResult(number=number, error=f"Network error: {e}")
        except Exception as e:
            return CarrierResult(number=number, error=str(e))

    def _normalize(self, number: str) -> str:
        n = number.strip().replace(" ", "").replace("-", "")
        return n if n.startswith("+") else "+" + n

    def _log_result(self, r: CarrierResult):
        if r.error:
            log.error(f"[HLR] {r.number} → ERROR: {r.error}")
            return
        flags = []
        if r.ported:  flags.append("PORTED")
        if r.roaming: flags.append("ROAMING")
        log.info(
            f"[HLR] {r.number} → {r.current_carrier} "
            f"({r.country}) [{r.line_type}] "
            f"{'  '.join(flags) or 'normal'}"
        )

# Legacy / Direct access wrappers
async def analyze_carrier(number: str) -> Dict[str, Any]:
    plugin = CarrierPlugin()
    return await plugin.run(number)

def hlr_lookup(number: str) -> CarrierResult:
    """Synchronous wrapper for legacy CLI commands."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            try:
                import importlib
                nest_asyncio = importlib.import_module("nest_asyncio")
                nest_asyncio.apply()
            except ModuleNotFoundError:
                raise RuntimeError(
                    "hlr_lookup cannot be used from a running event loop without nest_asyncio installed"
                )
    except Exception:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    res_dict = loop.run_until_complete(analyze_carrier(number))
    return CarrierResult(**res_dict)
