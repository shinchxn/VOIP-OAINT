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

log = logging.getLogger("carrier_intel")
keys = get_keys()

MCC_TABLE = {
    "404": "India", "405": "India",
    "310": "USA",   "311": "USA",
    "234": "UK",    "505": "Australia",
}

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
        
        # Try primary HLR (hlrlookup.com)
        result = await self._try_hlrlookup(number)
        
        # Fallback to Numverify if primary fails or is limited
        if not result.valid or result.error:
            log.warning(f"[HLR] Primary failed, trying fallback for {number}...")
            fallback = await self._try_numverify(number)
            if fallback.valid:
                result = fallback

        self._log_result(result)
        return asdict(result)

    async def _try_hlrlookup(self, number: str) -> CarrierResult:
        url = "https://hlrlookup.com/api" # Placeholder for actual API endpoint
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params={"msisdn": number}, timeout=10) as r:
                    if r.status != 200:
                        return CarrierResult(number=number, error=f"HTTP {r.status}")
                    d = await r.json()
                    mcc = d.get("mcc", "")
                    return CarrierResult(
                        number           = number,
                        mcc              = mcc,
                        mnc              = d.get("mnc"),
                        country          = MCC_TABLE.get(mcc, d.get("country")),
                        original_carrier = d.get("original_network"),
                        current_carrier  = d.get("network"),
                        ported           = bool(d.get("ported", False)),
                        roaming          = bool(d.get("roaming", False)),
                        valid            = bool(d.get("valid", True)),
                        line_type        = d.get("type"),
                    )
        except Exception as e:
            return CarrierResult(number=number, error=str(e))

    async def _try_numverify(self, number: str) -> CarrierResult:
        if not keys.numverify:
            return CarrierResult(number=number, error="No Numverify key")
            
        if not await async_acquire("numverify"):
            return CarrierResult(number=number, error="Rate limit hit")

        url = "https://apilayer.net/api/validate"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params={"access_key": keys.numverify, "number": number}, timeout=10) as r:
                    if r.status != 200:
                        return CarrierResult(number=number, error=f"HTTP {r.status}")
                    d = await r.json()
                    return CarrierResult(
                        number           = number,
                        country          = d.get("country_name"),
                        original_carrier = d.get("carrier"),
                        current_carrier  = d.get("carrier"),
                        valid            = bool(d.get("valid", False)),
                        line_type        = d.get("line_type"),
                    )
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
