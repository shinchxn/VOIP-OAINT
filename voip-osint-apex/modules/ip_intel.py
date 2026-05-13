"""
VoIP OSINT APEX — IP Intelligence Plugin
Refactored v3.0 modular plugin.
"""

import aiohttp
import asyncio
import logging
import socket
from typing import Any, Dict
# pyrefly: ignore [missing-import]
from ipwhois import IPWhois

from core.base_plugin import BasePlugin, PluginMetadata
from utils.cache import Cache
from utils.config import get_keys

log = logging.getLogger("ip_plugin")
keys = get_keys()
cache = Cache()

class IPPlugin(BasePlugin):
    """
    Plugin for deep-dive into IP reputation, VPN/Tor detection, and registration data.
    """

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="ip_intel",
            version="3.0",
            description="Deep analysis of IP addresses for risk and ownership.",
            author="Antigravity",
            category="intel"
        )

    async def run(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        cache_key = f"ip:{target}"
        cached = cache.get(cache_key)
        if cached: return cached

        async with aiohttp.ClientSession() as session:
            ip_api, abuse, shodan, proxy, tor, vt = await asyncio.gather(
                self._task_ip_api(session, target),
                self._task_abuseipdb(session, target),
                self._task_shodan(session, target),
                self._task_proxycheck(session, target),
                self._task_tor(session, target),
                self._task_vt(session, target)
            )

        rdap = await asyncio.to_thread(self._sync_whois, target)
        rdns = await asyncio.to_thread(self._sync_rdns, target)

        result = {
            "ip": target,
            "country": ip_api.get("country", "Unknown"),
            "city": ip_api.get("city", "Unknown"),
            "isp": ip_api.get("isp", "Unknown"),
            "is_vpn": proxy.get(target, {}).get("vpn", "no") == "yes",
            "is_tor": tor.get("is_tor", False),
            "abuse_score": abuse.get("data", {}).get("abuseConfidenceScore", 0),
            "vt_malicious": vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
            "asn": rdap.get("asn", "Unknown"),
            "hostname": rdns.get("hostname", "Unknown")
        }

        # Risk scoring
        score = result["abuse_score"]
        if result["is_tor"] or result["vt_malicious"] > 0:
            result["risk_level"] = "CRITICAL"
        elif result["is_vpn"] or score > 50:
            result["risk_level"] = "HIGH"
        else:
            result["risk_level"] = "LOW"

        cache.set(cache_key, result)
        return result

    async def _fetch_json(self, session: aiohttp.ClientSession, url: str, headers: Dict = None, service: str = "unknown") -> Dict:
        from utils.exceptions import APIError, AuthenticationError, RateLimitError, NetworkError
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status in (401, 403):
                    log.error(f"[{service}] Authentication failed (HTTP {response.status})")
                    raise AuthenticationError(service)
                elif response.status == 429:
                    log.warning(f"[{service}] Rate limit exceeded (HTTP 429)")
                    raise RateLimitError(service)
                else:
                    log.debug(f"[{service}] unexpected status: {response.status}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.debug(f"[{service}] Network error: {e}")
            # Don't raise NetworkError here to allow other parallel tasks to continue
        except Exception as e:
            log.error(f"[{service}] Unexpected error: {e}")
        return {}

    async def _task_ip_api(self, session, ip):
        return await self._fetch_json(session, f"http://ip-api.com/json/{ip}", service="ip-api")

    async def _task_abuseipdb(self, session, ip):
        if not keys.abuseipdb: return {}
        from utils.rate_limiter import async_acquire
        if not await async_acquire("abuseipdb"): return {}
        headers = {"Key": keys.abuseipdb, "Accept": "application/json"}
        return await self._fetch_json(session, f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers, service="abuseipdb")

    async def _task_shodan(self, session, ip):
        if not keys.shodan: return {}
        from utils.rate_limiter import async_acquire
        if not await async_acquire("shodan"): return {}
        return await self._fetch_json(session, f"https://api.shodan.io/shodan/host/{ip}?key={keys.shodan}", service="shodan")

    async def _task_proxycheck(self, session, ip):
        return await self._fetch_json(session, f"http://proxycheck.io/v2/{ip}?vpn=1&asn=1", service="proxycheck")

    async def _task_tor(self, session, ip):
        # BUG-10: Tor list fetch is slow and wasteful here.
        # Future: Move to threat_feeds or local cached list.
        try:
            async with session.get("https://dan.me.uk/torlist/", timeout=aiohttp.ClientTimeout(total=5)) as r:
                if r.status == 200:
                    text = await r.text()
                    return {"is_tor": ip in text}
        except Exception as e:
            log.debug(f"[Tor] Failed to fetch list: {e}")
        return {"is_tor": False}

    async def _task_vt(self, session, ip):
        if not keys.virustotal: return {}
        from utils.rate_limiter import async_acquire
        if not await async_acquire("virustotal"): return {}
        headers = {"x-apikey": keys.virustotal}
        return await self._fetch_json(session, f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers, service="virustotal")

    def _sync_whois(self, ip):
        from utils.exceptions import NetworkError
        try:
            obj = IPWhois(ip)
            return obj.lookup_rdap()
        except Exception as e:
            log.debug(f"[Whois] Lookup failed for {ip}: {e}")
            return {}

    def _sync_rdns(self, ip):
        try:
            return {"hostname": socket.gethostbyaddr(ip)[0]}
        except (socket.herror, socket.gaierror, IndexError) as e:
            log.debug(f"[RDNS] Lookup failed for {ip}: {e}")
            return {}
        except Exception as e:
            log.error(f"[RDNS] Unexpected error for {ip}: {e}")
            return {}

# Legacy wrapper
async def analyze_ip(ip: str) -> dict:
    plugin = IPPlugin()
    return await plugin.run(ip)
