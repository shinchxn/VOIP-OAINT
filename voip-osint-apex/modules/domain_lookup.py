"""
VoIP OSINT APEX — Domain Intelligence Plugin
Refactored v3.0 modular plugin.
"""

import aiohttp
import asyncio
import logging
import shutil
import os
import subprocess
from typing import Any, Dict, List
# pyrefly: ignore [missing-import]
import whois
# pyrefly: ignore [missing-import]
import dns.resolver

from core.base_plugin import BasePlugin, PluginMetadata
from utils.config import get_keys
from utils.rate_limiter import async_acquire
from utils.exceptions import APIError, NetworkError

log = logging.getLogger("domain_plugin")
keys = get_keys()

class DomainPlugin(BasePlugin):
    """
    Plugin for gathering WHOIS, DNS, and Certificate Transparency data.
    """

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="domain_lookup",
            version="3.0",
            description="Analyzes domains for ownership, DNS records, and threat reputation.",
            author="Antigravity",
            category="intel"
        )

    async def run(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        async with aiohttp.ClientSession() as session:
            # Run independent tasks in parallel
            dns_task = self._task_dns(target)
            whois_task = asyncio.to_thread(self._sync_whois, target)
            vt_task = self._task_vt(session, target)
            crt_task = self._task_crt(session, target)
            
            results = await asyncio.gather(dns_task, whois_task, vt_task, crt_task)
            
        result = {
            "domain": target,
            "dns": results[0],
            "whois": results[1],
            "vt": results[2],
            "crt": results[3]
        }
        
        # Optional: Harvest results if requested in context (not default for performance)
        if context and context.get("harvest"):
            result["harvest"] = await self._task_harvester(target)

        return result

    async def _task_dns(self, domain: str) -> Dict[str, List[str]]:
        dns_results = {}
        # Standard records
        for record in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, domain, record)
                dns_results[record] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
        
        # SIP SRV records
        for proto in ["tcp", "udp"]:
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, f"_sip._{proto}.{domain}", 'SRV')
                dns_results[f"_sip._{proto}"] = [str(r) for r in answers]
            except Exception:
                continue
                
        return dns_results

    def _sync_whois(self, domain: str) -> Dict[str, Any]:
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiry_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": w.emails
            }
        except Exception as e:
            log.debug(f"[Domain] WHOIS failed for {domain}: {e}")
            return {}

    async def _task_vt(self, session: aiohttp.ClientSession, domain: str) -> Dict[str, Any]:
        if not keys.virustotal: return {}
        if not await async_acquire("virustotal"): return {}
        
        headers = {"x-apikey": keys.virustotal}
        try:
            async with session.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=10) as r:
                if r.status == 200:
                    data = await r.json()
                    return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        except Exception as e:
            log.debug(f"[Domain] VT failed: {e}")
        return {}

    async def _task_crt(self, session: aiohttp.ClientSession, domain: str) -> List[str]:
        try:
            async with session.get(f"https://crt.sh/?q={domain}&output=json", timeout=15) as r:
                if r.status == 200:
                    data = await r.json()
                    return list(set(cert.get("name_value") for cert in data))
        except Exception as e:
            log.debug(f"[Domain] crt.sh failed: {e}")
        return []

    async def _task_harvester(self, domain: str) -> Dict[str, Any]:
        harvester_path = shutil.which("theHarvester")
        if not harvester_path:
            return {"error": "theHarvester not installed"}
        
        out_file = f"outputs/{domain}_harvest"
        try:
            process = await asyncio.create_subprocess_exec(
                "python3", harvester_path, "-d", domain, "-b", "google,bing,shodan", "-f", out_file,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            await asyncio.wait_for(process.wait(), timeout=120)
            return {"file": out_file}
        except Exception as e:
            log.warning(f"[Domain] theHarvester failed: {e}")
            return {"error": str(e)}

# Legacy wrappers
async def analyze_domain(domain: str) -> Dict[str, Any]:
    plugin = DomainPlugin()
    return await plugin.run(domain)

def lookup_domain(domain: str) -> Dict[str, Any]:
    """Synchronous wrapper for legacy CLI commands."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we are in an existing loop (unlikely for CLI), we can't run_until_complete.
            # But main.py commands are sync, so this is usually for fallback.
            try:
                nest_asyncio = __import__("nest_asyncio")
                nest_asyncio.apply()
            except ImportError:
                raise RuntimeError(
                    "Event loop is already running and nest_asyncio is not installed."
                )
    except Exception:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(analyze_domain(domain))

def run_harvester(domain: str) -> Dict[str, Any]:
    """Synchronous wrapper for harvesting."""
    plugin = DomainPlugin()
    try:
        loop = asyncio.get_event_loop()
    except Exception:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(plugin._task_harvester(domain))
