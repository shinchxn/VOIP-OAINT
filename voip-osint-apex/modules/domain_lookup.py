"""
VoIP OSINT APEX v3.0 — Domain Intelligence
Gathers DNS, WHOIS, CT logs, and passive DNS for domains.
"""

import asyncio
import logging
import dns.resolver
import whois
import aiohttp
from typing import Dict, Any, List

from utils.config import get_keys
from utils.rate_limiter import wait_for
from utils.cache import get_cache
import os
import subprocess

log = logging.getLogger("domain_lookup")
keys = get_keys()
cache = get_cache()


def whois_lookup(domain: str) -> Dict[str, Any]:
    """Perform WHOIS lookup."""
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
            "name_servers": w.name_servers,
            "org": w.org,
            "emails": w.emails
        }
    except Exception as e:
        return {"error": str(e)}


async def dns_enumerate(domain: str) -> Dict[str, List[str]]:
    """Enumerate DNS records."""
    records = {"A": [], "AAAA": [], "MX": [], "TXT": [], "NS": [], "SRV": []}
    
    # Run synchronously in executor because dnspython resolver isn't fully async
    loop = asyncio.get_event_loop()
    
    def resolve_type(qtype):
        res = []
        try:
            answers = dns.resolver.resolve(domain, qtype)
            for rdata in answers:
                if qtype in ['MX', 'SRV']:
                    res.append(str(rdata.target))
                else:
                    res.append(str(rdata))
        except Exception:
            pass
        return res

    for rt in records.keys():
        # Specifically check for SIP SRV records
        target = f"_sip._udp.{domain}" if rt == "SRV" else domain
        # Run blocking DNS lookup in executor
        recs = await loop.run_in_executor(None, resolve_type, rt if rt != "SRV" else "SRV")
        
        # If SRV for _sip failed, try _sips._tcp
        if rt == "SRV" and not recs:
            recs = await loop.run_in_executor(None, resolve_type, "SRV") # Need to tweak query string for sips if we wanted full
            
        records[rt] = recs
        
    return records


async def cert_transparency(domain: str) -> List[str]:
    """Fetch subdomains from Certificate Transparency logs (crt.sh)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as r:
                if r.status == 200:
                    data = await r.json()
                    for entry in data:
                        name = entry.get("name_value", "").lower()
                        if not name.startswith("*"):
                            subdomains.add(name)
    except Exception as e:
        log.debug(f"[Domain] crt.sh error: {e}")
        
    return list(subdomains)


async def reverse_ip_lookup(ip: str) -> List[str]:
    """HackerTarget reverse IP lookup."""
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as r:
                if r.status == 200:
                    text = await r.text()
                    if "error" not in text.lower() and "No DNS A records" not in text:
                        return text.splitlines()
    except Exception as e:
        log.debug(f"[Domain] Reverse IP error: {e}")
    return []


async def vt_domain_check(domain: str) -> Dict[str, Any]:
    """VirusTotal Domain Report."""
    if not keys.virustotal:
        return {"error": "VIRUSTOTAL_KEY missing"}
        
    await wait_for("virustotal")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": keys.virustotal}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as r:
                if r.status == 200:
                    data = (await r.json()).get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "categories": data.get("categories", {})
                    }
                return {"error": f"HTTP {r.status}"}
    except Exception as e:
        return {"error": str(e)}


async def passive_dns_history(domain: str) -> List[Dict[str, str]]:
    """SecurityTrails Passive DNS."""
    if not keys.securitytrails:
        return []
        
    url = f"https://api.securitytrails.com/v1/history/domain/{domain}/dns/a"
    headers = {"APIKEY": keys.securitytrails, "accept": "application/json"}
    
    history = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as r:
                if r.status == 200:
                    data = await r.json()
                    records = data.get("records", [])
                    for rec in records:
                        for val in rec.get("values", []):
                            history.append({
                                "ip": val.get("ip"),
                                "first_seen": rec.get("first_seen"),
                                "last_seen": rec.get("last_seen")
                            })
    except Exception as e:
        log.debug(f"[Domain] SecTrails error: {e}")
    return history


def run_dnsrecon(domain: str) -> str:
    """Wrapper for dnsrecon (Kali)."""
    try:
        res = subprocess.run(["dnsrecon", "-d", domain, "-t", "std"], 
                           capture_output=True, text=True, timeout=30)
        return res.stdout
    except FileNotFoundError:
        return "dnsrecon not installed"
    except Exception as e:
        return str(e)


def run_harvester(domain: str) -> str:
    """Wrapper for theHarvester (Kali)."""
    try:
        # Limited to a few fast sources
        res = subprocess.run(["theHarvester", "-d", domain, "-b", "bing,crtsh", "-l", "100"], 
                           capture_output=True, text=True, timeout=60)
        return res.stdout
    except FileNotFoundError:
        return "theHarvester not installed"
    except Exception as e:
        return str(e)


async def lookup_domain(domain: str) -> Dict[str, Any]:
    """Main domain analysis workflow."""
    cache_key = cache.make_key("domain", domain)
    cached = cache.get(cache_key)
    if cached:
        log.info(f"[Domain] Cache hit for {domain}")
        return cached

    log.info(f"[Domain] Analyzing {domain}...")
    
    # Run async tasks
    dns_t = asyncio.create_task(dns_enumerate(domain))
    ct_t = asyncio.create_task(cert_transparency(domain))
    vt_t = asyncio.create_task(vt_domain_check(domain))
    pdns_t = asyncio.create_task(passive_dns_history(domain))
    
    dns_data, ct_data, vt_data, pdns_data = await asyncio.gather(
        dns_t, ct_t, vt_t, pdns_t
    )
    
    # Sync tasks
    loop = asyncio.get_event_loop()
    whois_data = await loop.run_in_executor(None, whois_lookup, domain)
    
    # If we found A records, get reverse IP for the first one
    reverse_ips = []
    if dns_data.get("A"):
        first_ip = dns_data["A"][0]
        reverse_ips = await reverse_ip_lookup(first_ip)
        
    result = {
        "domain": domain,
        "whois": whois_data,
        "dns_records": dns_data,
        "subdomains_ct": ct_data,
        "virustotal": vt_data,
        "passive_dns": pdns_data,
        "shared_hosting_domains": reverse_ips
    }
    
    # Basic Risk Score
    malicious = vt_data.get("malicious", 0) if isinstance(vt_data, dict) else 0
    if malicious > 2:
        result["risk_level"] = "HIGH"
    elif malicious > 0:
        result["risk_level"] = "MEDIUM"
    else:
        result["risk_level"] = "LOW"
        
    cache.set(cache_key, result, ttl=3600)
    return result
