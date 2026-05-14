"""
VoIP OSINT APEX v3.0 — IP Intelligence
Gathers threat data from IPWhois, Shodan, AbuseIPDB, VirusTotal, ProxyCheck, and Tor.
"""

import asyncio
import logging
import socket
import aiohttp
from ipwhois import IPWhois
import shodan
from typing import Dict, Any, Tuple

from utils.config import get_keys
from utils.rate_limiter import wait_for
from utils.cache import get_cache
from realtime import emit

log = logging.getLogger("ip_intel")
keys = get_keys()
cache = get_cache()


async def geo_lookup(ip: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
    """Lookup IP geolocation and basic ASN info."""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,lat,lon,timezone,mobile,proxy,hosting,query"
    try:
        async with session.get(url, timeout=10) as r:
            if r.status == 200:
                data = await r.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "mobile": data.get("mobile", False),
                        "proxy": data.get("proxy", False),
                        "hosting": data.get("hosting", False),
                    }
                return {"error": data.get("message", "Failed")}
            return {"error": f"HTTP {r.status}"}
    except Exception as e:
        return {"error": str(e)}


async def abuse_check(ip: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
    """Check AbuseIPDB for reports."""
    if not keys.abuseipdb:
        return {"error": "ABUSEIPDB_KEY missing"}
        
    await wait_for("abuseipdb")
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": keys.abuseipdb
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    
    try:
        async with session.get(url, headers=headers, params=params, timeout=10) as r:
            if r.status == 200:
                data = (await r.json()).get("data", {})
                return {
                    "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                    "totalReports": data.get("totalReports", 0),
                    "lastReportedAt": data.get("lastReportedAt"),
                    "usageType": data.get("usageType"),
                    "domain": data.get("domain"),
                    "isp": data.get("isp")
                }
            return {"error": f"HTTP {r.status}"}
    except Exception as e:
        return {"error": str(e)}


def shodan_lookup(ip: str) -> Dict[str, Any]:
    """Check Shodan for open ports, vulnerabilities, and hostnames."""
    if not keys.shodan:
        return {"error": "SHODAN_KEY missing"}
        
    try:
        # Rate limit handled synchronously here or wrapper
        api = shodan.Shodan(keys.shodan)
        host = api.host(ip)
        return {
            "ports": host.get("ports", []),
            "hostnames": host.get("hostnames", []),
            "org": host.get("org", ""),
            "tags": host.get("tags", []),
            "vulns": host.get("vulns", []),
            "last_update": host.get("last_update", ""),
            "country_code": host.get("country_code", ""),
            "isp": host.get("isp", ""),
            "domains": host.get("domains", [])
        }
    except shodan.APIError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


async def virustotal_ip(ip: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
    """Check IP against VirusTotal."""
    if not keys.virustotal:
        return {"error": "VIRUSTOTAL_KEY missing"}
        
    await wait_for("virustotal")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": keys.virustotal}
    
    try:
        async with session.get(url, headers=headers, timeout=10) as r:
            if r.status == 200:
                data = (await r.json()).get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }
            return {"error": f"HTTP {r.status}"}
    except Exception as e:
        return {"error": str(e)}


async def proxy_check(ip: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
    """Check proxycheck.io for VPN/Proxy status."""
    url = f"http://proxycheck.io/v2/{ip}?vpn=1&asn=1"
    try:
        async with session.get(url, timeout=10) as r:
            if r.status == 200:
                data = await r.json()
                if data.get("status") == "ok":
                    ip_data = data.get(ip, {})
                    return {
                        "proxy": ip_data.get("proxy") == "yes",
                        "vpn": ip_data.get("type") == "VPN",
                        "type": ip_data.get("type", ""),
                        "provider": ip_data.get("provider", ""),
                        "asn": ip_data.get("asn", ""),
                        "range": ip_data.get("range", "")
                    }
            return {"error": f"HTTP {r.status}"}
    except Exception as e:
        return {"error": str(e)}


def tor_check(ip: str) -> bool:
    """Check if IP is a Tor exit node."""
    tor_cache_key = "voip:tor:exit_list"
    exit_nodes = cache.get(tor_cache_key)
    
    if not exit_nodes:
        # We need it sync here, or run loop. Let's do a quick sync fetch
        import requests
        try:
            r = requests.get("https://dan.me.uk/torlist/", timeout=5)
            if r.status_code == 200:
                exit_nodes = [line for line in r.text.splitlines() if not line.startswith("#")]
                cache.set(tor_cache_key, exit_nodes, ttl=21600)
        except Exception:
            exit_nodes = []
            
    return ip in exit_nodes


def rdap_lookup(ip: str) -> Dict[str, Any]:
    """RDAP lookup for ownership/routing info."""
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        
        network = result.get("network", {})
        return {
            "asn": result.get("asn", ""),
            "asn_description": result.get("asn_description", ""),
            "asn_country_code": result.get("asn_country_code", ""),
            "network_name": network.get("name", ""),
            "network_cidr": network.get("cidr", "")
        }
    except Exception as e:
        return {"error": str(e)}


def reverse_dns(ip: str) -> str:
    """Reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "N/A"


def correlate_ip_risk(data: Dict[str, Any]) -> Tuple[str, str]:
    """Determine overall IP risk level."""
    is_tor = data.get("tor_node", False)
    abuse_score = data.get("abuseipdb", {}).get("abuseConfidenceScore", 0)
    is_vpn = data.get("proxycheck", {}).get("vpn", False)
    hosting = data.get("geo", {}).get("hosting", False)
    
    if is_tor and abuse_score > 50:
        return ("CRITICAL", "Tor exit + abuse history")
    elif is_vpn and abuse_score > 30:
        return ("HIGH", "VPN with reported abuse")
    elif is_vpn:
        return ("HIGH", "VPN/Proxy detected")
    elif abuse_score > 50:
        return ("HIGH", "Heavy abuse report history")
    elif hosting:
        return ("MEDIUM", "Hosted/datacenter IP")
    else:
        return ("LOW", "Clean IP")


async def analyze_ip(ip: str) -> Dict[str, Any]:
    """Main IP intelligence function."""
    cache_key = cache.make_key("ip", ip)
    cached = cache.get(cache_key)
    if cached:
        log.info(f"[IPIntel] Cache hit for {ip}")
        return cached

    log.info(f"[IPIntel] Analyzing {ip}...")
    
    async with aiohttp.ClientSession() as session:
        geo_t = asyncio.create_task(geo_lookup(ip, session))
        abuse_t = asyncio.create_task(abuse_check(ip, session))
        vt_t = asyncio.create_task(virustotal_ip(ip, session))
        proxy_t = asyncio.create_task(proxy_check(ip, session))
        
        geo_data, abuse_data, vt_data, proxy_data = await asyncio.gather(
            geo_t, abuse_t, vt_t, proxy_t
        )
        
    # Sync calls
    loop = asyncio.get_event_loop()
    shodan_data = await loop.run_in_executor(None, shodan_lookup, ip)
    is_tor = await loop.run_in_executor(None, tor_check, ip)
    rdap_data = await loop.run_in_executor(None, rdap_lookup, ip)
    rev_dns = await loop.run_in_executor(None, reverse_dns, ip)
    
    result = {
        "ip": ip,
        "geo": geo_data,
        "abuseipdb": abuse_data,
        "virustotal": vt_data,
        "proxycheck": proxy_data,
        "shodan": shodan_data,
        "tor_node": is_tor,
        "rdap": rdap_data,
        "hostname": rev_dns
    }
    
    level, reason = correlate_ip_risk(result)
    result["risk_level"] = level
    result["risk_reason"] = reason
    
    # Emit realtime event for high risk
    if level in ["CRITICAL", "HIGH"]:
        await emit("THREAT_HIT", {"ip": ip, "reason": reason}, severity=level)
        
    cache.set(cache_key, result, ttl=3600)
    return result
