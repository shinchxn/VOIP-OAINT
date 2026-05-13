# pyrefly: ignore [missing-import]
import aiohttp
import asyncio
import os
import socket
# pyrefly: ignore [missing-import]
from ipwhois import IPWhois
from dotenv import load_dotenv
from utils.cache import Cache

load_dotenv()
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
SHODAN_KEY = os.getenv("SHODAN_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
cache = Cache()

async def fetch_json(session, url, headers=None, method='GET'):
    try:
        if method == 'GET':
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200: return await response.json()
        elif method == 'POST':
            async with session.post(url, headers=headers, timeout=10) as response:
                if response.status == 200: return await response.json()
    except:
        return {}
    return {}

async def task_ip_api(session, ip):
    return await fetch_json(session, f"http://ip-api.com/json/{ip}")

async def task_abuseipdb(session, ip):
    if not ABUSEIPDB_KEY or ABUSEIPDB_KEY == "your_key": return {}
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    return await fetch_json(session, f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers)

async def task_shodan(session, ip):
    if not SHODAN_KEY or SHODAN_KEY == "your_key": return {}
    return await fetch_json(session, f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}")

async def task_proxycheck(session, ip):
    return await fetch_json(session, f"http://proxycheck.io/v2/{ip}?vpn=1&asn=1")

async def task_tor(session, ip):
    try:
        async with session.get("https://dan.me.uk/torlist/", timeout=5) as r:
            if r.status == 200:
                text = await r.text()
                return {"is_tor": ip in text}
    except:
        pass
    return {"is_tor": False}

async def task_vt(session, ip):
    if not VIRUSTOTAL_KEY or VIRUSTOTAL_KEY == "your_key": return {}
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    return await fetch_json(session, f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers)

def sync_whois(ip):
    try:
        obj = IPWhois(ip)
        return obj.lookup_rdap()
    except:
        return {}

def sync_rdns(ip):
    try:
        return {"hostname": socket.gethostbyaddr(ip)[0]}
    except:
        return {}

async def analyze_ip(ip: str) -> dict:
    cache_key = f"ip:{ip}"
    cached = cache.get(cache_key)
    if cached: return cached

    async with aiohttp.ClientSession() as session:
        ip_api, abuse, shodan, proxy, tor, vt = await asyncio.gather(
            task_ip_api(session, ip),
            task_abuseipdb(session, ip),
            task_shodan(session, ip),
            task_proxycheck(session, ip),
            task_tor(session, ip),
            task_vt(session, ip)
        )

    rdap = await asyncio.to_thread(sync_whois, ip)
    rdns = await asyncio.to_thread(sync_rdns, ip)

    result = {
        "ip": ip,
        "country": ip_api.get("country", "Unknown"),
        "city": ip_api.get("city", "Unknown"),
        "isp": ip_api.get("isp", "Unknown"),
        "org": ip_api.get("org", "Unknown"),
        "is_vpn": proxy.get(ip, {}).get("vpn", "no") == "yes",
        "is_tor": tor.get("is_tor", False),
        "is_proxy": proxy.get(ip, {}).get("proxy", "no") == "yes",
        "hosting": ip_api.get("hosting", False),
        "abuse_score": abuse.get("data", {}).get("abuseConfidenceScore", 0),
        "total_reports": abuse.get("data", {}).get("totalReports", 0),
        "vt_malicious": vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
        "ports": shodan.get("ports", []),
        "hostnames": shodan.get("hostnames", []) + [rdns.get("hostname", "")] ,
        "asn": rdap.get("asn", "Unknown"),
        "asn_description": rdap.get("asn_description", "Unknown")
    }

    score = result["abuse_score"]
    if result["is_tor"]:
        result["risk_level"] = "CRITICAL"
    elif result["is_vpn"] or score > 50:
        result["risk_level"] = "HIGH"
    elif result["hosting"]:
        result["risk_level"] = "MEDIUM"
    else:
        result["risk_level"] = "LOW"

    cache.set(cache_key, result)
    return result
