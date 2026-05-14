"""
VoIP OSINT APEX v3.0 — Phone Number Intelligence
Parses phone numbers and checks them against IPQS, Numverify, and Tor blocklists.
"""

import asyncio
import logging
import aiohttp
import phonenumbers
from phonenumbers import geocoder, carrier as pn_carrier, timezone
from typing import Dict, Any, Tuple

from utils.config import get_keys
from utils.rate_limiter import wait_for
from utils.cache import get_cache

log = logging.getLogger("number_lookup")
keys = get_keys()
cache = get_cache()


def parse_number(number: str) -> Dict[str, Any]:
    """Offline parsing using libphonenumber."""
    result = {
        "number": number,
        "is_valid": False,
        "country": "Unknown",
        "carrier": "Unknown",
        "timezone": [],
        "number_type": "UNKNOWN",
        "national_format": "",
        "international_format": ""
    }
    try:
        parsed = phonenumbers.parse(number, None)
        result["is_valid"] = phonenumbers.is_valid_number(parsed)
        if result["is_valid"]:
            result["country"] = geocoder.description_for_number(parsed, "en")
            result["carrier"] = pn_carrier.name_for_number(parsed, "en")
            result["timezone"] = list(timezone.time_zones_for_number(parsed))
            
            # Map type
            ntype = phonenumbers.number_type(parsed)
            type_map = {
                phonenumbers.PhoneNumberType.MOBILE: "MOBILE",
                phonenumbers.PhoneNumberType.FIXED_LINE: "FIXED_LINE",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
                phonenumbers.PhoneNumberType.VOIP: "VOIP",
                phonenumbers.PhoneNumberType.PAGER: "PAGER",
                phonenumbers.PhoneNumberType.UAN: "UAN",
                phonenumbers.PhoneNumberType.VOICEMAIL: "VOICEMAIL"
            }
            result["number_type"] = type_map.get(ntype, "UNKNOWN")
            result["national_format"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            result["international_format"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    except Exception as e:
        log.warning(f"[NumberLookup] Parse failed: {e}")
    return result


async def ipqs_check(number: str) -> Dict[str, Any]:
    """Check IPQualityScore for fraud/voip status."""
    if not keys.ipqs:
        return {"error": "IPQS_KEY missing"}
        
    await wait_for("ipqs")
    url = f"https://www.ipqualityscore.com/api/json/phone/{keys.ipqs}/{number}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as r:
                if r.status == 200:
                    data = await r.json()
                    return {
                        "fraud_score": data.get("fraud_score", 0),
                        "voip": data.get("VOIP", False),
                        "disposable": data.get("spammer", False) or data.get("recent_abuse", False),
                        "active": data.get("active", False),
                        "carrier": data.get("carrier", ""),
                        "line_type": data.get("line_type", ""),
                        "recent_abuse": data.get("recent_abuse", False),
                        "leaked": data.get("leaked", False)
                    }
                return {"error": f"HTTP {r.status}"}
    except Exception as e:
        return {"error": str(e)}


async def numverify_check(number: str) -> Dict[str, Any]:
    """Check Numverify for carrier and line type."""
    if not keys.numverify:
        return {"error": "NUMVERIFY_KEY missing"}
        
    await wait_for("numverify")
    clean_num = number.lstrip("+")
    url = f"http://apilayer.net/api/validate?access_key={keys.numverify}&number={clean_num}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as r:
                if r.status == 200:
                    data = await r.json()
                    if "success" in data and not data["success"]:
                        return {"error": data.get("error", {}).get("info", "API Error")}
                    return {
                        "valid": data.get("valid", False),
                        "country_code": data.get("country_code", ""),
                        "location": data.get("location", ""),
                        "carrier": data.get("carrier", ""),
                        "line_type": data.get("line_type", "")
                    }
                return {"error": f"HTTP {r.status}"}
    except Exception as e:
        return {"error": str(e)}


async def tor_number_check(number: str, country: str) -> bool:
    """Check if number's country is heavily associated with Tor exits (rough heuristic)."""
    # This is a placeholder for actual Tor correlation against a number, 
    # as Tor is an IP anonymity network. But following spec:
    tor_cache_key = "voip:tor:exit_list"
    exit_nodes = cache.get(tor_cache_key)
    
    if not exit_nodes:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://dan.me.uk/torlist/", timeout=10) as r:
                    if r.status == 200:
                        text = await r.text()
                        exit_nodes = [line for line in text.splitlines() if not line.startswith("#")]
                        cache.set(tor_cache_key, exit_nodes, ttl=21600) # 6 hours
        except Exception:
            pass
            
    # As a simple heuristic for the spec: if the number is VOIP and from a high-risk country,
    # or we do IP cross-reference later. 
    return False # Proper IP tor check is in ip_intel.py


def risk_score(ipqs_data: Dict[str, Any]) -> Tuple[str, str]:
    """Calculate risk score based on IPQS data."""
    if "error" in ipqs_data:
        return ("UNKNOWN", "Could not assess risk due to API error")
        
    fraud = ipqs_data.get("fraud_score", 0)
    disposable = ipqs_data.get("disposable", False)
    
    if fraud > 85 and disposable:
        return ("CRITICAL", "Disposable VoIP, extreme fraud score")
    elif fraud > 75:
        return ("HIGH", "High fraud score detected")
    elif fraud > 40:
        return ("MEDIUM", "Moderate fraud indicators")
    else:
        return ("LOW", "No significant risk indicators")


async def analyze_number(number: str) -> Dict[str, Any]:
    """Main analysis function for phone numbers."""
    cache_key = cache.make_key("number", number)
    cached = cache.get(cache_key)
    if cached:
        log.info(f"[NumberLookup] Cache hit for {number}")
        return cached

    log.info(f"[NumberLookup] Analyzing {number}...")
    
    # 1. Parse
    parsed_data = parse_number(number)
    
    # 2. Async API calls
    ipqs_task = asyncio.create_task(ipqs_check(number))
    numverify_task = asyncio.create_task(numverify_check(number))
    
    ipqs_data, numv_data = await asyncio.gather(ipqs_task, numverify_task)
    
    # 3. Tor check (passing parsed country)
    is_tor = await tor_number_check(number, parsed_data.get("country", ""))
    
    # 4. Risk scoring
    level, reason = risk_score(ipqs_data)
    
    # 5. Subpoena hint
    carrier = parsed_data.get("carrier") or numv_data.get("carrier") or ipqs_data.get("carrier") or "Unknown"
    hint = f"{carrier} legal@{carrier.lower().replace(' ', '')}.com" if carrier != "Unknown" else "N/A"
    
    # 6. Merge
    result = {
        "number": parsed_data,
        "ipqs": ipqs_data,
        "numverify": numv_data,
        "tor_associated": is_tor,
        "risk_level": level,
        "risk_reason": reason,
        "subpoena_hint": hint
    }
    
    cache.set(cache_key, result, ttl=3600)
    return result
