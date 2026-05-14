"""
VoIP OSINT APEX — Threat Correlator
Correlates number, IP, and domain intel into a confidence-scored
attribution report with MITRE ATT&CK mappings.
"""

import json
import logging
import asyncio
from realtime import emit

log = logging.getLogger("threat_correlator")

# Known VoIP carrier → law enforcement contact portal mapping
# Sources: carrier transparency reports and LEA portals (public info)
_LEA_CONTACTS: dict[str, dict] = {
    "twilio":      {"legal": "legal@twilio.com",      "portal": "https://www.twilio.com/en-us/legal/privacy",   "display": "Twilio"},
    "vonage":      {"legal": "privacy@vonage.com",    "portal": "https://www.vonage.com/legal/privacy-policy/", "display": "Vonage"},
    "bandwidth":   {"legal": "legal@bandwidth.com",   "portal": "https://www.bandwidth.com/legal/",             "display": "Bandwidth"},
    "google":      {"legal": "N/A",                   "portal": "https://support.google.com/legal/troubleshooter/1114905", "display": "Google Voice"},
    "magicjack":   {"legal": "legal@magicjack.com",   "portal": "https://www.magicjack.com/privacy.html",       "display": "magicJack"},
    "ringcentral": {"legal": "legal@ringcentral.com", "portal": "https://www.ringcentral.com/legal/",           "display": "RingCentral"},
    "lingo":       {"legal": "legal@lingo.com",       "portal": "https://www.lingo.com/privacy",                "display": "Lingo"},
    "skype":       {"legal": "N/A",                   "portal": "https://www.microsoft.com/en-us/legal/",       "display": "Skype/Microsoft"},
}


def _carrier_lea(carrier: str) -> dict:
    """Look up LEA contact for a carrier name (case-insensitive substring match)."""
    if not carrier:
        return {}
    carrier_lower = carrier.lower()
    for key, info in _LEA_CONTACTS.items():
        if key in carrier_lower or carrier_lower in key:
            return info
    # Generic fallback: Google search for LEA page
    return {
        "legal": "N/A",
        "portal": f"https://www.google.com/search?q={carrier.replace(' ', '+')}+law+enforcement+legal+request",
        "display": carrier
    }


def correlate(number_data: dict, ip_data: dict, domain_data: dict, sip_data: list) -> dict:
    """
    Scores confidence 0–100 that the target is engaged in VoIP fraud/crime.
    Returns attribution hints, subpoena target, and MITRE ATT&CK mappings.
    """
    confidence = 0

    # Number-level signals
    if number_data.get("line_type") == "voip":    confidence += 20
    if number_data.get("disposable"):             confidence += 20
    if number_data.get("fraud_score", 0) > 75:   confidence += 15

    # IP-level signals
    if ip_data.get("is_vpn"):                     confidence += 15
    if ip_data.get("is_tor"):                     confidence += 10
    if ip_data.get("abuse_score", 0) > 50:        confidence += 10
    if ip_data.get("vt_malicious", 0) > 0:        confidence += 10

    confidence = min(confidence, 100)

    # Attribution hints
    attribution = []
    carrier = number_data.get("carrier", "")
    isp     = ip_data.get("isp", "")
    if carrier: attribution.append(f"Carrier: {carrier}")
    if isp:     attribution.append(f"ISP: {isp}")
    if sip_data and isinstance(sip_data, list) and len(sip_data) > 0:
        ua = sip_data[0].get("user_agent")
        if ua: attribution.append(f"User-Agent: {ua}")

    # Subpoena target — real LEA contact data
    lea = _carrier_lea(carrier)
    subpoena_target = {
        "platform":             lea.get("display", carrier or "Unknown"),
        "legal_contact":        lea.get("legal", "N/A"),
        "law_enforcement_url":  lea.get("portal", ""),
        "data_to_request": [
            "account registration IP",
            "payment records",
            "device fingerprint",
            "login history",
            "call detail records (CDR)",
            "subscriber name and address",
        ]
    }

    result = {
        "confidence":        confidence,
        "risk_level":        _risk_label(confidence),
        "attribution_hints": attribution,
        "subpoena_target":   subpoena_target,
        "mitre_mapping": [
            "T1566   – Phishing via VoIP",
            "T1598   – Spearphishing Voice (Vishing)",
            "T1036   – Masquerading",
            "T1090   – Proxy / VPN obfuscation",
            "T1583.3 – Acquire Infrastructure: VPS",
        ]
    }

    # Emit real-time event
    severity = "CRITICAL" if confidence >= 75 else "WARNING" if confidence >= 50 else "INFO"
    event_payload = {
        "confidence": confidence,
        "risk_level": result["risk_level"],
        "attribution_hints": attribution
    }
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(emit("CORRELATION_DONE", event_payload, severity=severity))
    except RuntimeError:
        asyncio.run(emit("CORRELATION_DONE", event_payload, severity=severity))

    return result


def _risk_label(confidence: int) -> str:
    if confidence >= 75: return "CRITICAL"
    if confidence >= 50: return "HIGH"
    if confidence >= 25: return "MEDIUM"
    return "LOW"
