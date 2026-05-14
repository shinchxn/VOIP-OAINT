"""
Passive DNS History
Tracks historical IP changes for a domain using free APIs:
  - HackerTarget (no key needed)
  - SecurityTrails (free tier key)
  - crt.sh (already used in domain module — extend here)
"""

import os
import logging
# pyrefly: ignore [missing-import]
import requests
from datetime import datetime
from typing import Optional
from utils.config import get_keys

log = logging.getLogger("passive_dns")
keys = get_keys()

HACKERTARGET_URL    = "https://api.hackertarget.com/hostsearch/"
SECURITYTRAILS_URL  = "https://api.securitytrails.com/v1/history/{domain}/dns/a"
CERTSH_URL          = "https://crt.sh/?q={domain}&output=json"


def passive_dns(domain: str) -> dict:
    """
    Aggregates passive DNS data from multiple free sources.
    Returns current hosts, historical IPs, and cert-based subdomains.
    """
    domain = domain.strip().lower()
    result = {
        "domain"          : domain,
        "current_hosts"   : [],
        "historical_ips"  : [],
        "cert_subdomains" : [],
        "sources_used"    : [],
        "errors"          : [],
    }

    # Source 1 — HackerTarget (no key)
    try:
        r = requests.get(HACKERTARGET_URL, params={"q": domain}, timeout=10)
        if "error" not in r.text.lower() and r.text.strip():
            result["current_hosts"] = _parse_hackertarget(r.text)
            result["sources_used"].append("hackertarget")
    except Exception as e:
        result["errors"].append(f"hackertarget: {e}")

    # Source 2 — SecurityTrails (key optional)
    st_key = keys.securitytrails
    if st_key:
        try:
            r = requests.get(
                SECURITYTRAILS_URL.format(domain=domain),
                headers={"apikey": st_key},
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()
            result["historical_ips"] = _parse_securitytrails(data)
            result["sources_used"].append("securitytrails")
        except Exception as e:
            result["errors"].append(f"securitytrails: {e}")
    else:
        log.debug("[PassiveDNS] No SECURITYTRAILS_KEY — skipping historical lookup.")

    # Source 3 — crt.sh subdomains
    try:
        r = requests.get(CERTSH_URL.format(domain=domain), timeout=10)
        r.raise_for_status()
        records = r.json()
        subs = {
            entry["name_value"].strip()
            for entry in records
            if "name_value" in entry
        }
        result["cert_subdomains"] = sorted(subs)
        result["sources_used"].append("crt.sh")
    except Exception as e:
        result["errors"].append(f"crt.sh: {e}")

    _summarize(result)
    return result


def ip_history_timeline(domain: str) -> list[dict]:
    """
    Returns a sorted timeline of IP changes:
    [{"date": "...", "ip": "...", "source": "..."}, ...]
    """
    data     = passive_dns(domain)
    timeline = []

    for host in data["current_hosts"]:
        timeline.append({"date": "current", "ip": host.get("ip"), "source": "hackertarget"})

    for record in data["historical_ips"]:
        for ip_entry in record.get("values", []):
            timeline.append({
                "date"   : record.get("first_seen", "unknown"),
                "ip"     : ip_entry.get("ip"),
                "source" : "securitytrails",
            })

    timeline.sort(key=lambda x: x["date"], reverse=True)
    return timeline


# ── parsers ──────────────────────────────────────────────────

def _parse_hackertarget(text: str) -> list[dict]:
    hosts = []
    for line in text.strip().splitlines():
        parts = line.split(",")
        if len(parts) == 2:
            hosts.append({"hostname": parts[0].strip(), "ip": parts[1].strip()})
    return hosts


def _parse_securitytrails(data: dict) -> list[dict]:
    return [
        {
            "first_seen" : record.get("first_seen"),
            "last_seen"  : record.get("last_seen"),
            "values"     : record.get("values", []),
        }
        for record in data.get("records", [])
    ]


def _summarize(result: dict):
    log.info(
        f"[PassiveDNS] {result['domain']} — "
        f"{len(result['current_hosts'])} hosts, "
        f"{len(result['historical_ips'])} history records, "
        f"{len(result['cert_subdomains'])} cert subdomains | "
        f"sources: {', '.join(result['sources_used'])}"
    )
