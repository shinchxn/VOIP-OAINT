"""
VoIP OSINT APEX — OSINT Engine
Email intelligence, domain harvesting, and DNS reconnaissance.
"""

import subprocess
import json
import shutil
import logging
# pyrefly: ignore [missing-import]
import requests

from utils.config import get_keys

log = logging.getLogger("osint_engine")
keys = get_keys()


def platform_check(email):
    """Check email against platform databases using holehe."""
    holehe_path = shutil.which("holehe")
    if not holehe_path:
        log.warning("[OSINT] holehe not installed — run: pip install holehe")
        return {"output": "holehe not installed — run: pip install holehe"}

    try:
        result = subprocess.run(
            ["holehe", email, "--only-used"],
            capture_output=True, text=True, timeout=60
        )
        return {"output": result.stdout}
    except subprocess.TimeoutExpired:
        log.warning(f"[OSINT] holehe timed out for {email}")
        return {"output": "holehe timed out"}
    except OSError as e:
        log.warning(f"[OSINT] Failed to run holehe: {e}")
        return {"output": f"holehe error: {e}"}


def harvester_osint(domain):
    """Run theHarvester for domain intelligence gathering."""
    out_file = f"outputs/{domain}_harvest"

    harvester_path = shutil.which("theHarvester")
    if not harvester_path:
        for candidate in ["/opt/theHarvester/theHarvester.py", "/usr/local/bin/theHarvester"]:
            import os
            if os.path.isfile(candidate):
                harvester_path = candidate
                break

    if not harvester_path:
        log.warning("[OSINT] theHarvester not found — install it or add to PATH")
        return {"error": "theHarvester not installed"}

    try:
        subprocess.run(
            ["python3", harvester_path, "-d", domain, "-b", "google,bing,shodan", "-f", out_file],
            capture_output=True, text=True, timeout=120
        )

        try:
            with open(f"{out_file}.json", "r") as f:
                data = json.load(f)
                return data
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log.debug(f"[OSINT] Could not read harvester output: {e}")
            return {"file": out_file}
    except subprocess.TimeoutExpired:
        log.warning(f"[OSINT] theHarvester timed out for {domain}")
        return {"error": "theHarvester timed out"}
    except OSError as e:
        log.warning(f"[OSINT] Failed to run theHarvester: {e}")
        return {"error": str(e)}


def dnsrecon_scan(domain):
    """Run DNSRecon for DNS enumeration."""
    dnsrecon_path = shutil.which("dnsrecon")
    if not dnsrecon_path:
        for candidate in ["/opt/dnsrecon/dnsrecon.py"]:
            import os
            if os.path.isfile(candidate):
                dnsrecon_path = candidate
                break

    if not dnsrecon_path:
        log.warning("[OSINT] dnsrecon not found — install it or add to PATH")
        return {"error": "dnsrecon not installed"}

    try:
        result = subprocess.run(
            ["python3", dnsrecon_path, "-d", domain, "-t", "std,brt"],
            capture_output=True, text=True, timeout=120
        )
        return {"output": result.stdout}
    except subprocess.TimeoutExpired:
        log.warning(f"[OSINT] dnsrecon timed out for {domain}")
        return {"error": "dnsrecon timed out"}
    except OSError as e:
        log.warning(f"[OSINT] Failed to run dnsrecon: {e}")
        return {"error": str(e)}


def check_leaked_db(identifier):
    """Check identifier against Have I Been Pwned (requires API key)."""
    if not keys.hibp:
        log.debug("[OSINT] HIBP API key not configured — skipping breach check")
        return {"status": "skipped", "reason": "HIBP_KEY not configured in .env"}

    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{identifier}",
            headers={
                "hibp-api-key": keys.hibp,
                "User-Agent": "VoIP-OSINT-APEX-LEA"
            },
            timeout=10
        )
        if r.status_code == 200:
            return {"breaches": r.json()}
        elif r.status_code == 404:
            return {"breaches": []}
        elif r.status_code == 401:
            log.warning("[OSINT] HIBP: Invalid API key")
            return {"status": "error", "reason": "Invalid HIBP API key"}
        elif r.status_code == 429:
            log.warning("[OSINT] HIBP: Rate limited")
            return {"status": "rate_limited"}
        else:
            log.warning(f"[OSINT] HIBP returned HTTP {r.status_code}")
            return {"status": "error", "http_code": r.status_code}
    except requests.ConnectionError as e:
        log.warning(f"[OSINT] HIBP connection failed: {e}")
        return {"status": "error", "reason": "Connection failed"}
    except requests.Timeout:
        log.warning("[OSINT] HIBP request timed out")
        return {"status": "error", "reason": "Timeout"}
    except requests.RequestException as e:
        log.warning(f"[OSINT] HIBP request error: {e}")
        return {"status": "error", "reason": str(e)}
