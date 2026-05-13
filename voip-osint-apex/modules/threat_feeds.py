"""
Autonomous Threat Feed Integration
Checks an IP against multiple free VoIP/abuse blacklists.
Feeds are cached locally to avoid re-downloading on every run.
"""

import os
import time
import logging
import ipaddress
# pyrefly: ignore [missing-import]
import requests
from pathlib import Path
from typing import Optional

log = logging.getLogger("threat_feeds")

CACHE_DIR  = Path("outputs/feed_cache")
CACHE_TTL  = 3600 * 6   # 6 hours

FEEDS: dict[str, str] = {
    "emergingthreats" : "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "cinsscore"       : "https://cinsscore.com/list/ci-badguys.txt",
    "blocklist_de_voip": "https://lists.blocklist.de/lists/voip.txt",
    "blocklist_de_sip" : "https://lists.blocklist.de/lists/sip.txt",
    "stopforumspam"   : "https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt",
    "spamhaus_drop"   : "https://www.spamhaus.org/drop/drop.txt",
}


def check_threat_feeds(ip: str) -> dict:
    """
    Returns which threat feeds list this IP and a summary score.
    Uses local cache — refreshed every 6 hours.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    hits: list[str] = []
    errors: list[str] = []

    for name, url in FEEDS.items():
        try:
            feed_lines = _get_feed(name, url)
            if _ip_in_feed(ip, feed_lines):
                hits.append(name)
                log.warning(f"[ThreatFeed] {ip} found in → {name}")
        except Exception as e:
            errors.append(f"{name}: {e}")
            log.debug(f"[ThreatFeed] Feed error {name}: {e}")

    score = _calc_score(hits)
    return {
        "ip"              : ip,
        "blacklisted_on"  : hits,
        "blacklist_count" : len(hits),
        "threat_score"    : score,
        "threat_level"    : _level(score),
        "feed_errors"     : errors,
    }


def refresh_feeds():
    """Force re-download all feeds, ignoring cache TTL."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in FEEDS.items():
        path = CACHE_DIR / f"{name}.txt"
        _download_feed(url, path)
    log.info("[ThreatFeed] All feeds refreshed.")


# ── internals ───────────────────────────────────────────────

def _get_feed(name: str, url: str) -> list[str]:
    path = CACHE_DIR / f"{name}.txt"
    if path.exists() and (time.time() - path.stat().st_mtime) < CACHE_TTL:
        return path.read_text().splitlines()
    return _download_feed(url, path)


def _download_feed(url: str, path: Path) -> list[str]:
    r = requests.get(url, timeout=12)
    r.raise_for_status()
    lines = [
        l.strip() for l in r.text.splitlines()
        if l.strip() and not l.startswith("#")
    ]
    path.write_text("\n".join(lines))
    log.debug(f"[ThreatFeed] Downloaded {len(lines)} entries → {path.name}")
    return lines


def _ip_in_feed(ip: str, lines: list[str]) -> bool:
    """Handles both plain IPs and CIDR ranges in feed."""
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for entry in lines:
        entry = entry.split(";")[0].split("#")[0].strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if target in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ipaddress.ip_address(entry) == target:
                return True
        except ValueError:
            continue
    return False


def _calc_score(hits: list[str]) -> int:
    """0-100 threat score based on how many feeds flag this IP."""
    weights = {
        "blocklist_de_voip" : 25,   # VoIP-specific — highest weight
        "blocklist_de_sip"  : 25,
        "emergingthreats"   : 20,
        "cinsscore"         : 15,
        "spamhaus_drop"     : 10,
        "stopforumspam"     : 5,
    }
    return min(100, sum(weights.get(h, 10) for h in hits))


def _level(score: int) -> str:
    if score >= 60: return "CRITICAL"
    if score >= 35: return "HIGH"
    if score >= 15: return "MEDIUM"
    if score >  0:  return "LOW"
    return "CLEAN"
