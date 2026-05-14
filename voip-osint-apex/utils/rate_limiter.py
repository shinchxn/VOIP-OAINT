"""
VoIP OSINT APEX v3.0 — API Rate Limiter
Prevents IP bans by strictly enforcing external API limits.
Thread-safe and async-aware.
"""

import asyncio
import time
import logging

log = logging.getLogger("rate_limiter")

class RateLimiter:
    """Token bucket / delay-based rate limiter for external APIs."""

    def __init__(self):
        # Default limits: max calls per rolling window (in seconds)
        # ipqs: 3/sec
        # shodan: 1/sec
        # abuseipdb: 5/sec
        # virustotal: 4/min (4/60s = 1/15s)
        
        self.limits = {
            "ipqs":       (3, 1.0),
            "shodan":     (1, 1.0),
            "abuseipdb":  (5, 1.0),
            "virustotal": (4, 60.0),
            "numverify":  (1, 1.0),
        }
        
        # State: api_name -> list of timestamps
        self._history = {name: [] for name in self.limits.keys()}
        self._lock = asyncio.Lock()

    async def wait(self, api_name: str) -> None:
        """
        Wait if necessary before making an API call to stay under limits.
        """
        if api_name not in self.limits:
            return  # No limit defined
            
        max_calls, window = self.limits[api_name]
        
        async with self._lock:
            now = time.time()
            history = self._history[api_name]
            
            # Clean up old timestamps outside the window
            history = [t for t in history if now - t < window]
            self._history[api_name] = history
            
            if len(history) >= max_calls:
                # We've hit the limit. Wait until the oldest call falls out of the window.
                oldest = history[0]
                sleep_time = (oldest + window) - now
                if sleep_time > 0:
                    log.debug(f"[RateLimiter] Throttling {api_name} for {sleep_time:.2f}s")
                    await asyncio.sleep(sleep_time)
            
            # Record the new call
            self._history[api_name].append(time.time())


# Singleton instance
_limiter = RateLimiter()

async def wait_for(api_name: str) -> None:
    """Helper to use the singleton limiter."""
    await _limiter.wait(api_name)
