"""
VoIP OSINT APEX — Per-API Rate Limiter
Token bucket algorithm with per-service limits.
Prevents API key bans from aggressive querying.
"""

import time
import asyncio
import logging
import threading
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional

log = logging.getLogger("rate_limiter")


@dataclass
class _Bucket:
    """Token bucket for a single API service."""
    capacity: float         # max tokens
    refill_rate: float      # tokens per second
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.time)
    
    # We maintain both locks to support sync and async callers safely
    _sync_lock: threading.Lock = field(default_factory=threading.Lock)
    _async_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        self.tokens = self.capacity

    def acquire(self, timeout: float = 30.0) -> bool:
        """
        Synchronous wait for a token.
        """
        deadline = time.time() + timeout
        while True:
            with self._sync_lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True

            if time.time() >= deadline:
                return False

            wait = max(0.05, (1.0 - self.tokens) / self.refill_rate)
            wait = min(wait, deadline - time.time())
            if wait <= 0: return False
            time.sleep(wait)

    async def async_acquire(self, timeout: float = 30.0) -> bool:
        """
        Asynchronous wait for a token. Non-blocking for the event loop.
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            async with self._async_lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True

            now = asyncio.get_event_loop().time()
            if now >= deadline:
                return False

            wait = max(0.05, (1.0 - self.tokens) / self.refill_rate)
            wait = min(wait, deadline - now)
            if wait <= 0: return False
            await asyncio.sleep(wait)

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now


# ── Per-service rate limits ─────────────────────────────────
# Format: (max_burst, requests_per_second)

_SERVICE_LIMITS: Dict[str, Tuple[float, float]] = {
    "ipqs":           (2,  4.0 / 60),     # 4 req/min
    "shodan":         (1,  1.0),           # 1 req/sec
    "abuseipdb":      (3,  40.0 / 3600),   # 40 req/hr
    "virustotal":     (2,  3.0 / 60),      # 3 req/min
    "numverify":      (2,  10.0 / 60),     # 10 req/min
    "securitytrails": (1,  2.0 / 3600),    # 2 req/hr
    "hackertarget":   (2,  10.0 / 60),     # 10 req/min
    "hibp":           (1,  1.5 / 60),      # ~1 req/40s
}

_buckets: Dict[str, _Bucket] = {}
_global_sync_lock = threading.Lock()


def _get_bucket(service: str) -> Optional[_Bucket]:
    """Internal helper to get or create a bucket."""
    with _global_sync_lock:
        if service not in _buckets:
            if service in _SERVICE_LIMITS:
                cap, rate = _SERVICE_LIMITS[service]
                _buckets[service] = _Bucket(capacity=cap, refill_rate=rate)
            else:
                return None
        return _buckets[service]


def acquire(service: str, timeout: float = 30.0) -> bool:
    """Synchronous acquisition."""
    bucket = _get_bucket(service)
    if not bucket: return True
    
    acquired = bucket.acquire(timeout=timeout)
    if not acquired:
        log.warning(f"[RateLimit] Timeout waiting for {service} token ({timeout}s)")
    return acquired


async def async_acquire(service: str, timeout: float = 30.0) -> bool:
    """Asynchronous acquisition."""
    bucket = _get_bucket(service)
    if not bucket: return True
    
    acquired = await bucket.async_acquire(timeout=timeout)
    if not acquired:
        log.warning(f"[RateLimit] Timeout waiting for {service} token ({timeout}s)")
    return acquired


def register_service(name: str, capacity: float, requests_per_second: float):
    """Register a custom rate limit."""
    with _global_sync_lock:
        _buckets[name] = _Bucket(capacity=capacity, refill_rate=requests_per_second)
    log.debug(f"[RateLimit] Registered {name}: burst={capacity}, rate={requests_per_second}/s")
