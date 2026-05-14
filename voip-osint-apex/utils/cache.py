"""
VoIP OSINT APEX v3.0 — Redis Cache with In-Memory Fallback
Key format: "voip:{module}:{identifier}"
Falls back to in-memory dict if Redis is unavailable.
"""

import json
import logging
import time
from typing import Any, Optional

try:
    import redis
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False

log = logging.getLogger("cache")

# ── In-memory fallback ──────────────────────────────────────

class _MemoryStore:
    """Simple TTL-aware in-memory cache."""

    def __init__(self):
        self._store: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        if key not in self._store:
            return None
        value, expires_at = self._store[key]
        if expires_at and time.time() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        expires_at = time.time() + ttl if ttl else 0
        self._store[key] = (value, expires_at)

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def flush_pattern(self, pattern: str) -> int:
        prefix = pattern.rstrip("*")
        keys = [k for k in self._store if k.startswith(prefix)]
        for k in keys:
            del self._store[k]
        return len(keys)


# ── Main Cache class ────────────────────────────────────────

class Cache:
    """
    Redis-backed cache with automatic in-memory fallback.
    All keys are namespaced as: voip:{module}:{identifier}
    """

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        self._redis: Optional[Any] = None
        self._memory = _MemoryStore()
        self._using_redis = False

        if _REDIS_AVAILABLE:
            try:
                self._redis = redis.Redis(
                    host=host, port=port, db=db,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                    decode_responses=True,
                )
                self._redis.ping()
                self._using_redis = True
                log.info("[Cache] Connected to Redis.")
            except Exception as e:
                log.warning(f"[Cache] Redis unavailable ({e}) — using in-memory fallback.")
                self._redis = None
        else:
            log.warning("[Cache] redis package not installed — using in-memory fallback.")

    @staticmethod
    def make_key(module: str, identifier: str) -> str:
        """Build a namespaced cache key."""
        return f"voip:{module}:{identifier}"

    # ── Redis operations (with fallback) ───────────────────

    def get(self, key: str) -> Optional[dict]:
        """Retrieve a cached value. Returns dict or None."""
        try:
            if self._using_redis and self._redis:
                raw = self._redis.get(key)
                if raw:
                    return json.loads(raw)
                return None
        except Exception as e:
            log.debug(f"[Cache] Redis get failed: {e}")
        return self._memory.get(key)

    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Store a value with TTL (seconds)."""
        try:
            if self._using_redis and self._redis:
                self._redis.setex(key, ttl, json.dumps(value, default=str))
                return
        except Exception as e:
            log.debug(f"[Cache] Redis set failed: {e}")
        self._memory.set(key, value, ttl)

    def exists(self, key: str) -> bool:
        """Check if a key exists."""
        try:
            if self._using_redis and self._redis:
                return bool(self._redis.exists(key))
        except Exception:
            pass
        return self._memory.exists(key)

    def delete(self, key: str) -> None:
        """Delete a specific key."""
        try:
            if self._using_redis and self._redis:
                self._redis.delete(key)
        except Exception:
            pass
        self._memory.delete(key)

    def flush_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern (e.g. 'voip:ip:*')."""
        count = 0
        try:
            if self._using_redis and self._redis:
                keys = list(self._redis.scan_iter(pattern))
                if keys:
                    count = self._redis.delete(*keys)
                return count
        except Exception as e:
            log.debug(f"[Cache] Redis flush_pattern failed: {e}")
        return self._memory.flush_pattern(pattern)

    def health(self) -> dict:
        return {
            "backend": "redis" if self._using_redis else "memory",
            "healthy": self._using_redis or True,
        }


# ── Singleton ───────────────────────────────────────────────

_cache_instance: Optional[Cache] = None


def get_cache() -> Cache:
    """Get singleton Cache instance (initialised from AppConfig)."""
    global _cache_instance
    if _cache_instance is None:
        from utils.config import get_config
        cfg = get_config()
        _cache_instance = Cache(host=cfg.redis_host, port=cfg.redis_port)
    return _cache_instance
