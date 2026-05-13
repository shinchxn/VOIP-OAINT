"""
Hybrid Cache Layer
Primary: Redis (if available)
Fallback: Local file-based cache (JSON) — zero external dependencies.
"""

import json
import time
import os
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("cache")

CACHE_DIR = Path("outputs/.cache")


class Cache:
    """Redis-first cache with automatic local JSON fallback."""

    def __init__(self, ttl: int = 3600):
        self.ttl = ttl
        self._redis = None
        self._use_redis = False
        self._init_redis()
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # ── Redis init ──────────────────────────────────────────

    def _init_redis(self):
        try:
            import redis
            r = redis.Redis(host="localhost", port=6379, db=0, socket_timeout=1)
            r.ping()
            self._redis = r
            self._use_redis = True
            log.debug("[Cache] Redis connected — using Redis backend.")
        except Exception:
            self._redis = None
            self._use_redis = False
            log.debug("[Cache] Redis unavailable — using local file cache.")

    # ── public API ──────────────────────────────────────────

    def get(self, key: str) -> Optional[dict]:
        if self._use_redis:
            return self._redis_get(key)
        return self._file_get(key)

    def set(self, key: str, value, ttl: int = None):
        ttl = ttl or self.ttl
        if self._use_redis:
            self._redis_set(key, value, ttl)
        else:
            self._file_set(key, value, ttl)

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def delete(self, key: str):
        if self._use_redis:
            try:
                self._redis.delete(key)
            except Exception:
                pass
        path = self._key_path(key)
        if path.exists():
            path.unlink()

    def clear(self):
        """Wipe all cached entries."""
        if self._use_redis:
            try:
                self._redis.flushdb()
            except Exception:
                pass
        for f in CACHE_DIR.glob("*.json"):
            f.unlink()
        log.info("[Cache] All entries cleared.")

    # ── Redis backend ───────────────────────────────────────

    def _redis_get(self, key: str) -> Optional[dict]:
        try:
            data = self._redis.get(key)
            return json.loads(data) if data else None
        except Exception:
            return self._file_get(key)

    def _redis_set(self, key: str, value, ttl: int):
        try:
            self._redis.setex(key, ttl, json.dumps(value, default=str))
        except Exception:
            pass

    # ── File backend ────────────────────────────────────────

    def _file_get(self, key: str) -> Optional[dict]:
        path = self._key_path(key)
        if not path.exists():
            return None
        try:
            with open(path, "r") as f:
                envelope = json.load(f)
            if time.time() > envelope.get("expires", 0):
                path.unlink(missing_ok=True)
                return None
            return envelope.get("data")
        except Exception:
            return None

    def _file_set(self, key: str, value, ttl: int):
        path = self._key_path(key)
        try:
            envelope = {
                "key":     key,
                "data":    value,
                "created": time.time(),
                "expires": time.time() + ttl,
            }
            with open(path, "w") as f:
                json.dump(envelope, f, default=str)
        except Exception as e:
            log.debug(f"[Cache] File write error: {e}")

    def _key_path(self, key: str) -> Path:
        safe = key.replace(":", "_").replace("/", "_").replace("\\", "_")
        return CACHE_DIR / f"{safe}.json"
