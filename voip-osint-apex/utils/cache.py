import redis
import json

class Cache:
    def __init__(self):
        try:
            self.r = redis.Redis(host="localhost", port=6379, db=0)
        except Exception:
            self.r = None

    def get(self, key):
        if not self.r: return None
        try:
            data = self.r.get(key)
            return json.loads(data) if data else None
        except Exception:
            return None

    def set(self, key, value, ttl=3600):
        if not self.r: return
        try:
            self.r.setex(key, ttl, json.dumps(value))
        except Exception:
            pass

    def exists(self, key):
        if not self.r: return False
        try:
            return self.r.exists(key)
        except Exception:
            return False
