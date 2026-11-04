"""Redis cache for TI lookups with in-memory fallback for tests."""
from __future__ import annotations

import json
import time
from typing import Any


class TICache:
    def __init__(self, redis_client=None, ttl_seconds: int = 3600):
        self.redis = redis_client
        self.ttl_seconds = ttl_seconds
        self._mem: dict[str, tuple[float, str]] = {}

    def get(self, key: str) -> dict[str, Any] | None:
        if self.redis is not None:
            try:
                data = self.redis.get(key)
                if data is not None:
                    return json.loads(data)
            except Exception:
                pass
        entry = self._mem.get(key)
        if not entry:
            return None
        expires_at, data = entry
        if time.time() > expires_at:
            self._mem.pop(key, None)
            return None
        try:
            return json.loads(data)
        except Exception:
            self._mem.pop(key, None)
            return None

    def set(self, key: str, value: dict[str, Any]) -> None:
        payload = json.dumps(value)
        if self.redis is not None:
            try:
                self.redis.setex(key, self.ttl_seconds, payload)
                return
            except Exception:
                pass
        self._mem[key] = (time.time() + self.ttl_seconds, payload)
