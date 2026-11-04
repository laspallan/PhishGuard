"""Cache for threat-intelligence lookups: Redis when configured, else a bounded in-memory dict.

Only complete, successful lookups are cached (see IntelService); errors such as HTTP 429 or a
timeout are not, so they are retried instead of being remembered as "clean".
"""

import json
import time
from collections import OrderedDict
from typing import Any


class TICache:
    def __init__(self, redis_client=None, ttl_seconds: int = 24 * 3600, max_entries: int = 10_000):
        self.redis = redis_client
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._mem: OrderedDict[str, tuple[float, str]] = OrderedDict()

    @classmethod
    def from_url(cls, redis_url: str | None, **kwargs) -> "TICache":
        if not redis_url:
            return cls(**kwargs)
        import redis

        return cls(redis.Redis.from_url(redis_url), **kwargs)

    def get(self, key: str) -> dict[str, Any] | None:
        if self.redis is not None:
            data = self.redis.get(key)
            return json.loads(data) if data is not None else None
        entry = self._mem.get(key)
        if entry is None:
            return None
        expires_at, data = entry
        if time.time() > expires_at:
            del self._mem[key]
            return None
        return json.loads(data)

    def set(self, key: str, value: dict[str, Any]) -> None:
        payload = json.dumps(value)
        if self.redis is not None:
            self.redis.setex(key, self.ttl_seconds, payload)
            return
        self._mem[key] = (time.time() + self.ttl_seconds, payload)
        self._mem.move_to_end(key)
        while len(self._mem) > self.max_entries:
            self._mem.popitem(last=False)
