"""Verdict cache and scan rate limit, in Redis (Docs/live_url_scanning.md, sections 5 and 6).

The verdict cache also keeps PhishGuard from contacting a site again for every scan of the same
URL, and the limit keeps it from being used to hammer a site. Keys hold hashes, never URLs.
Without Redis, or if Redis fails, scans still work: nothing is cached and nothing is limited.
"""

import json
import logging
import time
from typing import Any

import redis

log = logging.getLogger(__name__)


class ScanStore:
    def __init__(self, client: redis.Redis | None = None):
        self.client = client

    @classmethod
    def from_url(cls, url: str | None) -> "ScanStore":
        if not url:
            return cls()
        return cls(redis.Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1))

    def get(self, key: str) -> dict[str, Any] | None:
        if self.client is None:
            return None
        try:
            data = self.client.get(key)
        except redis.RedisError as error:
            log.warning("verdict cache unavailable: %s", type(error).__name__)
            return None
        return json.loads(data) if data is not None else None

    def set(self, key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        if self.client is None:
            return
        try:
            self.client.set(key, json.dumps(value), ex=ttl_seconds)
        except redis.RedisError as error:
            log.warning("verdict cache unavailable: %s", type(error).__name__)

    def allow(self, client_id: str, per_minute: int) -> bool:
        """Count one scan for this client in the current minute; False if over the limit."""
        if self.client is None or per_minute <= 0:
            return True
        key = f"phishguard:limit:{client_id}:{int(time.time() // 60)}"
        try:
            count = self.client.incr(key)
            self.client.expire(key, 120)
        except redis.RedisError as error:
            log.warning("rate limit unavailable: %s", type(error).__name__)
            return True
        return count <= per_minute
