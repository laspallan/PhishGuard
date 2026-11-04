"""Rate limiting helper (token bucket style)."""
from __future__ import annotations

import time


class RateLimiter:
    def __init__(self, rate_per_second: float, burst: int):
        self.rate_per_second = rate_per_second
        self.burst = burst
        self.tokens = burst
        self.updated_at = time.monotonic()

    def acquire(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.updated_at
        self.updated_at = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate_per_second)
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True

    def wait(self, sleep: float = 0.01) -> None:
        import time as _time

        while not self.acquire():
            _time.sleep(sleep)
