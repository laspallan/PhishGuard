"""Async sliding-window rate limits for the threat-intelligence APIs.

`acquire()` waits (with asyncio.sleep, so the API keeps serving other requests) until a request
fits in the per-minute window, and returns False without waiting when the per-day quota is used
up. VirusTotal's public API allows 4 requests per minute and 500 per day
(https://docs.virustotal.com/reference/public-vs-premium-api, read 2026-11-02).
"""

import asyncio
import time
from collections import deque
from collections.abc import Awaitable, Callable

MINUTE, DAY = 60.0, 86_400.0


class RateLimiter:
    def __init__(
        self,
        per_minute: int,
        per_day: int | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.per_minute = per_minute
        self.per_day = per_day
        self._clock = clock
        self._sleep = sleep
        self._minute: deque[float] = deque()
        self._day: deque[float] = deque()
        self._lock = asyncio.Lock()

    @staticmethod
    def _drop_older(window: deque[float], now: float, span: float) -> None:
        while window and now - window[0] >= span:
            window.popleft()

    async def acquire(self) -> bool:
        async with self._lock:
            now = self._clock()
            self._drop_older(self._day, now, DAY)
            if self.per_day is not None and len(self._day) >= self.per_day:
                return False
            self._drop_older(self._minute, now, MINUTE)
            while len(self._minute) >= self.per_minute:
                await self._sleep(MINUTE - (now - self._minute[0]))
                now = self._clock()
                self._drop_older(self._minute, now, MINUTE)
            self._minute.append(now)
            self._day.append(now)
            return True
