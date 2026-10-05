"""
Sliding-window rate limiter for the shared LLM key.

45 RPM, safety margin, concurrency cap. Guarantees no more than N
acquisitions in any rolling 60-second window across all agents.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque


class SlidingWindowRateLimiter:
    def __init__(self, limit_per_minute: int, safety_margin: int = 1, max_concurrent: int = 3):
        self.limit = max(1, limit_per_minute - safety_margin)
        self.window = 60.0
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(max_concurrent)

    async def _wait_for_slot(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                while self._timestamps and now - self._timestamps[0] >= self.window:
                    self._timestamps.popleft()
                if len(self._timestamps) < self.limit:
                    self._timestamps.append(now)
                    return
                sleep_for = self.window - (now - self._timestamps[0]) + 0.01
            await asyncio.sleep(sleep_for)

    async def acquire(self) -> None:
        await self._sem.acquire()
        try:
            await self._wait_for_slot()
        except BaseException:
            self._sem.release()
            raise

    def release(self) -> None:
        self._sem.release()

    class _Ctx:
        def __init__(self, parent: "SlidingWindowRateLimiter"):
            self.parent = parent

        async def __aenter__(self):
            await self.parent.acquire()
            return self

        async def __aexit__(self, *exc):
            self.parent.release()

    def __call__(self):
        return self._Ctx(self)

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *exc):
        self.release()

    def stats(self) -> dict:
        now = time.monotonic()
        in_window = sum(1 for t in self._timestamps if now - t < self.window)
        return {
            "limit": self.limit,
            "window_s": self.window,
            "in_window": in_window,
            "remaining": max(0, self.limit - in_window),
        }
