"""
Per-host request pacing + cool-down after 403/429.

Used by stealth_race to make sure even burst tests don't blow the
per-host rps budget. Steering, not enforcement — stealth_http already
paces via TimingModel, but the race helper bypasses that layer for
concurrency, so it consults the governor instead.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from ..logging_setup import get_logger

log = get_logger(__name__)


class RateGovernor:
    def __init__(self, default_rps: float = 5.0, cooldown_seconds: float = 45.0):
        self.default_rps = default_rps
        self.cooldown_seconds = cooldown_seconds
        self._host_rps: dict[str, float] = {}
        self._timestamps: dict[str, deque[float]] = defaultdict(deque)
        self._cooldown_until: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def set_host_rps(self, host: str, rps: float) -> None:
        self._host_rps[host] = max(0.1, rps)

    def rps_for(self, host: str) -> float:
        return self._host_rps.get(host, self.default_rps)

    async def acquire(self, url: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return
        async with self._locks[host]:
            now = time.monotonic()
            cd = self._cooldown_until.get(host, 0.0)
            if now < cd:
                await asyncio.sleep(cd - now)

            rps = self.rps_for(host)
            cap = max(1, int(rps))
            dq = self._timestamps[host]
            now = time.monotonic()
            while dq and now - dq[0] >= 1.0:
                dq.popleft()
            if len(dq) >= cap:
                wait = 1.0 - (now - dq[0]) + 0.01
                await asyncio.sleep(wait)
                now = time.monotonic()
                while dq and now - dq[0] >= 1.0:
                    dq.popleft()
            dq.append(time.monotonic())

    def note_response(self, url: str, status: int) -> None:
        host = (urlparse(url).hostname or "").lower()
        if status in (429, 403):
            self._cooldown_until[host] = time.monotonic() + self.cooldown_seconds
            log.warning("rate_governor.cooldown", host=host, status=status,
                        seconds=self.cooldown_seconds)

    def snapshot(self) -> dict:
        now = time.monotonic()
        return {
            "host_rps": dict(self._host_rps),
            "cooldowns": {
                h: max(0.0, u - now)
                for h, u in self._cooldown_until.items() if u > now
            },
            "default_rps": self.default_rps,
        }
