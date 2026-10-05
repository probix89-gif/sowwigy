"""
Behavior — higher-level human session behaviour.

Wraps TimingModel with:
  - warmup(): visit homepage + one asset before hitting an API
  - referer-aware pacing between flow steps
  - back-off on 403/429
  - session rotation on persistent block

The idea: a StealthSession calls Behavior before each request. Behavior
knows enough about where we are in a flow to keep things plausible.
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..logging_setup import get_logger
from .timing import TimingModel

log = get_logger(__name__)


@dataclass
class BehaviorState:
    warmed_up: bool = False
    consecutive_403: int = 0
    consecutive_429: int = 0
    last_status: int = 0
    cool_until: float = 0.0
    rotate_requested: bool = False
    hosts_seen: set[str] = field(default_factory=set)


class Behavior:
    def __init__(self, timing: TimingModel):
        self.timing = timing
        self.state = BehaviorState()

    # ------------------------------------------------------------------
    # pre-request
    # ------------------------------------------------------------------

    async def pre_request(self, url: str) -> None:
        # honor cool-down from a previous 403/429
        now = time.monotonic()
        if now < self.state.cool_until:
            await asyncio.sleep(self.state.cool_until - now)

        # human-like delay
        await self.timing.before_request()

        try:
            host = urlparse(url).netloc
            self.state.hosts_seen.add(host)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # post-request
    # ------------------------------------------------------------------

    def post_response(self, status: int, retry_after: int | None = None) -> None:
        self.state.last_status = status

        if status in (200, 201, 204, 301, 302, 304):
            self.state.consecutive_403 = 0
            self.state.consecutive_429 = 0
            return

        if status == 403:
            self.state.consecutive_403 += 1
            self.state.consecutive_429 = 0
            # exponential back-off
            cool = min(300, 20 * (2 ** (self.state.consecutive_403 - 1)))
            self.state.cool_until = time.monotonic() + cool
            log.warning("behavior.403", streak=self.state.consecutive_403, cool_s=cool)
            if self.state.consecutive_403 >= 3:
                self.state.rotate_requested = True
            return

        if status == 429:
            self.state.consecutive_429 += 1
            self.state.consecutive_403 = 0
            wait = retry_after or min(600, 30 * (2 ** (self.state.consecutive_429 - 1)))
            self.state.cool_until = time.monotonic() + wait
            log.warning("behavior.429", streak=self.state.consecutive_429, cool_s=wait)
            if self.state.consecutive_429 >= 3:
                self.state.rotate_requested = True
            return

        if 500 <= status < 600:
            # transient; small pause
            self.state.cool_until = time.monotonic() + random.uniform(2.0, 6.0)

    def should_rotate(self) -> bool:
        if self.state.rotate_requested:
            self.state.rotate_requested = False
            return True
        return False

    # ------------------------------------------------------------------
    # warmup
    # ------------------------------------------------------------------

    async def warmup(self, base_url: str, fetch=None) -> bool:
        """
        Optionally visit the homepage to acquire a fresh session cookie.
        `fetch` is an async callable(url) -> (status, headers, body).
        Returns True if warmup succeeded.
        """
        if self.state.warmed_up:
            return True
        if fetch is None:
            self.state.warmed_up = True
            return True

        try:
            await self.timing.before_request()
            status, _, _ = await fetch(base_url)
            self.post_response(status)
            self.state.warmed_up = 200 <= status < 400
            log.info("behavior.warmup", status=status, ok=self.state.warmed_up)
            return self.state.warmed_up
        except Exception:
            log.exception("behavior.warmup_failed")
            return False

    # ------------------------------------------------------------------
    # info
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        return {
            "warmed_up": self.state.warmed_up,
            "consecutive_403": self.state.consecutive_403,
            "consecutive_429": self.state.consecutive_429,
            "cool_down_remaining_s": max(0.0, self.state.cool_until - time.monotonic()),
            "timing": self.timing.stats(),
            "hosts_seen": sorted(self.state.hosts_seen),
        }
