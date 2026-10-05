"""
TimingModel — human-like delays between requests.

Real humans:
  - leave 200ms–2s between clicks
  - pause to think occasionally
  - occasionally zone out (burst pauses of 6–20s)
  - don't fire requests on a fixed cadence

The model produces:
  - a per-request delay before the next call
  - a "burst pause" decision occasionally
  - a "think pause" decision occasionally

The delay distribution is log-normal-ish, which matches actual click
interval data better than uniform.

The model is stateful per session: it tracks burst counter, and
naturally resets after pauses.
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field

from ..config import HumanTimingCfg


@dataclass
class TimingState:
    burst_count: int = 0
    last_request_ts: float = 0.0
    total_delays: float = 0.0
    total_pauses: int = 0
    total_bursts: int = 0


class TimingModel:
    def __init__(self, cfg: HumanTimingCfg, seed: int | None = None):
        self.cfg = cfg
        self._rng = random.Random(seed)
        self.state = TimingState()

    def _jitter_ms(self) -> int:
        # log-normal-ish: most delays are small, tail is longer
        base = self.cfg.base_delay_ms
        jitter = self.cfg.jitter_ms
        # sample from a beta-ish shape; mean ~ base + jitter/2
        u = self._rng.random()
        # weight toward smaller values
        w = u ** 1.6
        return int(base + w * jitter)

    async def before_request(self) -> None:
        """Called before each request. Awaits the human-like delay."""
        if not self.cfg.enabled:
            return

        # baseline inter-request delay
        delay_ms = self._jitter_ms()
        await asyncio.sleep(delay_ms / 1000.0)
        self.state.total_delays += delay_ms / 1000.0

        # think pause?
        if self._rng.random() < self.cfg.think_pauses_prob:
            t = self._rng.uniform(
                self.cfg.think_pause_min_s,
                self.cfg.think_pause_max_s,
            )
            await asyncio.sleep(t)
            self.state.total_pauses += 1

        # burst pause? (probability grows with burst counter)
        burst_p = self.cfg.burst_pause_prob * (1 + self.state.burst_count * 0.35)
        if self._rng.random() < burst_p:
            t = self._rng.uniform(
                self.cfg.burst_pause_min_s,
                self.cfg.burst_pause_max_s,
            )
            await asyncio.sleep(t)
            self.state.total_bursts += 1
            self.state.burst_count = 0
        else:
            self.state.burst_count += 1

        self.state.last_request_ts = time.time()

    def stats(self) -> dict:
        return {
            "total_delay_s": round(self.state.total_delays, 2),
            "pauses": self.state.total_pauses,
            "bursts": self.state.total_bursts,
            "burst_count": self.state.burst_count,
        }

    def reset(self) -> None:
        self.state = TimingState()
