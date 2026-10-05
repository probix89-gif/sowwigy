"""
ThinkingController — enforces the 12–32s reasoning window.

Why: GLM-5.3-Flash can answer instantly, but for the main agents
(decision + attacker) we want depth. The controller:

  1. Wraps a single LLM call.
  2. Measures wall-clock time.
  3. If faster than min_seconds: sleep the remainder.
  4. If the underlying call runs past max_seconds: it is not aborted
     (network calls can't be cleanly cancelled mid-response), but we
     log a warning and record a soft violation.

Optional "extended thinking" prompt injection:
  When enabled, the first call asks the model for a short reasoning
  pass; the second call uses that reasoning as a scratchpad. This is
  opt-in per agent because it doubles token cost.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

from ..logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class ThinkingResult:
    elapsed_s: float
    padded: bool
    over_max: bool
    under_min_original: float


class ThinkingController:
    def __init__(
        self,
        enabled: bool,
        min_seconds: float = 12.0,
        max_seconds: float = 32.0,
        agents: list[str] | None = None,
    ):
        self.enabled = enabled
        self.min_seconds = min_seconds
        self.max_seconds = max_seconds
        self.agents = set(agents or [])

    def applies_to(self, agent: str) -> bool:
        if not self.enabled:
            return False
        return agent in self.agents

    async def wrap(
        self,
        agent: str,
        call: Callable[[], Awaitable[dict]],
    ) -> tuple[dict, ThinkingResult]:
        """
        Run the LLM call, pad the total wall time to at least min_seconds
        for thinking agents. Return (response, timing info).
        """
        if not self.applies_to(agent):
            start = time.monotonic()
            resp = await call()
            elapsed = time.monotonic() - start
            return resp, ThinkingResult(
                elapsed_s=elapsed, padded=False, over_max=False,
                under_min_original=elapsed,
            )

        start = time.monotonic()
        resp = await call()
        original = time.monotonic() - start

        over_max = original > self.max_seconds
        if over_max:
            log.warning(
                "thinking.over_max",
                agent=agent,
                elapsed=original,
                max_seconds=self.max_seconds,
            )

        padded = False
        if original < self.min_seconds:
            pad = self.min_seconds - original
            await asyncio.sleep(pad)
            padded = True

        elapsed = time.monotonic() - start
        log.info(
            "thinking.window",
            agent=agent,
            elapsed=round(elapsed, 2),
            original=round(original, 2),
            padded=padded,
            over_max=over_max,
        )
        return resp, ThinkingResult(
            elapsed_s=elapsed,
            padded=padded,
            over_max=over_max,
            under_min_original=original,
        )

    def describe(self) -> dict:
        return {
            "enabled": self.enabled,
            "min_seconds": self.min_seconds,
            "max_seconds": self.max_seconds,
            "agents": sorted(self.agents),
        }
