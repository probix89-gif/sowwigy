"""
Per-agent soft budgets. V2: bumped because we have 1B/day.

Each agent gets a ceiling so one runaway worker can't consume the whole
daily quota. Sum is under the global cap so it stays coherent.
"""
from __future__ import annotations

import asyncio
from typing import Any


V2_DEFAULT_CAPS: dict[str, int] = {
    "decision":       120_000_000,
    "recon":          120_000_000,
    "business_logic": 150_000_000,
    "research":        80_000_000,
    "validation":     130_000_000,
    "attacker":       200_000_000,
    "hermes":         180_000_000,
}


class AgentTokenBudget:
    def __init__(self, caps: dict[str, int] | None = None):
        self.caps = caps or dict(V2_DEFAULT_CAPS)
        self._spent: dict[str, int] = {k: 0 for k in self.caps}
        self._lock = asyncio.Lock()

    async def can_spend(self, agent: str, estimated: int = 0) -> bool:
        async with self._lock:
            cap = self.caps.get(agent, 100_000_000)
            return self._spent.get(agent, 0) + estimated <= cap

    async def record(self, agent: str, tokens: int) -> None:
        async with self._lock:
            self._spent[agent] = self._spent.get(agent, 0) + tokens

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                a: {"spent": s, "cap": self.caps.get(a, 0)}
                for a, s in self._spent.items()
            }

    async def reset(self, agent: str | None = None) -> None:
        async with self._lock:
            if agent is None:
                for a in self._spent:
                    self._spent[a] = 0
            else:
                self._spent[agent] = 0
