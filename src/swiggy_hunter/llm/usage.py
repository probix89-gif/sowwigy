"""
Token usage tracker, per-day and per-agent. Persisted to disk. Enforces
daily cap globally. Emits a warning when crossing the warn threshold.
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import date
from pathlib import Path
from typing import Any


class UsageTracker:
    def __init__(self, path: str | Path, daily_limit: int, warn_at_percent: int = 85):
        self.path = Path(path)
        self.daily_limit = daily_limit
        self.warn_at = warn_at_percent
        self._lock = asyncio.Lock()
        self._data: dict[str, Any] = self._load()
        self._warned_today = False
        self.last_warning: str | None = None

    def _load(self) -> dict[str, Any]:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"days": {}}

    def _today_key(self) -> str:
        return date.today().isoformat()

    def _today(self) -> dict[str, Any]:
        days = self._data.setdefault("days", {})
        return days.setdefault(self._today_key(), {"total": 0, "by_agent": {}, "calls": 0})

    async def can_spend(self, estimated: int = 0) -> bool:
        async with self._lock:
            return self._today()["total"] + estimated <= self.daily_limit

    async def record(self, agent: str, prompt_tokens: int, completion_tokens: int,
                     thinking_tokens: int = 0) -> None:
        async with self._lock:
            t = self._today()
            total = prompt_tokens + completion_tokens + thinking_tokens
            t["total"] += total
            t["calls"] += 1
            t["by_agent"][agent] = t["by_agent"].get(agent, 0) + total
            self._flush_locked()
            self._check_warn_locked()

    def _check_warn_locked(self) -> None:
        t = self._today()["total"]
        pct = (t / self.daily_limit) * 100 if self.daily_limit else 0
        if pct >= self.warn_at and not self._warned_today:
            self._warned_today = True
            self.last_warning = (
                f"token usage at {pct:.1f}% of daily limit "
                f"({t:,}/{self.daily_limit:,})"
            )

    def _flush_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return json.loads(json.dumps(self._data))

    async def today(self) -> dict[str, Any]:
        async with self._lock:
            return json.loads(json.dumps(self._today()))

    async def reset_today(self) -> None:
        async with self._lock:
            self._data.setdefault("days", {})[self._today_key()] = {
                "total": 0, "by_agent": {}, "calls": 0,
            }
            self._warned_today = False
            self.last_warning = None
            self._flush_locked()
