"""
Lifecycle — the runtime state machine.

States:
    IDLE       created, not started
    RUNNING    active
    PAUSED     workers blocked on pause_event
    STOPPING   shutdown in progress
    STOPPED    clean exit
    EMERGENCY  killed by operator

Every control action (start/pause/resume/stop/emergency/restart) funnels
through here. Telegram commands and the orchestrator both mutate state
via this object. Listeners get notified on every transition.
"""
from __future__ import annotations

import asyncio
import time
from enum import Enum
from typing import Awaitable, Callable

from ..logging_setup import get_logger

log = get_logger(__name__)


class RunState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    EMERGENCY = "emergency"


class Lifecycle:
    def __init__(self) -> None:
        self.state: RunState = RunState.IDLE
        self._lock = asyncio.Lock()
        self.stop_event = asyncio.Event()
        self.pause_event = asyncio.Event()
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self.paused_at: float | None = None
        self._listeners: list[Callable[[RunState], Awaitable[None]]] = []

    def on_change(self, cb: Callable[[RunState], Awaitable[None]]) -> None:
        self._listeners.append(cb)

    async def _emit(self) -> None:
        for cb in self._listeners:
            try:
                await cb(self.state)
            except Exception:
                log.exception("lifecycle.listener_failed")

    async def start(self) -> bool:
        async with self._lock:
            if self.state not in (RunState.IDLE, RunState.STOPPED):
                return False
            self.stop_event.clear()
            self.pause_event.clear()
            self.state = RunState.RUNNING
            self.started_at = time.time()
            self.stopped_at = None
            self.paused_at = None
        await self._emit()
        log.info("lifecycle.start")
        return True

    async def pause(self) -> bool:
        async with self._lock:
            if self.state != RunState.RUNNING:
                return False
            self.pause_event.set()
            self.state = RunState.PAUSED
            self.paused_at = time.time()
        await self._emit()
        log.info("lifecycle.pause")
        return True

    async def resume(self) -> bool:
        async with self._lock:
            if self.state != RunState.PAUSED:
                return False
            self.pause_event.clear()
            self.state = RunState.RUNNING
            self.paused_at = None
        await self._emit()
        log.info("lifecycle.resume")
        return True

    async def stop(self, emergency: bool = False) -> bool:
        async with self._lock:
            if self.state in (RunState.STOPPING, RunState.STOPPED):
                return False
            self.state = RunState.STOPPING
            self.stop_event.set()
        await self._emit()
        log.info("lifecycle.stop", emergency=emergency)
        await asyncio.sleep(0.5)
        async with self._lock:
            self.state = RunState.EMERGENCY if emergency else RunState.STOPPED
            self.stopped_at = time.time()
        await self._emit()
        log.info("lifecycle.stopped", state=self.state.value)
        return True

    async def restart(self) -> bool:
        await self.stop()
        await asyncio.sleep(0.5)
        return await self.start()

    def snapshot(self) -> dict:
        return {
            "state": self.state.value,
            "started_at": self.started_at,
            "paused_at": self.paused_at,
            "stopped_at": self.stopped_at,
            "uptime_s": (
                time.time() - self.started_at
                if self.started_at and self.state == RunState.RUNNING
                else 0
            ),
        }
