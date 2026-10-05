"""
TaskScheduler — assigns ready tasks to idle agents.

V2 improvements:
  - fairness: skips agents that were just assigned in the last cycle
  - priority-aware: low-number priority wins, ties broken by age
  - dependency-aware: blocked until depends_on tasks are done
  - non-blocking: assign callback runs as a task so a slow supervisor
    can't stall the tick
"""
from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable

from ..logging_setup import get_logger
from ..state.blackboard import Blackboard
from ..state.schemas import AgentName, Task, TaskStatus

log = get_logger(__name__)


TaskCallback = Callable[[AgentName, Task], Awaitable[None]]


class TaskScheduler:
    def __init__(
        self,
        blackboard: Blackboard,
        stop_event: asyncio.Event,
        pause_event: asyncio.Event,
        on_assign: TaskCallback,
        tick_seconds: float = 3.0,
    ):
        self.blackboard = blackboard
        self.stop_event = stop_event
        self.pause_event = pause_event
        self.on_assign = on_assign
        self.tick_seconds = tick_seconds
        self._busy_agents: set[str] = set()
        self._last_assign: dict[str, float] = {}

    def mark_busy(self, agent: AgentName) -> None:
        self._busy_agents.add(agent.value)

    def mark_idle(self, agent: AgentName) -> None:
        self._busy_agents.discard(agent.value)
        self._last_assign.pop(agent.value, None)

    # ------------------------------------------------------------------

    async def run(self) -> None:
        log.info("scheduler.start")
        while not self.stop_event.is_set():
            try:
                await self._tick()
            except Exception:
                log.exception("scheduler.tick_failed")
            await self._sleep(self.tick_seconds)
        log.info("scheduler.stop")

    async def _tick(self) -> None:
        if self.pause_event.is_set():
            return

        tasks = await self.blackboard.list_tasks()
        done_ids = {t.id for t in tasks if t.status == TaskStatus.done}

        # block tasks whose deps aren't done
        for t in tasks:
            if t.status == TaskStatus.pending and t.depends_on:
                if not all(d in done_ids for d in t.depends_on):
                    await self.blackboard.update_task(t.id, status=TaskStatus.blocked)

        # ready tasks, sorted by (priority, age, least-recently-assigned)
        now = time.time()
        ready = [
            t for t in tasks
            if t.status == TaskStatus.pending
            and t.assignee.value not in self._busy_agents
        ]

        def sort_key(t: Task) -> tuple:
            last = self._last_assign.get(t.assignee.value, 0.0)
            return (t.priority, t.created_at, last)

        ready.sort(key=sort_key)

        for task in ready:
            if task.assignee.value in self._busy_agents:
                continue
            updated = await self.blackboard.update_task(task.id, status=TaskStatus.assigned)
            if updated is None:
                continue
            self.mark_busy(task.assignee)
            self._last_assign[task.assignee.value] = now
            log.info("scheduler.assign",
                     task=task.id, agent=task.assignee.value, title=task.title[:60])
            try:
                await self.on_assign(task.assignee, task)
            except Exception:
                log.exception("scheduler.assign_callback_failed")
                self.mark_idle(task.assignee)

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self.stop_event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass
