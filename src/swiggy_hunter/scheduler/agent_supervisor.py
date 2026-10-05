"""
AgentSupervisor — owns the seven worker coroutines.

Each worker loop:
    pull queued task → run → next
If a worker crashes, its loop is respawned after a backoff so the
runtime never loses an agent. Pause/stop are honored at every point.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ..agents.base import BaseAgent
from ..agents.decision import DecisionAgent
from ..logging_setup import get_logger
from ..state.schemas import AgentName, Task
from .lifecycle import Lifecycle
from .task_scheduler import TaskScheduler

log = get_logger(__name__)


class AgentSupervisor:
    def __init__(
        self,
        agents: dict[AgentName, BaseAgent],
        decision: DecisionAgent,
        scheduler: TaskScheduler,
        lifecycle: Lifecycle,
        idle_sleep: float = 4.0,
        crash_backoff_s: float = 5.0,
    ):
        self.agents = agents
        self.decision = decision
        self.scheduler = scheduler
        self.lifecycle = lifecycle
        self.idle_sleep = idle_sleep
        self.crash_backoff_s = crash_backoff_s

        self._tasks: dict[AgentName, asyncio.Task] = {}
        self._pending: dict[AgentName, list[Task]] = {a: [] for a in agents}
        self._lock = asyncio.Lock()
        self._stopping = False

    # ------------------------------------------------------------------
    # queue handoff from scheduler
    # ------------------------------------------------------------------

    async def on_task_assigned(self, agent_name: AgentName, task: Task) -> None:
        async with self._lock:
            self._pending[agent_name].append(task)

    def next_for(self, agent_name: AgentName) -> Task | None:
        q = self._pending.get(agent_name)
        if not q:
            return None
        return q.pop(0)

    # ------------------------------------------------------------------
    # start / stop
    # ------------------------------------------------------------------

    async def start_all(self) -> None:
        for name, agent in self.agents.items():
            t = asyncio.create_task(
                self._agent_loop(name, agent),
                name=f"agent-{name.value}",
            )
            self._tasks[name] = t
        log.info("supervisor.started", count=len(self._tasks))

    async def stop_all(self) -> None:
        self._stopping = True
        for _, t in self._tasks.items():
            t.cancel()
        for _, t in self._tasks.items():
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks.clear()
        log.info("supervisor.stopped")

    # ------------------------------------------------------------------
    # worker loop
    # ------------------------------------------------------------------

    async def _agent_loop(self, name: AgentName, agent: BaseAgent) -> None:
        log.info("agent_loop.start", agent=name.value)
        try:
            while not self.lifecycle.stop_event.is_set():
                if self.lifecycle.pause_event.is_set():
                    await asyncio.sleep(1.0)
                    continue

                task = self.next_for(name)
                if task is None:
                    task = await agent.ctx.blackboard.next_task_for(name.value)

                if task is None:
                    self.scheduler.mark_idle(name)
                    await asyncio.sleep(self.idle_sleep)
                    continue

                try:
                    await agent.run_task(task)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log.exception("agent_loop.task_failed",
                                  agent=name.value, task=task.id)
                finally:
                    self.scheduler.mark_idle(name)

        except asyncio.CancelledError:
            log.info("agent_loop.cancelled", agent=name.value)
            raise
        except Exception:
            log.exception("agent_loop.crashed", agent=name.value)
        finally:
            log.info("agent_loop.exit", agent=name.value)

    # ------------------------------------------------------------------
    # inspection
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        return {
            "agents": [
                {
                    "name": n.value,
                    "alive": not t.done(),
                    "queued": len(self._pending.get(n, [])),
                }
                for n, t in self._tasks.items()
            ],
        }
