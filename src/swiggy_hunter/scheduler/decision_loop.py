"""
DecisionLoop — periodic planning cycles.

V2 additions:
  - fires early when directives are pending
  - fires early on critical findings (external trigger)
  - stall detection with an automatic pivot note
"""
from __future__ import annotations

import asyncio
import time

from ..agents.decision import DecisionAgent
from ..logging_setup import get_logger
from ..state.blackboard import Blackboard

log = get_logger(__name__)


class DecisionLoop:
    def __init__(
        self,
        decision: DecisionAgent,
        blackboard: Blackboard,
        stop_event: asyncio.Event,
        pause_event: asyncio.Event,
        interval_s: float = 90.0,
        directive_poll_s: float = 4.0,
        stall_threshold: int = 5,
    ):
        self.decision = decision
        self.blackboard = blackboard
        self.stop_event = stop_event
        self.pause_event = pause_event
        self.interval_s = interval_s
        self.directive_poll_s = directive_poll_s
        self.stall_threshold = stall_threshold

        self._last_finding_count = 0
        self._last_task_count = 0
        self._stall_cycles = 0
        self._trigger = asyncio.Event()
        self._last_cycle_ts = 0.0

    def trigger_now(self) -> None:
        self._trigger.set()

    # ------------------------------------------------------------------

    async def run(self) -> None:
        log.info("decision_loop.start", interval=self.interval_s)
        await asyncio.sleep(2.0)

        while not self.stop_event.is_set():
            if self.pause_event.is_set():
                await asyncio.sleep(1.0)
                continue

            now = time.monotonic()
            since = now - self._last_cycle_ts

            # decide whether to run now
            should_run = False
            if self._trigger.is_set():
                should_run = True
            elif since >= self.interval_s:
                should_run = True
            else:
                # check for pending directives; if any, fire soon
                if self._pending_directives():
                    if since >= self.directive_poll_s:
                        should_run = True

            if should_run:
                self._trigger.clear()
                self._last_cycle_ts = time.monotonic()
                try:
                    await self._cycle()
                except Exception:
                    log.exception("decision_loop.cycle_failed")
                await asyncio.sleep(1.0)
            else:
                await asyncio.sleep(0.8)

        log.info("decision_loop.stop")

    def _pending_directives(self) -> bool:
        try:
            return bool(self.decision.directives.pending(limit=1))
        except Exception:
            return False

    # ------------------------------------------------------------------

    async def _cycle(self) -> None:
        result = await self.decision.run_decision_cycle()
        findings = await self.blackboard.list_findings()
        tasks = await self.blackboard.list_tasks()

        new_findings = len(findings) - self._last_finding_count
        new_tasks = len(tasks) - self._last_task_count
        self._last_finding_count = len(findings)
        self._last_task_count = len(tasks)

        if new_findings == 0 and new_tasks == 0:
            self._stall_cycles += 1
        else:
            self._stall_cycles = 0

        log.info(
            "decision_loop.cycle",
            ok=result.get("ok"),
            created=len(result.get("created_tasks", [])),
            replied=result.get("replied", False),
            new_findings=new_findings,
            stall=self._stall_cycles,
        )

        if self._stall_cycles >= self.stall_threshold:
            log.warning("decision_loop.stalled", cycles=self._stall_cycles)
            await self.blackboard.set_narrative(
                notes=(
                    f"Stall detected: {self._stall_cycles} cycles with no new "
                    f"findings or tasks. Pivot strategy: try a new subdomain, "
                    f"a new flow, or a new class of business-logic test."
                ),
            )
            self._stall_cycles = 0
