"""
BaseAgent v2 — the shared execution loop.

Same skeleton as v1 but V2-aware:
  - surfaces auth status in every task digest
  - honors the thinking window transparently (LLMClient pads)
  - auto-rotates session on persistent 403/429 via behavior
  - streams tool events to the telegram bot
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any

from ..llm.client import BudgetExceeded
from ..llm.prompts import AGENT_PROMPTS
from ..logging_setup import get_logger
from ..state.schemas import AgentName, AgentStatus, Task, TaskStatus
from ..tools.base import ToolRegistry
from .context import AgentContext

log = get_logger(__name__)


@dataclass
class AgentRunResult:
    task_id: str
    status: TaskStatus
    summary: str
    iterations: int
    elapsed_s: float
    tool_calls: int
    stopped_early: bool = False


class BaseAgent:
    name: AgentName = AgentName.recon  # overridden
    max_iterations: int = 30
    max_tool_calls_per_turn: int = 6
    allow_tools: list[str] | None = None
    temperature: float = 0.5

    def __init__(self, ctx: AgentContext):
        self.ctx = ctx
        self.registry: ToolRegistry = ctx.registry
        self.status = AgentStatus(name=self.name)

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    async def run_task(self, task: Task) -> AgentRunResult:
        await self._set_status("working", task.id)
        await self._update_task(task.id, status=TaskStatus.running)

        start = time.monotonic()
        iterations = 0
        tool_calls = 0
        stopped_early = False
        final_content = ""

        messages = await self._initial_messages(task)

        try:
            while iterations < self.max_iterations:
                if self.ctx.is_stopped():
                    stopped_early = True
                    final_content = final_content or "stopped by operator"
                    break
                await self.ctx.wait_if_paused()
                if self.ctx.is_stopped():
                    stopped_early = True
                    final_content = final_content or "stopped by operator"
                    break

                if not await self.ctx.budget.can_spend(self.name.value, estimated=2000):
                    final_content = "agent token budget exhausted"
                    break

                iterations += 1
                assistant = await self._call_llm(messages)

                tool_calls_in_turn = assistant.get("tool_calls") or []
                content = assistant.get("content") or ""

                messages.append(self._assistant_message(assistant))

                if not tool_calls_in_turn:
                    final_content = content or final_content
                    break

                if len(tool_calls_in_turn) > self.max_tool_calls_per_turn:
                    tool_calls_in_turn = tool_calls_in_turn[: self.max_tool_calls_per_turn]

                for tc in tool_calls_in_turn:
                    tool_calls += 1
                    result = await self._dispatch_tool(tc)
                    messages.append(self._tool_message(tc["id"], result))

                if content:
                    final_content = content

                await self._emit_progress("iteration", {
                    "iteration": iterations, "tool_calls": tool_calls,
                })

        except BudgetExceeded as e:
            final_content = f"budget exhausted: {e}"
            log.warning("agent.budget", agent=self.name.value, task=task.id)
        except asyncio.CancelledError:
            stopped_early = True
            final_content = "cancelled"
            raise
        except Exception as e:
            final_content = f"error: {type(e).__name__}: {e}"
            log.exception("agent.failed", agent=self.name.value, task=task.id)

        elapsed = time.monotonic() - start
        status = TaskStatus.done if not stopped_early and not final_content.startswith("error") else TaskStatus.failed
        if stopped_early:
            status = TaskStatus.failed

        summary = final_content.strip()[:4000] or "(no output)"
        await self._update_task(task.id, status=status, result=summary)
        await self._set_status("idle", None)

        return AgentRunResult(
            task_id=task.id, status=status, summary=summary,
            iterations=iterations, elapsed_s=elapsed,
            tool_calls=tool_calls, stopped_early=stopped_early,
        )

    async def run_cycle(self) -> AgentRunResult | None:
        task = await self.ctx.blackboard.next_task_for(self.name.value)
        if task is None:
            return None
        await self._update_task(task.id, status=TaskStatus.assigned)
        return await self.run_task(task)

    # ------------------------------------------------------------------
    # message construction
    # ------------------------------------------------------------------

    async def _initial_messages(self, task: Task) -> list[dict[str, Any]]:
        system = AGENT_PROMPTS.get(self.name.value, AGENT_PROMPTS["recon"])
        digest = await self._blackboard_digest()
        task_block = self._render_task(task)

        user = (
            f"# Task\n{task_block}\n\n"
            f"# Shared State\n{digest}\n\n"
            f"# Runtime\n{self._runtime_digest()}\n\n"
            f"Work the task. Use tools decisively. report_finding is ONLY "
            f"for demonstrated high-impact business-rule violations with "
            f"raw evidence and repro steps — everything else is preserved "
            f"as an internal observation automatically. When the task is "
            f"complete, respond with a short plain-text summary and stop "
            f"calling tools."
        )
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

    def _render_task(self, task: Task) -> str:
        lines = [
            f"- id: {task.id}",
            f"- title: {task.title}",
            f"- description: {task.description or '(none)'}",
            f"- priority: {task.priority}",
        ]
        if task.finding_ids:
            lines.append(f"- linked findings: {', '.join(task.finding_ids)}")
        if task.meta:
            lines.append(f"- meta: {json.dumps(task.meta, default=str)}")
        return "\n".join(lines)

    async def _blackboard_digest(self) -> str:
        findings = await self.ctx.blackboard.list_findings()
        tasks = await self.ctx.blackboard.list_tasks()
        agents = await self.ctx.blackboard.agent_statuses()
        observations = await self.ctx.blackboard.list_observations(limit=50)

        recent_findings = findings[:10]
        open_tasks = [t for t in tasks if t.status.value in ("pending", "assigned", "running")][:15]

        f_lines = [
            f"  [{f.severity.value}] {f.id} {f.status.value} :: {f.title} ({f.category})"
            for f in recent_findings
        ] or ["  (none)"]
        o_lines = [
            f"  {o.id} [{o.impact_category or o.category}] {o.title[:70]}"
            for o in observations[:8]
        ] or ["  (none)"]
        t_lines = [
            f"  p{t.priority} {t.id} {t.assignee.value}:{t.status.value} :: {t.title}"
            for t in open_tasks
        ] or ["  (none)"]
        a_lines = [
            f"  {a.name.value}: {a.state}"
            + (f" (task {a.current_task_id})" if a.current_task_id else "")
            for a in agents
        ] or ["  (none)"]

        return "\n".join([
            f"Findings (last 10 of {len(findings)} — only gate-passing candidates):",
            *f_lines,
            "",
            f"Internal observations (last 8 of {len(observations)} — gate-rejected "
            "candidates; correlate them into chains before reporting):",
            *o_lines,
            "",
            f"Open tasks (of {len(tasks)}):",
            *t_lines,
            "",
            "Agent status:",
            *a_lines,
        ])

    def _runtime_digest(self) -> str:
        auth = self.ctx.auth_status()
        stealth = self.ctx.stealth_status()
        lines = [
            f"- target: {self.ctx.config.target.domain}",
            f"- authenticated: {auth.get('authenticated')}",
        ]
        if auth.get("phone"):
            lines.append(f"- phone: {auth['phone']}")
        if auth.get("cookies"):
            lines.append(f"- cookies: {auth['cookies']}")
        if stealth:
            lines.append(f"- fingerprint: {stealth.get('fingerprint')}")
            lines.append(f"- requests this session: {stealth.get('requests')}")
            beh = stealth.get("behavior") or {}
            if beh.get("consecutive_403") or beh.get("consecutive_429"):
                lines.append(
                    f"- recent blocks: 403x{beh.get('consecutive_403')} "
                    f"429x{beh.get('consecutive_429')}"
                )
            cd = beh.get("cool_down_remaining_s") or 0
            if cd > 0.5:
                lines.append(f"- cool-down remaining: {cd:.1f}s")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # LLM + tool loop
    # ------------------------------------------------------------------

    async def _call_llm(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        schemas = self.registry.schemas(allow=self.allow_tools)
        return await self.ctx.llm.chat(
            agent=self.name.value,
            messages=messages,
            temperature=self.temperature,
            tools=schemas,
        )

    async def _dispatch_tool(self, tool_call: dict[str, Any]) -> str:
        fn = tool_call.get("function") or {}
        name = fn.get("name", "")
        raw_args = fn.get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except json.JSONDecodeError:
            args = {}

        log.info("tool.call", agent=self.name.value, tool=name)
        result = await self.registry.dispatch(name, args)

        # surface finding events
        if name == "report_finding" and result.ok:
            fid = (result.meta or {}).get("finding_id")
            if fid:
                f = await self.ctx.blackboard.get_finding(fid)
                if f:
                    await self.ctx.notify_finding(f)

        await self._emit_progress("tool", {
            "tool": name, "ok": result.ok, "ms": result.elapsed_ms,
        })
        return result.to_content()

    def _assistant_message(self, assistant: dict[str, Any]) -> dict[str, Any]:
        msg: dict[str, Any] = {"role": "assistant"}
        msg["content"] = assistant.get("content") or ""
        if assistant.get("tool_calls"):
            msg["tool_calls"] = assistant["tool_calls"]
        return msg

    def _tool_message(self, tool_call_id: str, content: str) -> dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": content,
        }

    # ------------------------------------------------------------------
    # status / task
    # ------------------------------------------------------------------

    async def _set_status(self, state: str, current_task_id: str | None) -> None:
        self.status = AgentStatus(
            name=self.name,
            state=state,  # type: ignore[arg-type]
            current_task_id=current_task_id,
            last_heartbeat=time.time(),
        )
        await self.ctx.blackboard.set_agent_status(self.status)

    async def _update_task(self, tid: str, *, status: TaskStatus, result: str | None = None) -> None:
        updated = await self.ctx.blackboard.update_task(tid, status=status, result=result)
        if updated:
            await self.ctx.notify_task(updated)

    async def _emit_progress(self, kind: str, payload: dict[str, Any]) -> None:
        await self.ctx.notify_progress(self.name.value, {"kind": kind, **payload})

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "max_iterations": self.max_iterations,
            "tools": self.allow_tools or self.registry.names(),
        }
