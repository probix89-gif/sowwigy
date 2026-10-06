"""
DecisionAgent v2 — planner + operator interlocutor.

Consumes directives from the DirectiveQueue (messages the operator
sent via telegram, plain or /ask /inject /note). Answers questions
through the operator_reply field of the plan JSON. Its reply is
routed back to telegram by the orchestrator.

Also writes the narrative sections of the blackboard and creates
tasks for the worker agents.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Awaitable, Callable

from ..directives import Directive, DirectiveQueue
from ..llm.client import BudgetExceeded
from ..llm.prompts import DECISION_MAKER_PROMPT
from ..logging_setup import get_logger
from ..state.schemas import AgentName, AgentStatus, Finding, Task
from .context import AgentContext

log = get_logger(__name__)


_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


class DecisionAgent:
    name = AgentName.decision
    temperature = 0.45

    # tools the decision-maker may use in its investigation phase,
    # before it emits the plan JSON. Shell access is included so the
    # planner can inspect the environment, check artifacts, run quick
    # read-only commands (ls, cat, grep, curl probes) to plan better.
    allow_tools = [
        "shell", "file_read", "file_list",
        "query_blackboard",
    ]
    max_investigation_iterations = 6
    max_tool_calls_per_turn = 4

    def __init__(self, ctx: AgentContext, directives: DirectiveQueue | None = None):
        self.ctx = ctx
        self.status = AgentStatus(name=self.name)
        self.directives = directives or DirectiveQueue(
            path=str(self.ctx.config.paths.directives)
        )
        self._reply_hook: Callable[[str], Awaitable[None]] | None = None

    def set_reply_hook(self, hook: Callable[[str], Awaitable[None]]) -> None:
        self._reply_hook = hook

    # ------------------------------------------------------------------
    # cycle
    # ------------------------------------------------------------------

    async def run_decision_cycle(self) -> dict[str, Any]:
        await self._set_status("working", None)
        try:
            pending = self.directives.pending(limit=20)
            snapshot = await self._snapshot(directives=pending)
            messages = [
                {"role": "system", "content": DECISION_MAKER_PROMPT},
                {"role": "user", "content": snapshot},
            ]

            # ---- investigation phase: the planner may gather facts via
            # tools (shell, files, blackboard, web) before committing to a
            # plan. Bounded so a cycle stays fast.
            await self._investigate(messages)

            assistant = await self.ctx.llm.chat(
                agent=self.name.value,
                messages=messages,
                temperature=self.temperature,
                tools=None,
            )
            raw = assistant.get("content") or ""
            plan = self._parse_plan(raw)
            if plan is None:
                log.warning("decision.bad_json", raw=raw[:500])
                await self._set_status("error", None)
                return {"ok": False, "reason": "could not parse plan",
                        "raw": raw[:500]}

            created = await self._apply_plan(plan)

            # consume directives + reply to operator
            reply = (plan.get("operator_reply") or "").strip()
            if pending:
                self.directives.mark_consumed(
                    [d.id for d in pending],
                    response=reply or None,
                )
            if reply:
                # notify via hook if present, and also route through ctx
                if self._reply_hook:
                    try:
                        await self._reply_hook(reply)
                    except Exception:
                        log.exception("decision.reply_hook_failed")
                await self.ctx.notify_operator(reply)

            await self._set_status("idle", None)
            return {
                "ok": True,
                "created_tasks": created,
                "plan": plan,
                "replied": bool(reply),
            }

        except BudgetExceeded as e:
            await self._set_status("blocked", None)
            return {"ok": False, "reason": f"budget: {e}"}
        except Exception as e:
            log.exception("decision.cycle_failed")
            await self._set_status("error", None)
            return {"ok": False, "reason": f"{type(e).__name__}: {e}"}

    # ------------------------------------------------------------------
    # tool investigation phase
    # ------------------------------------------------------------------

    async def _investigate(self, messages: list[dict[str, Any]]) -> None:
        """Bounded tool loop: lets the decision-maker gather facts with
        its allowed tools (shell, files, blackboard, web) before planning.
        Any tool errors are fed back as tool results; the loop ends when
        the model stops calling tools or the iteration cap is hit."""
        if self.ctx.registry is None:
            return
        schemas = self.ctx.registry.schemas(allow=self.allow_tools)
        if not schemas:
            return

        for _ in range(self.max_investigation_iterations):
            if self.ctx.is_stopped():
                return
            try:
                assistant = await self.ctx.llm.chat(
                    agent=self.name.value,
                    messages=messages,
                    temperature=self.temperature,
                    tools=schemas,
                )
            except BudgetExceeded:
                return
            tool_calls = assistant.get("tool_calls") or []
            if not tool_calls:
                return  # model is done investigating

            messages.append({
                "role": "assistant",
                "content": assistant.get("content") or "",
                "tool_calls": tool_calls,
            })
            for tc in tool_calls[: self.max_tool_calls_per_turn]:
                result = await self._dispatch_tool(tc)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "content": result,
                })

    async def _dispatch_tool(self, tool_call: dict[str, Any]) -> str:
        fn = tool_call.get("function") or {}
        name = fn.get("name", "")
        raw_args = fn.get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except json.JSONDecodeError:
            args = {}

        log.info("decision.tool_call", tool=name)
        try:
            result = await self.ctx.registry.dispatch(name, args)
            out = result.to_content()
        except Exception as e:
            out = f"tool error: {type(e).__name__}: {e}"
        # keep transcripts bounded for the planning context
        return out[:4000]

    # ------------------------------------------------------------------
    # snapshot
    # ------------------------------------------------------------------

    async def _snapshot(self, directives: list[Directive] | None = None) -> str:
        findings = await self.ctx.blackboard.list_findings()
        tasks = await self.ctx.blackboard.list_tasks()
        agents = await self.ctx.blackboard.agent_statuses()

        directives = directives or []
        directive_block = [
            {
                "id": d.id,
                "at": d.at,
                "kind": d.kind,
                "text": d.text,
            }
            for d in directives
        ]

        payload = {
            "mission": self.ctx.config.target.domain,
            "scope": self.ctx.config.target.scope,
            "narrative": self._read_narrative(),
            "operator_directives": directive_block,
            "findings": self._summarize_findings(findings),
            "tasks": self._summarize_tasks(tasks),
            "agents": [
                {"name": a.name.value, "state": a.state, "task": a.current_task_id}
                for a in agents
            ],
            "runtime": {
                "auth": self.ctx.auth_status(),
                "stealth": self.ctx.stealth_status(),
            },
            "counts": {
                "findings": len(findings),
                "tasks": len(tasks),
                "pending": sum(1 for t in tasks if t.status.value == "pending"),
                "running": sum(1 for t in tasks if t.status.value == "running"),
                "confirmed": sum(1 for f in findings if f.status.value == "confirmed"),
            },
        }
        return json.dumps(payload, indent=2, default=str)

    @staticmethod
    def _summarize_findings(findings: list[Finding]) -> list[dict[str, Any]]:
        order = {"confirmed": 0, "new": 1, "validating": 2, "reported": 3, "false_positive": 4}
        sorted_f = sorted(
            findings,
            key=lambda f: (order.get(f.status.value, 9), -_sev_rank(f)),
        )
        return [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.value,
                "status": f.status.value,
                "endpoint": f.endpoint,
                "discovered_by": f.discovered_by.value,
                "tags": f.tags,
            }
            for f in sorted_f[:40]
        ]

    @staticmethod
    def _summarize_tasks(tasks: list[Task]) -> list[dict[str, Any]]:
        open_tasks = [t for t in tasks if t.status.value not in ("done", "failed")]
        open_tasks.sort(key=lambda t: (t.priority, t.created_at))
        return [
            {
                "id": t.id,
                "title": t.title,
                "assignee": t.assignee.value,
                "priority": t.priority,
                "status": t.status.value,
            }
            for t in open_tasks[:40]
        ]

    def _read_narrative(self) -> dict[str, str]:
        try:
            text = self.ctx.blackboard.path.read_text(encoding="utf-8")
        except Exception:
            return {}
        out: dict[str, str] = {}
        for key in ("Mission", "Current Focus", "Next Actions", "Notes"):
            m = re.search(rf"## {key}\n(.*?)(?=\n## |\Z)", text, re.DOTALL)
            if m:
                out[key.lower().replace(" ", "_")] = m.group(1).strip()
        return out

    # ------------------------------------------------------------------
    # apply plan
    # ------------------------------------------------------------------

    def _parse_plan(self, raw: str) -> dict[str, Any] | None:
        candidates: list[str] = [raw.strip()]
        m = re.search(r"```(?:json)?\n(.*?)```", raw, re.DOTALL)
        if m:
            candidates.append(m.group(1).strip())
        m2 = _JSON_BLOCK.search(raw)
        if m2:
            candidates.append(m2.group(0))

        for cand in candidates:
            try:
                obj = json.loads(cand)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                continue
        return None

    async def _apply_plan(self, plan: dict[str, Any]) -> list[str]:
        created: list[str] = []

        nu = plan.get("narrative_update") or {}
        if nu:
            allowed = {"mission", "current_focus", "next_actions", "notes"}
            fields = {k: v for k, v in nu.items()
                      if k in allowed and isinstance(v, str)}
            if fields:
                await self.ctx.blackboard.set_narrative(**fields)

        for item in plan.get("tasks") or []:
            try:
                assignee = AgentName(item["assignee"])
            except Exception:
                continue
            task = Task(
                title=item.get("title", "untitled"),
                description=item.get("description", ""),
                assignee=assignee,
                priority=int(item.get("priority", 5)),
                finding_ids=list(item.get("finding_ids") or []),
                meta={"created_by": "decision"},
            )
            await self.ctx.blackboard.add_task(task)
            created.append(task.id)
            await self.ctx.notify_task(task)

        return created

    async def _set_status(self, state: str, current_task_id: str | None) -> None:
        self.status = AgentStatus(
            name=self.name,
            state=state,  # type: ignore[arg-type]
            current_task_id=current_task_id,
            last_heartbeat=time.time(),
        )
        await self.ctx.blackboard.set_agent_status(self.status)


def _sev_rank(f: Finding) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
        f.severity.value, 0
    )
