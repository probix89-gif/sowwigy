"""
Orchestrator v2 — the top-level runtime.

Owns:
  - config, blackboard, LLM client, usage tracker, token budget
  - Stealth layer (fingerprint pool, auth manager, browser)
  - All seven agents (decision + 6 workers)
  - TaskScheduler, AgentSupervisor, DecisionLoop, ReporterLoop
  - DirectiveQueue (operator messages)
  - Wire everything through AgentContext

Public API for the telegram bot:
  start / stop / pause / resume / restart / emergency
  status / usage_report / full_report / findings_digest
  target_info / model_info / set_interval / set_reasoning
  clear_data / retest_finding / progress_now
  ask_decision / inject_task / note_to_plan / directives_recent
  auth_status / auth_send_otp / auth_verify_otp / auth_import_cookie
  auth_check / auth_rotate / auth_logout
  runtime_description
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import time
from typing import Any, Awaitable, Callable

from .agents import AgentContext, build_agent
from .agents.base import BaseAgent
from .agents.decision import DecisionAgent
from .auth.manager import AuthManager
from .config import AppConfig, load_config
from .directives import DirectiveQueue
from .llm.client import LLMClient
from .llm.token_budget import AgentTokenBudget
from .llm.usage import UsageTracker
from .logging_setup import get_logger, setup_logging
from .scheduler.agent_supervisor import AgentSupervisor
from .scheduler.decision_loop import DecisionLoop
from .scheduler.lifecycle import Lifecycle, RunState
from .scheduler.report_builder import ReportBuilder
from .scheduler.reporter import ReporterLoop
from .scheduler.task_scheduler import TaskScheduler
from .state.blackboard import Blackboard
from .state.schemas import (
    AgentName,
    AgentStatus,
    Finding,
    FindingStatus,
    Severity,
    Task,
    TaskStatus,
)
from .stealth.browser import Browser
from .stealth.fingerprint import FingerprintPool, build_default_pool
from .tools import build_agent_registry

log = get_logger(__name__)


class Orchestrator:
    def __init__(
        self,
        config_path: str | Path = "config.yaml",
        report_sender: Callable[[str], Awaitable[None]] | None = None,
    ):
        setup_logging()
        self.config: AppConfig = load_config(config_path)

        # core
        self.lifecycle = Lifecycle()
        self.blackboard = Blackboard(self.config.paths.blackboard)
        self.usage = UsageTracker(
            path=self.config.paths.usage,
            daily_limit=self.config.budget.daily_token_limit,
            warn_at_percent=self.config.budget.warn_at_percent,
        )
        self.budget = AgentTokenBudget()
        self.llm = LLMClient(self.config, self.usage, self.budget)

        # directives
        self.directives = DirectiveQueue(path=self.config.paths.directives)

        # stealth + auth + browser
        self.fingerprints: FingerprintPool = FingerprintPool(build_default_pool())
        self.auth: AuthManager = AuthManager(self.config, self.fingerprints)
        self._browser: Browser | None = None

        # report hook (telegram)
        self._report_sender = report_sender

        # agents + runtime
        self.ctx: AgentContext | None = None
        self.agents: dict[AgentName, BaseAgent] = {}
        self.decision: DecisionAgent | None = None

        self.scheduler: TaskScheduler | None = None
        self.supervisor: AgentSupervisor | None = None
        self.decision_loop: DecisionLoop | None = None
        self.reporter: ReporterLoop | None = None

        self._runtime_tasks: list[asyncio.Task] = []
        self._boot_lock = asyncio.Lock()
        self._booted = False
        self._report_interval_minutes = self.config.reporter.interval_minutes
        self._reasoning_level = "medium"

    # ==================================================================
    # boot
    # ==================================================================

    async def boot(self) -> None:
        async with self._boot_lock:
            if self._booted:
                return
            await self.blackboard.load()
            await self._seed_mission()
            self._build_agents()
            self._wire_hooks()
            self._booted = True
            log.info("orchestrator.booted")

    def _session_provider(self):
        return self.auth.session

    def _browser_provider(self):
        if not self.config.browser.enabled:
            return None
        if self._browser is None:
            fp = self.fingerprints.draw()
            self._browser = Browser(fp, self.config.browser)
        return self._browser

    def _build_agents(self) -> None:
        worker_names = (
            AgentName.recon,
            AgentName.business_logic,
            AgentName.research,
            AgentName.validation,
            AgentName.attacker,
            AgentName.hermes,
        )

        # a scope guard is constructed inside runtime; we attach it to
        # tools via a closure that the runtime patches in later
        from .scanner.scope import ScopeGuard
        scope = ScopeGuard(patterns=self.config.target.scope)

        allowed_installers = (
            self.config.tools_autoload.allowed_installers
            if self.config.tools_autoload.auto_install
            else None
        )

        self.agents = {}
        for name in worker_names:
            reg = build_agent_registry(
                agent_name=name,
                blackboard=self.blackboard,
                session_provider=self._session_provider,
                browser_provider=self._browser_provider if self.config.browser.enabled else None,
                scope=scope,
                auth_manager=self.auth,
                allowed_installers=allowed_installers,
            )
            ctx = AgentContext(
                config=self.config,
                blackboard=self.blackboard,
                registry=reg,
                llm=self.llm,
                budget=self.budget,
                auth_manager=self.auth,
                browser_provider=self._browser_provider if self.config.browser.enabled else None,
                stop_event=self.lifecycle.stop_event,
                pause_event=self.lifecycle.pause_event,
            )
            self.agents[name] = build_agent(name, ctx)

        # decision agent
        decision_reg = build_agent_registry(
            agent_name=AgentName.decision,
            blackboard=self.blackboard,
            session_provider=self._session_provider,
            scope=scope,
            auth_manager=self.auth,
            allowed_installers=allowed_installers,
        )
        decision_ctx = AgentContext(
            config=self.config,
            blackboard=self.blackboard,
            registry=decision_reg,
            llm=self.llm,
            budget=self.budget,
            auth_manager=self.auth,
            stop_event=self.lifecycle.stop_event,
            pause_event=self.lifecycle.pause_event,
        )
        self.decision = DecisionAgent(decision_ctx, directives=self.directives)
        self.ctx = decision_ctx

    def _wire_hooks(self) -> None:
        assert self.ctx is not None
        self.ctx.finding_hook = self._on_finding
        self.ctx.task_hook = self._on_task
        self.ctx.progress_hook = self._on_progress
        # propagate to every worker context too
        for agent in self.agents.values():
            agent.ctx.finding_hook = self._on_finding
            agent.ctx.task_hook = self._on_task
            agent.ctx.progress_hook = self._on_progress

    async def _seed_mission(self) -> None:
        narrative = {
            "mission": (
                f"Find critical business-logic bugs on {self.config.target.domain} "
                f"that lead to free orders, discount abuse, or payment manipulation."
            ),
            "current_focus": "Initial reconnaissance. Map the attack surface.",
            "next_actions": "Authenticate, warm up, enumerate endpoints and JS bundles.",
            "notes": "",
        }
        await self.blackboard.set_narrative(**narrative)

    # ==================================================================
    # start / stop
    # ==================================================================

    async def start(self) -> bool:
        await self.boot()
        ok = await self.lifecycle.start()
        if not ok:
            log.info("orchestrator.start_rejected", state=self.lifecycle.state.value)
            return False

        assert self.decision is not None
        self.scheduler = TaskScheduler(
            blackboard=self.blackboard,
            stop_event=self.lifecycle.stop_event,
            pause_event=self.lifecycle.pause_event,
            on_assign=self._on_scheduler_assign,
            tick_seconds=3.0,
        )
        self.supervisor = AgentSupervisor(
            agents=self.agents,
            decision=self.decision,
            scheduler=self.scheduler,
            lifecycle=self.lifecycle,
        )
        self.decision_loop = DecisionLoop(
            decision=self.decision,
            blackboard=self.blackboard,
            stop_event=self.lifecycle.stop_event,
            pause_event=self.lifecycle.pause_event,
            interval_s=90.0,
        )
        if self._report_sender:
            self.reporter = ReporterLoop(
                blackboard=self.blackboard,
                sender=self._report_sender,
                stop_event=self.lifecycle.stop_event,
                interval_minutes=self._report_interval_minutes,
                usage_snapshot=self.usage.snapshot,
                lifecycle_snapshot=self.lifecycle.snapshot,
                runtime_snapshot=self.runtime_description,
            )

        self._runtime_tasks.append(asyncio.create_task(
            self.scheduler.run(), name="scheduler"))
        self._runtime_tasks.append(asyncio.create_task(
            self.supervisor.start_all(), name="supervisor"))
        self._runtime_tasks.append(asyncio.create_task(
            self.decision_loop.run(), name="decision_loop"))
        if self.reporter:
            self._runtime_tasks.append(asyncio.create_task(
                self.reporter.run(), name="reporter"))

        asyncio.create_task(self._kickstart(), name="kickstart")
        log.info("orchestrator.started")
        return True

    async def _kickstart(self) -> None:
        await asyncio.sleep(1.0)
        if self.decision_loop:
            self.decision_loop.trigger_now()

    async def _on_scheduler_assign(self, agent: AgentName, task: Task) -> None:
        if self.supervisor:
            await self.supervisor.on_task_assigned(agent, task)

    async def stop(self, emergency: bool = False) -> bool:
        ok = await self.lifecycle.stop(emergency=emergency)
        for t in self._runtime_tasks:
            t.cancel()
        for t in self._runtime_tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        self._runtime_tasks.clear()
        if self.supervisor:
            await self.supervisor.stop_all()
        try:
            await self.auth.shutdown()
        except Exception:
            pass
        if self._browser:
            try:
                await self._browser.stop()
            except Exception:
                pass
        await self.llm.close()
        await self.blackboard.flush()
        log.info("orchestrator.stopped", emergency=emergency)
        return ok

    async def emergency(self) -> bool:
        return await self.stop(emergency=True)

    async def pause(self) -> bool:
        return await self.lifecycle.pause()

    async def resume(self) -> bool:
        return await self.lifecycle.resume()

    async def restart(self) -> bool:
        await self.stop()
        await asyncio.sleep(1.0)
        return await self.start()

    # ==================================================================
    # info commands
    # ==================================================================

    async def status(self) -> dict[str, Any]:
        findings = await self.blackboard.list_findings()
        tasks = await self.blackboard.list_tasks()
        agents = await self.blackboard.agent_statuses()
        return {
            "lifecycle": self.lifecycle.snapshot(),
            "target": self.config.target.domain,
            "scope": self.config.target.scope,
            "model": self.config.model.name,
            "reasoning": self._reasoning_level,
            "report_interval_min": self._report_interval_minutes,
            "findings": len(findings),
            "tasks": len(tasks),
            "agents": [
                {"name": a.name.value, "state": a.state, "task": a.current_task_id}
                for a in agents
            ],
            "auth": self.auth.status(),
            "stealth": self.auth.session.snapshot() if self.auth else {},
            "thinking": self.llm.thinking.describe(),
            "rate": self.llm.limiter.stats(),
        }

    async def usage_report(self) -> str:
        snap = await self.usage.snapshot()
        agent_snap = await self.budget.snapshot()
        today = snap.get("days", {}).get(time.strftime("%Y-%m-%d"), {})
        total = today.get("total", 0)
        calls = today.get("calls", 0)
        lines = [
            f"<b>Token usage — {time.strftime('%Y-%m-%d')}</b>",
            f"Total today: <code>{total:,}</code> / <code>{self.config.budget.daily_token_limit:,}</code>",
            f"Calls today: <code>{calls}</code>",
            "",
            "<b>By agent (usage tracker):</b>",
        ]
        by_agent = today.get("by_agent", {})
        if by_agent:
            for k, v in sorted(by_agent.items(), key=lambda x: -x[1]):
                lines.append(f"  • <code>{k}</code> {v:,}")
        else:
            lines.append("  <i>(no usage yet)</i>")
        lines.append("")
        lines.append("<b>Per-agent caps:</b>")
        for name, info in agent_snap.items():
            pct = (info["spent"] / info["cap"]) * 100 if info["cap"] else 0
            lines.append(
                f"  • <code>{name}</code> {info['spent']:,}/{info['cap']:,} ({pct:.1f}%)"
            )
        return "\n".join(lines)

    async def full_report(self) -> str:
        builder = ReportBuilder(self.blackboard)
        return await builder.full_report()

    async def findings_digest(self) -> str:
        findings = await self.blackboard.list_findings()
        if not findings:
            return "<i>no findings yet</i>"
        lines = [f"<b>Latest findings — {len(findings)} total</b>"]
        for f in findings[:20]:
            marker = {
                "critical": "🔴", "high": "🟠", "medium": "🟡",
                "low": "🟢", "info": "⚪",
            }.get(f.severity.value, "•")
            lines.append(
                f"{marker} <code>{f.id}</code> [{f.status.value}] {f.title[:80]}"
            )
        return "\n".join(lines)

    async def target_info(self) -> str:
        lines = [f"<b>Target:</b> <code>{self.config.target.domain}</code>", "",
                 "<b>Scope:</b>"]
        for s in self.config.target.scope:
            lines.append(f"• <code>{s}</code>")
        return "\n".join(lines)

    async def model_info(self) -> str:
        return (
            f"<b>Model:</b> <code>{self.config.model.name}</code>\n"
            f"<b>Base URL:</b> <code>{self.config.model.base_url}</code>\n"
            f"<b>Max output:</b> <code>{self.config.model.max_output_tokens}</code>\n"
            f"<b>Rate limit:</b> <code>{self.config.rate_limit.requests_per_minute} rpm</code>\n"
            f"<b>Reasoning:</b> <code>{self._reasoning_level}</code>\n"
            f"<b>Thinking window:</b> "
            f"<code>{self.config.model.thinking_window.min_seconds}-"
            f"{self.config.model.thinking_window.max_seconds}s</code> "
            f"on {', '.join(self.config.model.thinking_window.agents)}"
        )

    async def set_interval(self, minutes: int) -> bool:
        if minutes < 1 or minutes > 24 * 60:
            return False
        self._report_interval_minutes = minutes
        if self.reporter:
            self.reporter.interval_s = minutes * 60
        log.info("orchestrator.set_interval", minutes=minutes)
        return True

    async def set_reasoning(self, level: str) -> bool:
        level = level.lower().strip()
        if level not in ("low", "medium", "high"):
            return False
        self._reasoning_level = level
        temps = {"low": 0.2, "medium": 0.5, "high": 0.75}
        for agent in self.agents.values():
            agent.temperature = temps[level]
        if self.decision:
            self.decision.temperature = max(0.2, temps[level] - 0.05)
        log.info("orchestrator.set_reasoning", level=level)
        return True

    async def clear_data(self) -> bool:
        await self.blackboard.clear()
        await self.blackboard.set_narrative(
            mission=self.blackboard.narrative().get("mission", ""),
            current_focus="Reset. Awaiting new decision cycle.",
            next_actions="",
            notes="",
        )
        log.info("orchestrator.clear_data")
        return True

    async def retest_finding(self, finding_id: str) -> bool:
        f = await self.blackboard.get_finding(finding_id)
        if f is None:
            return False
        task = Task(
            title=f"Retest finding {finding_id}",
            description=(
                f"Re-verify finding '{f.title}' with fresh evidence. "
                f"Prior status: {f.status.value}"
            ),
            assignee=AgentName.validation,
            priority=2,
            finding_ids=[finding_id],
            meta={"retest": True},
        )
        await self.blackboard.add_task(task)
        f.status = FindingStatus.validating
        await self.blackboard.upsert_finding(f)
        if self.decision_loop:
            self.decision_loop.trigger_now()
        return True

    async def progress_now(self) -> str:
        if self.reporter:
            return await self.reporter.build_report()
        return "<i>reporter not configured</i>"

    def runtime_description(self) -> dict[str, Any]:
        auth = self.auth.status() if self.auth else {}
        stealth = self.auth.session.snapshot() if self.auth else {}
        return {"auth": auth, "stealth": stealth}

    # ==================================================================
    # operator chat + directives
    # ==================================================================

    async def ask_decision(self, text: str) -> str:
        d = self.directives.push(text=text, kind="chat")
        if self.decision_loop:
            self.decision_loop.trigger_now()
        return d.id

    async def inject_task(self, text: str) -> str:
        d = self.directives.push(text=text, kind="task")
        if self.decision_loop:
            self.decision_loop.trigger_now()
        return d.id

    async def note_to_plan(self, text: str) -> str:
        d = self.directives.push(text=text, kind="note")
        if self.decision_loop:
            self.decision_loop.trigger_now()
        return d.id

    async def directives_recent(self, limit: int = 20) -> list[dict]:
        return [d.__dict__ for d in self.directives.recent(limit)]

    # ==================================================================
    # auth commands
    # ==================================================================

    async def auth_status(self) -> dict[str, Any]:
        if not self.auth:
            return {"authenticated": False, "reason": "auth disabled"}
        return self.auth.status()

    async def auth_send_otp(self, phone: str) -> dict[str, Any]:
        if not self.auth:
            return {"ok": False, "message": "auth disabled"}
        r = await self.auth.login_otp_send(phone)
        return {"ok": r.ok, "message": r.message,
                "phone": r.phone, "status": r.status}

    async def auth_verify_otp(self, otp: str) -> dict[str, Any]:
        if not self.auth:
            return {"ok": False, "message": "auth disabled"}
        r = await self.auth.login_otp_verify(otp)
        return {
            "ok": r.ok, "message": r.message,
            "phone": r.phone, "cookies": r.cookies_count, "status": r.status,
        }

    async def auth_import_cookie(self, raw: str) -> dict[str, Any]:
        if not self.auth:
            return {"ok": False, "message": "auth disabled"}
        r = await self.auth.login_cookie(raw)
        return {"ok": r.ok, "message": r.message,
                "cookies": r.cookies_count, "status": r.status}

    async def auth_check(self) -> dict[str, Any]:
        if not self.auth:
            return {"ok": False, "message": "auth disabled"}
        r = await self.auth.check_auth()
        return {"ok": r.ok, "message": r.message,
                "phone": r.phone, "cookies": r.cookies_count, "status": r.status}

    async def auth_rotate(self) -> dict[str, Any]:
        if not self.auth:
            return {"ok": False, "message": "auth disabled"}
        r = await self.auth.rotate_session()
        return {"ok": r.ok, "message": r.message,
                "cookies": r.cookies_count}

    async def auth_logout(self) -> dict[str, Any]:
        if not self.auth:
            return {"ok": False, "message": "auth disabled"}
        r = self.auth.logout()
        return {"ok": r.ok, "message": r.message}

    async def auth_restore(self) -> dict[str, Any]:
        if not self.auth:
            return {"ok": False, "message": "auth disabled"}
        r = await self.auth.restore("primary")
        return {"ok": r.ok, "message": r.message,
                "phone": r.phone, "cookies": r.cookies_count, "status": r.status}

    # ==================================================================
    # hooks
    # ==================================================================

    async def _on_finding(self, finding: Finding) -> None:
        log.info("orchestrator.finding",
                 id=finding.id, sev=finding.severity.value,
                 title=finding.title[:80])
        if (finding.severity in (Severity.high, Severity.critical)
                and self.decision_loop):
            self.decision_loop.trigger_now()

    async def _on_task(self, task: Task) -> None:
        log.debug("orchestrator.task_event", id=task.id, status=task.status.value)

    async def _on_progress(self, agent: str, payload: dict) -> None:
        log.debug("orchestrator.progress", agent=agent, **payload)

    # ==================================================================
    # context manager
    # ==================================================================

    async def __aenter__(self):
        await self.boot()
        return self

    async def __aexit__(self, *exc):
        await self.stop()
