"""
AgentContext v2 — the dependency bundle every agent gets.

Holds references to config, blackboard, tool registry, LLM client,
token budget, the auth manager, the browser provider, and the shared
stop/pause events. Nothing is a global; everything is passed.

New in v2:
  - auth_manager      : AuthManager (session state)
  - browser_provider  : callable returning a Browser or None
  - evidence          : EvidenceCollector for capture persistence
  - dedup             : FindingDeduplicator for merge-on-write
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from ..config import AppConfig
from ..llm.client import LLMClient
from ..llm.token_budget import AgentTokenBudget
from ..state.blackboard import Blackboard
from ..tools.base import ToolRegistry


@dataclass
class AgentContext:
    config: AppConfig
    blackboard: Blackboard
    registry: ToolRegistry
    llm: LLMClient
    budget: AgentTokenBudget

    # v2 — stealth + auth + browser + evidence
    auth_manager: Any | None = None
    browser_provider: Callable[[], Any] | None = None
    evidence: Any | None = None
    dedup: Any | None = None

    # coordination
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)
    pause_event: asyncio.Event = field(default_factory=asyncio.Event)

    # hooks
    finding_hook: Callable[[Any], Awaitable[None]] | None = None
    task_hook: Callable[[Any], Awaitable[None]] | None = None
    progress_hook: Callable[[str, dict], Awaitable[None]] | None = None
    operator_reply_hook: Callable[[str], Awaitable[None]] | None = None

    async def notify_progress(self, agent: str, payload: dict) -> None:
        if self.progress_hook:
            try:
                await self.progress_hook(agent, payload)
            except Exception:
                pass

    async def notify_finding(self, finding: Any) -> None:
        if self.finding_hook:
            try:
                await self.finding_hook(finding)
            except Exception:
                pass

    async def notify_task(self, task: Any) -> None:
        if self.task_hook:
            try:
                await self.task_hook(task)
            except Exception:
                pass

    async def notify_operator(self, text: str) -> None:
        if self.operator_reply_hook and text:
            try:
                await self.operator_reply_hook(text)
            except Exception:
                pass

    def is_stopped(self) -> bool:
        return self.stop_event.is_set()

    def is_paused(self) -> bool:
        return self.pause_event.is_set()

    async def wait_if_paused(self) -> None:
        while self.pause_event.is_set() and not self.stop_event.is_set():
            await asyncio.sleep(0.5)

    def auth_status(self) -> dict:
        if self.auth_manager is None:
            return {"authenticated": False, "reason": "auth disabled"}
        try:
            return self.auth_manager.status()
        except Exception:
            return {"authenticated": False, "reason": "auth error"}

    def stealth_status(self) -> dict:
        if self.auth_manager is None:
            return {}
        try:
            return self.auth_manager.session.snapshot()
        except Exception:
            return {}
