"""
Blackboard v2 — shared state as a Markdown file with a fenced JSON block.

The markdown top is human-readable (mission, focus, notes).
The JSON block is what agents parse.

Decision-maker is the only writer of the narrative sections.
Everyone writes findings and tasks via the async upsert/update methods.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

from .schemas import AgentStatus, Finding, Task


_YAML_FENCE = re.compile(r"```(?:json|yaml)\n(.*?)```", re.DOTALL)


class Blackboard:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self._findings: dict[str, Finding] = {}
        self._tasks: dict[str, Task] = {}
        self._agents: dict[str, AgentStatus] = {}
        self._narrative: dict[str, str] = {
            "mission": "",
            "current_focus": "",
            "next_actions": "",
            "notes": "",
        }
        self._loaded = False

    # ---------- load / dump ----------

    async def load(self) -> None:
        async with self._lock:
            self._load_locked()

    def _load_locked(self) -> None:
        if not self.path.exists():
            self._loaded = True
            return
        text = self.path.read_text(encoding="utf-8")
        for blk in _YAML_FENCE.findall(text):
            blk = blk.strip()
            try:
                obj = json.loads(blk)
            except Exception:
                continue
            for f in obj.get("findings") or []:
                try:
                    fo = Finding(**f)
                    self._findings[fo.id] = fo
                except Exception:
                    pass
            for t in obj.get("tasks") or []:
                try:
                    to = Task(**t)
                    self._tasks[to.id] = to
                except Exception:
                    pass
            for a in obj.get("agents") or []:
                try:
                    ao = AgentStatus(**a)
                    self._agents[ao.name.value] = ao
                except Exception:
                    pass
            if isinstance(obj.get("narrative"), dict):
                self._narrative.update(obj["narrative"])
        self._loaded = True

    def _serialize_locked(self) -> str:
        state = {
            "findings": [f.model_dump(mode="json") for f in self._findings.values()],
            "tasks": [t.model_dump(mode="json") for t in self._tasks.values()],
            "agents": [a.model_dump(mode="json") for a in self._agents.values()],
            "narrative": self._narrative,
            "updated_at": time.time(),
        }
        body = json.dumps(state, indent=2)
        md = [
            "# Swiggy Hunter — Shared State",
            "",
            "## Mission",
            self._narrative.get("mission") or "_not set_",
            "",
            "## Current Focus",
            self._narrative.get("current_focus") or "_none_",
            "",
            "## Next Actions",
            self._narrative.get("next_actions") or "_none_",
            "",
            "## Notes",
            self._narrative.get("notes") or "_none_",
            "",
            "## Machine State",
            "",
            "```json",
            body,
            "```",
            "",
        ]
        return "\n".join(md)

    async def flush(self) -> None:
        async with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        tmp = self.path.with_suffix(".md.tmp")
        tmp.write_text(self._serialize_locked(), encoding="utf-8")
        tmp.replace(self.path)

    # ---------- narrative ----------

    async def set_narrative(self, **fields: str) -> None:
        async with self._lock:
            for k, v in fields.items():
                if k in self._narrative and v is not None:
                    self._narrative[k] = v
            self._flush_locked()

    def narrative(self) -> dict[str, str]:
        return dict(self._narrative)

    # ---------- findings ----------

    async def upsert_finding(self, finding: Finding) -> Finding:
        async with self._lock:
            existing = self._findings.get(finding.id)
            if existing:
                finding.updated_at = time.time()
            self._findings[finding.id] = finding
            self._flush_locked()
            return finding

    async def get_finding(self, fid: str) -> Finding | None:
        async with self._lock:
            return self._findings.get(fid)

    async def list_findings(self) -> list[Finding]:
        async with self._lock:
            return sorted(self._findings.values(), key=lambda f: f.discovered_at, reverse=True)

    # ---------- tasks ----------

    async def add_task(self, task: Task) -> Task:
        async with self._lock:
            self._tasks[task.id] = task
            self._flush_locked()
            return task

    async def update_task(self, tid: str, **fields: Any) -> Task | None:
        async with self._lock:
            t = self._tasks.get(tid)
            if not t:
                return None
            for k, v in fields.items():
                if hasattr(t, k):
                    setattr(t, k, v)
            t.updated_at = time.time()
            self._flush_locked()
            return t

    async def next_task_for(self, agent: str) -> Task | None:
        async with self._lock:
            candidates = [
                t for t in self._tasks.values()
                if t.assignee.value == agent and t.status.value in ("pending", "assigned")
            ]
            if not candidates:
                return None
            candidates.sort(key=lambda t: (t.priority, t.created_at))
            return candidates[0]

    async def list_tasks(self) -> list[Task]:
        async with self._lock:
            return list(self._tasks.values())

    # ---------- agent status ----------

    async def set_agent_status(self, status: AgentStatus) -> None:
        async with self._lock:
            self._agents[status.name.value] = status
            self._flush_locked()

    async def agent_statuses(self) -> list[AgentStatus]:
        async with self._lock:
            return list(self._agents.values())

    # ---------- bulk ----------

    async def clear(self) -> None:
        async with self._lock:
            self._findings.clear()
            self._tasks.clear()
            self._flush_locked()
