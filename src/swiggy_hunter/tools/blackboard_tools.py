"""
Blackboard-backed tools — the way agents write findings and update tasks.
"""
from __future__ import annotations

import json
import time
from typing import Any

from ..state.blackboard import Blackboard
from ..state.schemas import (
    AgentName,
    Finding,
    FindingStatus,
    Severity,
    Task,
    TaskStatus,
)
from .base import Tool, ToolResult


class ReportFindingTool(Tool):
    name = "report_finding"
    description = (
        "Report a security finding. Include exact evidence — raw requests, "
        "responses, file paths, line references. Findings are deduplicated "
        "automatically. Use this for every concrete observation."
    )
    parameters = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "category": {
                "type": "string",
                "description": "recon | business_logic | auth | idor | hermes_flow | research | other",
            },
            "severity": {"type": "string",
                         "enum": ["info", "low", "medium", "high", "critical"]},
            "endpoint": {"type": "string"},
            "method": {"type": "string"},
            "description": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"}},
            "repro_steps": {"type": "array", "items": {"type": "string"}},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["title", "category", "description"],
    }

    def __init__(self, blackboard: Blackboard, agent_name: AgentName):
        self.blackboard = blackboard
        self.agent_name = agent_name

    async def run(self, **kwargs: Any) -> ToolResult:
        try:
            f = Finding(
                title=kwargs["title"],
                category=kwargs.get("category", "other"),
                severity=Severity(kwargs.get("severity", "info")),
                endpoint=kwargs.get("endpoint"),
                method=kwargs.get("method"),
                description=kwargs.get("description", ""),
                evidence=list(kwargs.get("evidence") or []),
                repro_steps=list(kwargs.get("repro_steps") or []),
                discovered_by=self.agent_name,
                tags=list(kwargs.get("tags") or []),
            )
            await self.blackboard.upsert_finding(f)
            return ToolResult(ok=True,
                              output=f"finding recorded: {f.id} ({f.severity.value})",
                              meta={"finding_id": f.id})
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))


class QueryBlackboardTool(Tool):
    name = "query_blackboard"
    description = (
        "Read blackboard state. slice: 'summary' | 'findings' | 'tasks' "
        "| 'agents' | 'narrative'."
    )
    parameters = {
        "type": "object",
        "properties": {
            "slice": {"type": "string",
                      "enum": ["summary", "findings", "tasks", "agents", "narrative"],
                      "default": "summary"},
            "filter_status": {"type": "string"},
            "filter_agent": {"type": "string"},
            "limit": {"type": "integer", "default": 50},
        },
    }

    def __init__(self, blackboard: Blackboard):
        self.blackboard = blackboard

    async def run(self, **kwargs: Any) -> ToolResult:
        slc = kwargs.get("slice", "summary")
        filt_status = kwargs.get("filter_status")
        filt_agent = kwargs.get("filter_agent")
        limit = int(kwargs.get("limit", 50))

        if slc == "summary":
            findings = await self.blackboard.list_findings()
            tasks = await self.blackboard.list_tasks()
            agents = await self.blackboard.agent_statuses()
            sev: dict[str, int] = {}
            for f in findings:
                sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
            st: dict[str, int] = {}
            for t in tasks:
                st[t.status.value] = st.get(t.status.value, 0) + 1
            out = {
                "findings_total": len(findings),
                "findings_by_severity": sev,
                "tasks_total": len(tasks),
                "tasks_by_status": st,
                "agents": [{"name": a.name.value, "state": a.state} for a in agents],
            }
            return ToolResult(ok=True, output=json.dumps(out, indent=2))

        if slc == "findings":
            findings = await self.blackboard.list_findings()
            if filt_status:
                findings = [f for f in findings if f.status.value == filt_status]
            if filt_agent:
                findings = [f for f in findings if f.discovered_by.value == filt_agent]
            payload = [f.model_dump(mode="json") for f in findings[:limit]]
            return ToolResult(ok=True, output=json.dumps(payload, indent=2))

        if slc == "tasks":
            tasks = await self.blackboard.list_tasks()
            if filt_status:
                tasks = [t for t in tasks if t.status.value == filt_status]
            if filt_agent:
                tasks = [t for t in tasks if t.assignee.value == filt_agent]
            payload = [t.model_dump(mode="json") for t in tasks[:limit]]
            return ToolResult(ok=True, output=json.dumps(payload, indent=2))

        if slc == "agents":
            agents = await self.blackboard.agent_statuses()
            return ToolResult(ok=True,
                              output=json.dumps([a.model_dump(mode="json") for a in agents], indent=2))

        if slc == "narrative":
            try:
                text = self.blackboard.path.read_text(encoding="utf-8")
            except Exception:
                text = ""
            return ToolResult(ok=True, output=text[:8000])

        return ToolResult(ok=False, output="", error=f"unknown slice {slc}")


class UpdateTaskTool(Tool):
    name = "update_task"
    description = "Update a task's status and/or result."
    parameters = {
        "type": "object",
        "properties": {
            "task_id": {"type": "string"},
            "status": {"type": "string",
                       "enum": ["pending", "assigned", "running", "done", "failed", "blocked"]},
            "result": {"type": "string"},
        },
        "required": ["task_id", "status"],
    }

    def __init__(self, blackboard: Blackboard):
        self.blackboard = blackboard

    async def run(self, **kwargs: Any) -> ToolResult:
        tid = kwargs["task_id"]
        try:
            updated = await self.blackboard.update_task(
                tid,
                status=TaskStatus(kwargs["status"]),
                result=kwargs.get("result"),
            )
            if updated is None:
                return ToolResult(ok=False, output="", error=f"task not found: {tid}")
            return ToolResult(ok=True, output=f"task {tid} -> {kwargs['status']}")
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))


class AddTaskTool(Tool):
    name = "add_task"
    description = "Add a follow-up task for another agent."
    parameters = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "description": {"type": "string"},
            "assignee": {"type": "string",
                         "enum": ["decision", "recon", "business_logic", "research",
                                  "validation", "attacker", "hermes"]},
            "priority": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
            "finding_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["title", "assignee"],
    }

    def __init__(self, blackboard: Blackboard, created_by: AgentName):
        self.blackboard = blackboard
        self.created_by = created_by

    async def run(self, **kwargs: Any) -> ToolResult:
        try:
            t = Task(
                title=kwargs["title"],
                description=kwargs.get("description", ""),
                assignee=AgentName(kwargs["assignee"]),
                priority=int(kwargs.get("priority", 5)),
                finding_ids=list(kwargs.get("finding_ids") or []),
                meta={"created_by": self.created_by.value},
            )
            await self.blackboard.add_task(t)
            return ToolResult(ok=True,
                              output=f"task created: {t.id} -> {t.assignee.value}")
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))


class AnnotateFindingTool(Tool):
    name = "annotate_finding"
    description = "Update finding: status, severity, append evidence, add repro step."
    parameters = {
        "type": "object",
        "properties": {
            "finding_id": {"type": "string"},
            "status": {"type": "string",
                       "enum": ["new", "validating", "confirmed",
                                "false_positive", "reported"]},
            "severity": {"type": "string",
                         "enum": ["info", "low", "medium", "high", "critical"]},
            "append_evidence": {"type": "string"},
            "append_repro_step": {"type": "string"},
            "add_tag": {"type": "string"},
            "note": {"type": "string"},
        },
        "required": ["finding_id"],
    }

    def __init__(self, blackboard: Blackboard):
        self.blackboard = blackboard

    async def run(self, **kwargs: Any) -> ToolResult:
        fid = kwargs["finding_id"]
        f = await self.blackboard.get_finding(fid)
        if f is None:
            return ToolResult(ok=False, output="", error=f"finding not found: {fid}")
        try:
            if kwargs.get("status"):
                f.status = FindingStatus(kwargs["status"])
            if kwargs.get("severity"):
                f.severity = Severity(kwargs["severity"])
            if kwargs.get("append_evidence"):
                f.evidence.append(kwargs["append_evidence"])
            if kwargs.get("append_repro_step"):
                f.repro_steps.append(kwargs["append_repro_step"])
            if kwargs.get("add_tag") and kwargs["add_tag"] not in f.tags:
                f.tags.append(kwargs["add_tag"])
            if kwargs.get("note"):
                f.meta.setdefault("notes", []).append(
                    {"at": time.time(), "text": kwargs["note"]})
            f.updated_at = time.time()
            await self.blackboard.upsert_finding(f)
            return ToolResult(ok=True, output=f"finding {fid} updated")
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))


def register_blackboard_tools(reg, blackboard: Blackboard, agent_name: AgentName) -> None:
    reg.register(ReportFindingTool(blackboard, agent_name))
    reg.register(QueryBlackboardTool(blackboard))
    reg.register(UpdateTaskTool(blackboard))
    reg.register(AddTaskTool(blackboard, agent_name))
    reg.register(AnnotateFindingTool(blackboard))
