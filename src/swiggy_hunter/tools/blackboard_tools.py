"""
Blackboard-backed tools — the way agents write findings and update tasks.

report_finding is GATED: every candidate passes FindingGate before it can
become a Finding. Candidates that fail the gate are preserved as internal
Observations (never silently dropped) with a machine-readable reason.
Agents cannot bypass the gate — severity is normalized programmatically.
"""
from __future__ import annotations

import json
import time
from typing import Any

from ..scanner.dedup import FindingDeduplicator
from ..scanner.triage import (
    FindingGate,
    GateDecision,
    observation_from_candidate,
)
from ..state.blackboard import Blackboard
from ..state.schemas import (
    AgentName,
    Finding,
    FindingStatus,
    Observation,
    Severity,
    Task,
    TaskStatus,
)
from .base import Tool, ToolResult


class ReportFindingTool(Tool):
    name = "report_finding"
    description = (
        "Report a candidate HIGH-IMPACT business-logic vulnerability. "
        "REQUIREMENTS: (1) the flaw must map to a high-impact category — "
        "coupon/discount abuse, cart/checkout/payment/order/refund/wallet "
        "integrity, or authorization leading to financial manipulation; "
        "(2) raw request+response evidence showing the violated business "
        "invariant in the FINAL state; (3) numbered reproduction steps; "
        "(4) a description asserting what business rule was violated and "
        "what the money/state outcome was. Weak signals (status changed, "
        "extra field, missing validation, undocumented endpoint, accepted "
        "parameter) are auto-routed to internal observations, NOT findings. "
        "Findings are triaged, deduplicated, and severity-normalized "
        "automatically — you cannot bypass the gate."
    )
    parameters = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "category": {
                "type": "string",
                "description": (
                    "high-impact category: coupon_abuse | discount_abuse | "
                    "pricing_integrity | cart_total_integrity | "
                    "checkout_integrity | order_integrity | payment_integrity | "
                    "refund_integrity | wallet_integrity | stored_value_abuse | "
                    "authorization_to_financial_state. Non-impact categories "
                    "(recon/research/observation) are stored as observations."
                ),
            },
            "severity": {"type": "string",
                         "enum": ["info", "low", "medium", "high", "critical"]},
            "endpoint": {"type": "string"},
            "method": {"type": "string"},
            "description": {
                "type": "string",
                "description": (
                    "MUST state the violated business invariant and the final "
                    "financial/state outcome, e.g. 'server computed total ₹0 "
                    "after quantity=-2; order was placed and charged ₹0'."
                ),
            },
            "evidence": {"type": "array", "items": {"type": "string"}},
            "repro_steps": {"type": "array", "items": {"type": "string"}},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["title", "category", "description", "evidence", "repro_steps"],
    }

    def __init__(self, blackboard: Blackboard, agent_name: AgentName,
                 gate: FindingGate | None = None):
        self.blackboard = blackboard
        self.agent_name = agent_name
        self.gate = gate

    def _gate(self) -> FindingGate:
        # lazily bind to the shared deduplicator if the orchestrator supplied
        # one on the blackboard toolset; otherwise a private instance
        if self.gate is None:
            shared = getattr(self.blackboard, "_shared_gate", None)
            self.gate = shared if isinstance(shared, FindingGate) else FindingGate()
        return self.gate

    async def run(self, **kwargs: Any) -> ToolResult:
        title = kwargs.get("title") or ""
        category = kwargs.get("category") or "other"
        description = kwargs.get("description") or ""
        evidence = [str(e) for e in (kwargs.get("evidence") or [])]
        repro = [str(s) for s in (kwargs.get("repro_steps") or [])]
        tags = [str(t) for t in (kwargs.get("tags") or [])]
        endpoint = kwargs.get("endpoint")

        try:
            claimed = Severity(kwargs.get("severity", "info"))
        except ValueError:
            claimed = Severity.info

        try:
            result = self._gate().evaluate(
                title=title, category=category, description=description,
                evidence=evidence, repro_steps=repro,
                claimed_severity=claimed, tags=tags, endpoint=endpoint,
            )
        except Exception as e:
            return ToolResult(ok=False, output="",
                              error=f"triage gate error: {e}")

        # ---- REJECT is never used for deletion: everything survives as an
        # observation so evidence is never lost.
        obs = Observation(**observation_from_candidate(
            title=title, category=category, description=description,
            evidence=evidence, repro_steps=repro,
            agent_name=self.agent_name.value, endpoint=endpoint, tags=tags,
            gate_reason=result.reason,
        ))
        await self.blackboard.add_observation(obs)

        if result.decision is not GateDecision.accept:
            return ToolResult(
                ok=False,
                output=(
                    f"NOT recorded as a finding — {result.decision.value}: "
                    f"{result.reason} "
                    f"(preserved as internal observation {obs.id}; other agents "
                    f"can find it via query_blackboard observations)"
                ),
                meta={"observation_id": obs.id, "gate": result.decision.value},
            )

        # ---- ACCEPT: build the real finding, gate-normalized -------------
        f = Finding(
            title=title,
            category=result.normalized_category or category,
            severity=result.adjusted_severity or claimed,
            endpoint=endpoint,
            method=kwargs.get("method"),
            description=description,
            evidence=evidence,
            repro_steps=repro,
            discovered_by=self.agent_name,
            tags=tags,
            meta={
                "gate": {
                    "impact_category": result.impact.category.value if result.impact else None,
                    "impact_score": result.impact.score if result.impact else 0,
                    "evidence_quality": result.evidence.evidence_quality if result.evidence else 0,
                    "verified_impact": result.fp.verified_impact if result.fp else False,
                    "observation_id": obs.id,
                },
            },
        )

        # root-cause dedup: merge into an existing finding when signatures match
        dedup = self._gate().dedup
        existing_id = result.duplicate_of or dedup.lookup(f)
        if existing_id:
            existing = await self.blackboard.get_finding(existing_id)
            if existing:
                merged = dedup.merge(existing, f)
                await self.blackboard.upsert_finding(merged)
                return ToolResult(
                    ok=True,
                    output=(
                        f"merged into existing root-cause finding {existing_id} "
                        f"(same flaw, another manifestation). Evidence appended."
                    ),
                    meta={"finding_id": existing_id, "merged": True},
                )

        await self.blackboard.upsert_finding(f)
        dedup.register(f)
        return ToolResult(
            ok=True,
            output=(
                f"finding accepted: {f.id} [{f.severity.value}] "
                f"category={f.category}. Awaiting validation — it will only be "
                f"reported after independent reproduction."
            ),
            meta={"finding_id": f.id},
        )


class QueryBlackboardTool(Tool):
    name = "query_blackboard"
    description = (
        "Read blackboard state. slice: 'summary' | 'findings' | 'observations' "
        "| 'tasks' | 'agents' | 'narrative'. Use observations to find "
        "previously collected evidence that did not qualify as a finding."
    )
    parameters = {
        "type": "object",
        "properties": {
            "slice": {"type": "string",
                      "enum": ["summary", "findings", "observations", "tasks", "agents", "narrative"],
                      "default": "summary"},
            "filter_status": {"type": "string"},
            "filter_agent": {"type": "string"},
            "search": {"type": "string",
                       "description": "keyword search (observations slice)"},
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
            observations = await self.blackboard.list_observations(limit=1000)
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
                "observations_total": len(observations),
                "note": "observations are internal evidence that did not pass the finding gate",
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

        if slc == "observations":
            search = kwargs.get("search")
            if search:
                obs = await self.blackboard.find_observations(search, limit=limit)
            else:
                obs = await self.blackboard.list_observations(limit=limit)
            if filt_agent:
                obs = [o for o in obs if o.agent == filt_agent]
            payload = [o.model_dump(mode="json") for o in obs]
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
    # one shared gate + deduplicator across ALL agents — a manifestation of
    # the same root cause found by different agents merges into one finding
    shared = getattr(blackboard, "_shared_gate", None)
    if not isinstance(shared, FindingGate):
        shared = FindingGate()
        blackboard._shared_gate = shared  # type: ignore[attr-defined]
    reg.register(ReportFindingTool(blackboard, agent_name, gate=shared))
    reg.register(QueryBlackboardTool(blackboard))
    reg.register(UpdateTaskTool(blackboard))
    reg.register(AddTaskTool(blackboard, agent_name))
    reg.register(AnnotateFindingTool(blackboard))
