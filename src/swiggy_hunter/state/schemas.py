"""
Shared data models. V2 adds the hermes agent name; everything else is
stable.
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, Enum):
    new = "new"
    validating = "validating"
    confirmed = "confirmed"
    false_positive = "false_positive"
    reported = "reported"


class TaskStatus(str, Enum):
    pending = "pending"
    assigned = "assigned"
    running = "running"
    done = "done"
    failed = "failed"
    blocked = "blocked"


class AgentName(str, Enum):
    decision = "decision"
    recon = "recon"
    business_logic = "business_logic"
    research = "research"
    validation = "validation"
    attacker = "attacker"
    hermes = "hermes"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:10])
    title: str
    category: str
    severity: Severity = Severity.info
    status: FindingStatus = FindingStatus.new
    endpoint: str | None = None
    method: str | None = None
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    repro_steps: list[str] = Field(default_factory=list)
    discovered_by: AgentName
    discovered_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class Observation(BaseModel):
    """Internal evidence that did NOT pass the finding gate.

    Low-level observations (endpoint discoveries, weak anomalies, partial
    evidence) are preserved here so future agents can use them as
    building blocks — without polluting the findings pipeline."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:10])
    title: str
    category: str = "other"
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    repro_steps: list[str] = Field(default_factory=list)
    endpoint: str | None = None
    tags: list[str] = Field(default_factory=list)
    agent: str = ""
    impact_category: str | None = None
    impact_score: float = 0.0
    gate_reason: str = ""
    created_at: float = Field(default_factory=time.time)


class Task(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:10])
    title: str
    description: str = ""
    assignee: AgentName
    priority: int = 5
    status: TaskStatus = TaskStatus.pending
    depends_on: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    result: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class AgentStatus(BaseModel):
    name: AgentName
    state: Literal["idle", "working", "blocked", "error", "stopped"] = "idle"
    current_task_id: str | None = None
    last_heartbeat: float = Field(default_factory=time.time)
    notes: str = ""


class SessionInfo(BaseModel):
    """A stealth-authenticated identity against Swiggy."""
    name: str
    phone: str | None = None
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    fingerprint_id: str | None = None
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    expires_at: float | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
