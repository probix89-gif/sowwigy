"""
Agent factory. Builds every agent with its own tool registry, bound to
the correct agent_name for blackboard writes.
"""
from __future__ import annotations

from .context import AgentContext
from .base import BaseAgent, AgentRunResult
from .decision import DecisionAgent
from .recon import ReconAgent
from .business_logic import BusinessLogicAgent
from .research import ResearchAgent
from .validation import ValidationAgent
from .attacker import AttackerAgent
from .hermes import HermesAgent
from ..state.schemas import AgentName


AGENT_CLASSES = {
    AgentName.recon: ReconAgent,
    AgentName.business_logic: BusinessLogicAgent,
    AgentName.research: ResearchAgent,
    AgentName.validation: ValidationAgent,
    AgentName.attacker: AttackerAgent,
    AgentName.hermes: HermesAgent,
}


def build_agent(name: AgentName, ctx: AgentContext) -> BaseAgent:
    cls = AGENT_CLASSES.get(name)
    if cls is None:
        raise ValueError(f"no concrete agent for {name}")
    return cls(ctx)


__all__ = [
    "AgentContext",
    "BaseAgent",
    "AgentRunResult",
    "DecisionAgent",
    "ReconAgent",
    "BusinessLogicAgent",
    "ResearchAgent",
    "ValidationAgent",
    "AttackerAgent",
    "HermesAgent",
    "build_agent",
    "AGENT_CLASSES",
]
