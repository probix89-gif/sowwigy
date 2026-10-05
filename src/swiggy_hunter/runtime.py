"""
Runtime — process-wide singletons that aren't part of AgentContext.

Owns: scope guard, rate governor, profiler, dedup, evidence, exploit
builder. Wires the scope + rate governor into the stealth session
(already done via the session itself for pacing; the governor is used
by the race helper).
"""
from __future__ import annotations

from .config import AppConfig
from .logging_setup import get_logger
from .scanner import (
    EvidenceCollector,
    ExploitBuilder,
    FindingDeduplicator,
    RateGovernor,
    ScopeGuard,
    TargetProfiler,
)

log = get_logger(__name__)


class Runtime:
    def __init__(self, config: AppConfig):
        self.config = config
        self.scope = ScopeGuard(patterns=config.target.scope or [config.target.domain])
        self.governor = RateGovernor(default_rps=5.0, cooldown_seconds=45.0)
        self.profiler = TargetProfiler(data_dir=config.paths.data_dir)
        self.dedup = FindingDeduplicator()
        self.evidence = EvidenceCollector(data_dir=config.paths.data_dir)
        self.exploits = ExploitBuilder(data_dir=config.paths.data_dir)
        log.info("runtime.ready", patterns=self.scope.patterns())

    def describe(self) -> dict:
        return {
            "scope_patterns": self.scope.patterns(),
            "rate": self.governor.snapshot(),
            "profile_hosts": list(self.profiler.hosts.keys()),
        }

    async def shutdown(self) -> None:
        self.profiler.flush()
