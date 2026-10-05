"""
Attach Runtime to Orchestrator:
  - route findings through the deduplicator on write
  - mirror every finding into evidence/ as a note
"""
from __future__ import annotations

import asyncio
from typing import Any

from .logging_setup import get_logger
from .state.schemas import Finding

log = get_logger(__name__)


def attach_runtime(orch: Any, runtime: Any) -> None:
    dedup = runtime.dedup
    evidence = runtime.evidence

    original_upsert = orch.blackboard.upsert_finding

    async def _seed():
        try:
            findings = await orch.blackboard.list_findings()
            dedup.rebuild(findings)
        except Exception:
            log.exception("patch.seed_dedup_failed")

    try:
        loop = asyncio.get_event_loop()
        loop.create_task(_seed())
    except RuntimeError:
        pass

    async def dedup_aware_upsert(finding: Finding) -> Finding:
        existing_id = dedup.lookup(finding)
        if existing_id and existing_id != finding.id:
            existing = await orch.blackboard.get_finding(existing_id)
            if existing is not None:
                merged = dedup.merge(existing, finding)
                for ev in finding.evidence:
                    try:
                        evidence.note(merged.id, ev)
                    except Exception:
                        pass
                return await original_upsert(merged)

        dedup.register(finding)
        try:
            evidence.save_meta(finding.id, {
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity.value,
                "discovered_by": finding.discovered_by.value,
            })
            for ev in finding.evidence:
                evidence.note(finding.id, ev)
        except Exception:
            log.exception("patch.evidence_route_failed", finding_id=finding.id)
        return await original_upsert(finding)

    orch.blackboard.upsert_finding = dedup_aware_upsert  # type: ignore[assignment]
    log.info("orchestrator.runtime_attached")
