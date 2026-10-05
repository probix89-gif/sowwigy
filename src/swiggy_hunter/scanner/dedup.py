"""
Finding deduplicator. Same signature → merge evidence, bump severity.
Signature = (normalized endpoint, category, first 120 chars of desc).
"""
from __future__ import annotations

import hashlib
import re
import time

from ..state.schemas import Finding, Severity


_WS = re.compile(r"\s+")
_SEV_RANK = {
    Severity.info: 1, Severity.low: 2, Severity.medium: 3,
    Severity.high: 4, Severity.critical: 5,
}


def _norm_endpoint(endpoint: str | None) -> str:
    if not endpoint:
        return ""
    e = endpoint.lower().strip().rstrip("/")
    if "?" in e:
        base, _, q = e.partition("?")
        pairs = sorted(p for p in q.split("&") if p)
        e = f"{base}?{'&'.join(pairs)}"
    return e


def _norm_desc(text: str) -> str:
    return _WS.sub(" ", (text or "").strip().lower())[:120]


class FindingDeduplicator:
    def __init__(self) -> None:
        self._index: dict[str, str] = {}

    def signature(self, f: Finding) -> str:
        raw = "|".join([
            _norm_endpoint(f.endpoint),
            (f.category or "").lower(),
            _norm_desc(f.description),
        ])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def lookup(self, f: Finding) -> str | None:
        return self._index.get(self.signature(f))

    def register(self, f: Finding) -> None:
        self._index[self.signature(f)] = f.id

    def merge(self, existing: Finding, incoming: Finding) -> Finding:
        existing.evidence.extend(
            e for e in incoming.evidence if e not in existing.evidence
        )
        for step in incoming.repro_steps:
            if step not in existing.repro_steps:
                existing.repro_steps.append(step)
        for tag in incoming.tags:
            if tag not in existing.tags:
                existing.tags.append(tag)
        existing.meta.setdefault("duplicates", []).append({
            "at": time.time(),
            "by": incoming.discovered_by.value,
            "title": incoming.title,
        })
        if _SEV_RANK.get(incoming.severity, 0) > _SEV_RANK.get(existing.severity, 0):
            existing.severity = incoming.severity
        existing.updated_at = time.time()
        return existing

    def rebuild(self, findings: list[Finding]) -> None:
        self._index.clear()
        for f in findings:
            self.register(f)
