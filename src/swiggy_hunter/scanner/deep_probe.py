"""
DeepProbe — batch a param with N variants, auto-diff for meaningful
divergence. Uses the stealth session so tests look human-paced.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

from ..logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class ProbeResult:
    variant: str
    status: int
    len_body: int
    preview: str
    error: str | None = None
    ok: bool = False


@dataclass
class ProbeDiff:
    endpoint: str
    param: str
    baseline: ProbeResult | None
    variants: list[ProbeResult]

    def interesting(self) -> list[ProbeResult]:
        if self.baseline is None:
            return self.variants
        base_status = self.baseline.status
        base_len = self.baseline.len_body
        out: list[ProbeResult] = []
        for v in self.variants:
            if v.error:
                continue
            if v.status != base_status:
                out.append(v)
                continue
            if base_len and abs(v.len_body - base_len) / base_len > 0.10:
                out.append(v)
        return out


class DeepProbe:
    def __init__(self, session_provider):
        self.session_provider = session_provider

    def _session(self):
        s = self.session_provider() if callable(self.session_provider) else self.session_provider
        if s is None:
            raise RuntimeError("no stealth session")
        return s

    async def probe(
        self,
        endpoint: str,
        method: str,
        param: str,
        variants: list[str],
        base_params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        json_mode: bool = False,
        baseline_value: str | None = None,
    ) -> ProbeDiff:
        base_params = base_params or {}
        headers = headers or {}
        session = self._session()

        async def call(value: str) -> ProbeResult:
            try:
                if json_mode:
                    body = dict(base_params)
                    body[param] = value
                    r = await session.api_post(endpoint, json_body=body,
                                               headers=headers or None)
                elif method.upper() == "GET":
                    params = dict(base_params)
                    params[param] = value
                    r = await session.api_get(endpoint, params=params,
                                              headers=headers or None)
                else:
                    r = await session.request(
                        method.upper(), endpoint,
                        headers=headers or None,
                        data=json.dumps({**base_params, param: value}),
                        kind="xhr",
                    )
                return ProbeResult(variant=value, status=r.status,
                                   len_body=len(r.body), preview=r.text[:300],
                                   ok=True)
            except Exception as e:
                return ProbeResult(variant=value, status=0, len_body=0,
                                   preview="", error=str(e), ok=False)

        baseline = await call(baseline_value) if baseline_value is not None else None
        results = await asyncio.gather(*(call(v) for v in variants))
        return ProbeDiff(endpoint=endpoint, param=param,
                         baseline=baseline, variants=list(results))
