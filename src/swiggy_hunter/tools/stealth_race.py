"""
stealth_race — the ONLY sanctioned way to fire concurrent requests.

Race conditions are a legitimate business-logic test. Firing them
carefully means:
  - cap concurrency (default 8, max 20)
  - go through the StealthSession (TLS + headers coherent)
  - pace across the batch so we don't trigger rate-limits
  - return per-request status + a summary of successful vs failed
  - never exceed 5 rps host-wide, even during the burst

The attacker agent uses this for coupon-race, order-race, wallet-race.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from ..logging_setup import get_logger
from ..scanner.scope import ScopeGuard, ScopeViolation
from ..stealth.session import StealthSession
from .base import Tool, ToolResult

log = get_logger(__name__)


class StealthRaceTool(Tool):
    name = "stealth_race"
    description = (
        "Fire N concurrent identical requests at the same endpoint to test "
        "for race conditions (coupon reuse, order-race, wallet-credit race). "
        "Governed: max 20 concurrent, host rps respected, stealth session "
        "used for every request. Returns per-request status and a summary "
        "of how many succeeded. Use ONLY for legitimate race tests — not "
        "for fuzzing."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                "default": "POST",
            },
            "headers": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
            "json_body": {"type": "object"},
            "data": {"type": "string"},
            "count": {"type": "integer", "default": 8, "minimum": 2, "maximum": 20},
            "concurrency": {"type": "integer", "default": 8, "minimum": 2, "maximum": 20},
            "stagger_ms": {
                "type": "integer",
                "default": 0,
                "description": "Optional stagger between firing each request",
            },
        },
        "required": ["url"],
    }

    def __init__(
        self,
        session_provider,
        scope: ScopeGuard | None = None,
        max_body: int = 20_000,
    ):
        self.session_provider = session_provider
        self.scope = scope
        self.max_body = max_body

    def _get_session(self) -> StealthSession:
        s = self.session_provider() if callable(self.session_provider) else self.session_provider
        if s is None:
            raise RuntimeError("no stealth session")
        return s

    async def run(self, **kwargs: Any) -> ToolResult:
        url = (kwargs.get("url") or "").strip()
        if not url:
            return ToolResult(ok=False, output="", error="missing url")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        if self.scope is not None:
            try:
                self.scope.check(url)
            except ScopeViolation as e:
                return ToolResult(ok=False, output="", error=f"scope: {e}")

        method = (kwargs.get("method") or "POST").upper()
        headers = kwargs.get("headers") or {}
        json_body = kwargs.get("json_body")
        data = kwargs.get("data")
        count = min(20, max(2, int(kwargs.get("count", 8))))
        concurrency = min(20, max(2, int(kwargs.get("concurrency", count))))
        stagger_ms = int(kwargs.get("stagger_ms", 0))

        session = self._get_session()

        sem = asyncio.Semaphore(concurrency)
        results: list[dict[str, Any]] = []
        lock = asyncio.Lock()
        started = time.monotonic()

        async def one(idx: int) -> None:
            if stagger_ms and idx > 0:
                await asyncio.sleep((stagger_ms * idx) / 1000.0)
            async with sem:
                try:
                    r = await session.request(
                        method=method,
                        url=url,
                        headers=headers or None,
                        json_body=json_body,
                        data=data,
                        kind="xhr",
                        timeout=45,
                    )
                    async with lock:
                        results.append({
                            "idx": idx,
                            "status": r.status,
                            "elapsed_ms": r.elapsed_ms,
                            "body_preview": r.text[:500],
                        })
                except Exception as e:
                    async with lock:
                        results.append({
                            "idx": idx,
                            "error": f"{type(e).__name__}: {e}",
                        })

        await asyncio.gather(*(one(i) for i in range(count)))

        elapsed = time.monotonic() - started
        results.sort(key=lambda r: r["idx"])

        ok_count = sum(1 for r in results if 200 <= r.get("status", 0) < 300)
        created = sum(1 for r in results if r.get("status") == 201)
        conflict = sum(1 for r in results if r.get("status") in (409, 400, 422))
        rate_limited = sum(1 for r in results if r.get("status") == 429)
        error_count = sum(1 for r in results if r.get("error"))

        summary = {
            "total": count,
            "succeeded_2xx": ok_count,
            "created_201": created,
            "conflict_4xx": conflict,
            "rate_limited_429": rate_limited,
            "errors": error_count,
            "elapsed_s": round(elapsed, 3),
            "host_rps": round(count / elapsed, 2) if elapsed else 0,
        }

        # race signal: more than one 2xx is potentially a race win
        race_indicator = ok_count > 1

        lines = [
            f"=== stealth_race {method} {url} x{count} ===",
            f"elapsed: {summary['elapsed_s']}s  host_rps: {summary['host_rps']}",
            f"2xx: {ok_count}  4xx: {conflict}  429: {rate_limited}  errors: {error_count}",
            f"race_indicator (more than one success): {race_indicator}",
            "",
        ]
        for r in results:
            status = r.get("status", "err")
            preview = (r.get("body_preview") or "").replace("\n", " ")[:120]
            lines.append(f"  #{r['idx']:02d}  {status}  {preview}")

        return ToolResult(
            ok=error_count == 0,
            output="\n".join(lines),
            error=None if error_count == 0 else f"{error_count} request(s) failed",
            meta={"summary": summary, "race_indicator": race_indicator,
                  "results": results, "url": url, "method": method},
        )
