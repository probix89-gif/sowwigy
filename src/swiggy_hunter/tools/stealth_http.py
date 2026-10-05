"""
stealth_http — the primary HTTP tool in V2.

Everything agents do against the target goes through this tool. It:
  - uses the shared AuthManager's StealthSession (TLS-impersonating,
    human-paced, referer-chained)
  - blocks out-of-scope URLs (via ScopeGuard, injected at build time)
  - records every request/response as a capture artifact
  - auto-absorbs Set-Cookie, respects behavior back-off
  - exposes a session_name arg so agents can hit as a specific identity
  - can stream raw evidence back into the LLM-friendly render

Returned meta includes the raw capture dict so report_finding can
attach it as evidence.
"""
from __future__ import annotations

import json
from typing import Any

from ..logging_setup import get_logger
from ..scanner.scope import ScopeGuard, ScopeViolation
from ..stealth.session import StealthSession, StealthResponse
from .base import Tool, ToolResult

log = get_logger(__name__)


class StealthHttpTool(Tool):
    name = "stealth_http"
    description = (
        "Send an HTTP request through the stealth session (real browser "
        "TLS + human pacing + coherent headers + auth cookies). This is "
        "the default way to talk to the target. Supports GET/POST/PUT/"
        "PATCH/DELETE/OPTIONS/HEAD. Returns status, headers, body. "
        "Cookies from Set-Cookie are absorbed automatically. "
        "Use kind='navigate' for top-level pages, 'xhr' for API calls "
        "(default), 'form' for form POSTs."
    )
    parameters = {
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
                "default": "GET",
            },
            "url": {"type": "string"},
            "headers": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
            "params": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
            "json_body": {"type": "object"},
            "data": {"type": "string"},
            "kind": {
                "type": "string",
                "enum": ["navigate", "xhr", "form", "asset", "preflight"],
                "default": "xhr",
            },
            "timeout": {"type": "integer", "default": 45},
            "allow_redirects": {"type": "boolean", "default": True},
        },
        "required": ["url"],
    }

    def __init__(
        self,
        session_provider,
        scope: ScopeGuard | None = None,
        evidence_collector=None,
        max_body: int = 200_000,
    ):
        # session_provider is a callable returning the current StealthSession
        # (usually AuthManager.session — we keep a callable so rotation
        # is transparent)
        self.session_provider = session_provider
        self.scope = scope
        self.evidence = evidence_collector
        self.max_body = max_body

    def _get_session(self) -> StealthSession:
        s = self.session_provider() if callable(self.session_provider) else self.session_provider
        if s is None:
            raise RuntimeError("no stealth session available")
        return s

    async def run(self, **kwargs: Any) -> ToolResult:
        method = (kwargs.get("method") or "GET").upper()
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

        session = self._get_session()

        resp = await session.request(
            method=method,
            url=url,
            params=kwargs.get("params") or None,
            headers=kwargs.get("headers") or None,
            json_body=kwargs.get("json_body"),
            data=kwargs.get("data"),
            kind=kwargs.get("kind", "xhr"),
            timeout=float(kwargs.get("timeout", 45)),
            allow_redirects=bool(kwargs.get("allow_redirects", True)),
        )

        return self._render(resp, method)

    def _render(self, resp: StealthResponse, method: str) -> ToolResult:
        body_text = resp.text[: self.max_body]
        truncated = len(resp.body) > self.max_body

        lines = [
            f">>> {method} {resp.url}",
            f"<<< {resp.status} ({resp.elapsed_ms}ms, fp={resp.fingerprint_id})",
        ]
        for k, v in resp.headers.items():
            if k.lower() in ("set-cookie", "content-length"):
                v = v[:200]
            lines.append(f"<<< {k}: {v}")
        lines.append("")
        lines.append(body_text)
        if truncated:
            lines.append(f"\n... [truncated, full body {len(resp.body)} bytes]")

        capture = resp.to_capture(method=method, request_headers={}, request_body=None)

        return ToolResult(
            ok=200 <= resp.status < 400,
            output="\n".join(lines),
            error=None if 200 <= resp.status < 400 else f"HTTP {resp.status}",
            meta={"capture": capture, "status": resp.status,
                  "url": resp.url, "fingerprint": resp.fingerprint_id},
        )


def _try_parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None
