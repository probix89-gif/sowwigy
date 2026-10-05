"""
Web analysis tools — headers, cookies. Uses stealth session.
"""
from __future__ import annotations

import json
from typing import Any

from .base import Tool, ToolResult


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


class HeaderAnalysisTool(Tool):
    name = "header_analysis"
    description = "Fetch a URL and analyze response headers (security gaps, stack hints)."
    parameters = {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    }

    def __init__(self, session_provider):
        self.session_provider = session_provider

    def _get_session(self):
        s = self.session_provider() if callable(self.session_provider) else self.session_provider
        if s is None:
            raise RuntimeError("no stealth session")
        return s

    async def run(self, **kwargs: Any) -> ToolResult:
        url = kwargs.get("url", "")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        session = self._get_session()
        try:
            r = await session.get(url, kind="navigate")
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))
        headers = {k.lower(): v for k, v in r.headers.items()}
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        interesting_keys = ["server", "x-powered-by", "via", "x-cache"]
        interesting = {k: v for k, v in headers.items()
                       if any(k.startswith(p) for p in interesting_keys)}
        report = {
            "url": url,
            "status": r.status,
            "missing_security_headers": missing,
            "interesting_headers": interesting,
            "all_headers": headers,
        }
        return ToolResult(ok=True, output=json.dumps(report, indent=2), meta=report)


class CookieInspectTool(Tool):
    name = "cookie_inspect"
    description = "Analyze Set-Cookie headers for missing flags / JWT-shaped values."
    parameters = {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    }

    def __init__(self, session_provider):
        self.session_provider = session_provider

    def _get_session(self):
        s = self.session_provider() if callable(self.session_provider) else self.session_provider
        if s is None:
            raise RuntimeError("no stealth session")
        return s

    async def run(self, **kwargs: Any) -> ToolResult:
        url = kwargs.get("url", "")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        session = self._get_session()
        try:
            r = await session.get(url, kind="navigate")
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))

        raw_list: list[str] = []
        for k, v in r.headers.items():
            if k.lower() == "set-cookie":
                raw_list.append(v)
        parsed = []
        for raw in raw_list:
            parts = [p.strip() for p in raw.split(";")]
            name, _, val = parts[0].partition("=")
            flags: dict[str, Any] = {"httponly": False, "secure": False, "samesite": None}
            for p in parts[1:]:
                low = p.lower()
                if low == "httponly":
                    flags["httponly"] = True
                elif low == "secure":
                    flags["secure"] = True
                elif low.startswith("samesite"):
                    flags["samesite"] = p.split("=", 1)[-1]
            jwt_shaped = val.count(".") == 2 and len(val) > 40
            parsed.append({
                "name": name,
                "value_preview": val[:24] + ("..." if len(val) > 24 else ""),
                "flags": flags,
                "jwt_shaped": jwt_shaped,
            })
        return ToolResult(ok=True, output=json.dumps(parsed, indent=2),
                          meta={"cookies": parsed})


class ParamFuzzTool(Tool):
    name = "param_fuzz"
    description = (
        "Send a request repeatedly with modified parameter values, report "
        "responses. Prefer stealth_race for true concurrency."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "default": "GET"},
            "param_name": {"type": "string"},
            "variants": {"type": "array", "items": {"type": "string"}},
            "base_params": {"type": "object",
                            "additionalProperties": {"type": "string"}},
            "headers": {"type": "object",
                        "additionalProperties": {"type": "string"}},
            "json_mode": {"type": "boolean", "default": False},
        },
        "required": ["url", "param_name", "variants"],
    }

    def __init__(self, session_provider):
        self.session_provider = session_provider

    def _get_session(self):
        s = self.session_provider() if callable(self.session_provider) else self.session_provider
        if s is None:
            raise RuntimeError("no stealth session")
        return s

    async def run(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        method = kwargs.get("method", "GET").upper()
        param = kwargs["param_name"]
        variants = kwargs["variants"]
        base = kwargs.get("base_params") or {}
        headers = kwargs.get("headers") or {}
        json_mode = bool(kwargs.get("json_mode", False))

        session = self._get_session()
        results: list[dict[str, Any]] = []
        for v in variants:
            try:
                if json_mode:
                    body = {**base, param: v}
                    r = await session.api_post(url, json_body=body, headers=headers or None)
                else:
                    if method == "GET":
                        params = {**base, param: v}
                        r = await session.api_get(url, params=params, headers=headers or None)
                    else:
                        r = await session.request(
                            method, url, headers=headers or None,
                            data=json.dumps({**base, param: v}), kind="xhr",
                        )
                results.append({
                    "variant": v, "status": r.status, "len": len(r.body),
                    "preview": r.text[:200],
                })
            except Exception as e:
                results.append({"variant": v, "error": str(e)})

        results.sort(key=lambda r: r.get("len", -1))
        return ToolResult(ok=True,
                          output=json.dumps({"param": param, "results": results}, indent=2),
                          meta={"results": results})
