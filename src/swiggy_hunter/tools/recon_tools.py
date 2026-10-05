"""
Recon helpers. Uses external binaries if present (subfinder), else
built-in wordlist DNS brute.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import socket
from typing import Any

from ..logging_setup import get_logger
from .base import Tool, ToolResult

log = get_logger(__name__)


class SubdomainEnumTool(Tool):
    name = "subdomain_enum"
    description = (
        "Enumerate subdomains. Uses subfinder if installed, otherwise "
        "a built-in wordlist DNS brute."
    )
    parameters = {
        "type": "object",
        "properties": {"domain": {"type": "string"}},
        "required": ["domain"],
    }

    BUILTIN = [
        "api", "app", "admin", "www", "m", "mobile", "partner", "partners",
        "restaurant", "restaurants", "delivery", "order", "orders", "pay",
        "payments", "wallet", "user", "users", "auth", "login", "sso",
        "cdn", "static", "assets", "img", "images", "media",
        "test", "staging", "stage", "dev", "beta", "internal",
        "dashboard", "analytics", "metrics", "grafana", "kibana", "logs",
        "support", "help", "docs", "status", "health", "monitor",
    ]

    async def run(self, **kwargs: Any) -> ToolResult:
        domain = kwargs["domain"]
        results: set[str] = set()
        subfinder = shutil.which("subfinder")

        if subfinder:
            try:
                proc = await asyncio.create_subprocess_shell(
                    f"{subfinder} -d {domain} -silent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, _ = await proc.communicate()
                for line in out.decode().splitlines():
                    line = line.strip()
                    if line:
                        results.add(line)
            except Exception:
                log.exception("subfinder.failed")

        sem = asyncio.Semaphore(20)
        loop = asyncio.get_event_loop()

        async def check(name: str) -> None:
            host = f"{name}.{domain}"
            async with sem:
                try:
                    await loop.run_in_executor(None, socket.gethostbyname, host)
                    results.add(host)
                except Exception:
                    pass

        await asyncio.gather(*(check(n) for n in self.BUILTIN))
        return ToolResult(
            ok=True,
            output="\n".join(sorted(results)) or "(none found)",
            meta={"count": len(results), "subdomains": sorted(results)},
        )


class EndpointDiscoveryTool(Tool):
    name = "endpoint_discovery"
    description = (
        "Probe common API / app paths on a host, report status + size. "
        "Goes through the stealth session, so no rate-limit blowups."
    )
    parameters = {
        "type": "object",
        "properties": {
            "base_url": {"type": "string"},
            "paths": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["base_url"],
    }

    DEFAULT_PATHS = [
        "/", "/api", "/api/v1", "/api/v2", "/api/v3",
        "/health", "/status", "/metrics",
        "/login", "/signup", "/auth", "/oauth/token",
        "/user", "/me", "/profile", "/account",
        "/cart", "/order", "/orders", "/checkout",
        "/coupon", "/coupons", "/offer", "/offers",
        "/payment", "/wallet", "/transaction",
        "/restaurant", "/restaurants", "/menu", "/search",
        "/admin", "/dashboard",
        "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
        "/graphql", "/swagger.json", "/openapi.json",
    ]

    def __init__(self, session_provider):
        self.session_provider = session_provider

    def _get_session(self):
        s = self.session_provider() if callable(self.session_provider) else self.session_provider
        if s is None:
            raise RuntimeError("no stealth session")
        return s

    async def run(self, **kwargs: Any) -> ToolResult:
        base = kwargs["base_url"].rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        paths = kwargs.get("paths") or self.DEFAULT_PATHS
        session = self._get_session()
        results: list[dict[str, Any]] = []

        for path in paths:
            url = base + path
            try:
                r = await session.api_get(url)
                results.append({
                    "path": path,
                    "status": r.status,
                    "len": len(r.body),
                    "ctype": r.headers.get("content-type", ""),
                })
            except Exception as e:
                results.append({"path": path, "error": str(e)})

        results.sort(key=lambda r: (r.get("status", 999), r.get("path", "")))
        return ToolResult(ok=True, output=json.dumps(results, indent=2),
                          meta={"endpoints": results})


class TechFingerprintTool(Tool):
    name = "tech_fingerprint"
    description = "Fingerprint tech stack from headers + body."
    parameters = {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    }

    SIGNATURES = {
        "cloudflare": ["cf-ray", "cf-cache-status"],
        "nginx": ["nginx"],
        "apache": ["apache"],
        "iis": ["iis", "x-aspnet"],
        "express": ["x-powered-by: express"],
        "nextjs": ["x-powered-by: next.js", "__next"],
        "django": ["csrftoken", "django"],
        "rails": ["_rails", "rails"],
        "react": ["react", "_next/static"],
        "graphql": ["graphql"],
        "aws": ["x-amz", "amazonaws"],
        "gcp": ["x-goog", "google"],
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
        session = self._get_session()
        try:
            r = await session.get(url, kind="navigate")
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))

        headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body = r.text[:5000].lower()
        cookies = " ".join(
            v for k, v in r.headers.items() if k.lower() == "set-cookie"
        ).lower()
        hay = headers_text + "\n" + body + "\n" + cookies

        hits: list[str] = []
        for tech, sigs in self.SIGNATURES.items():
            for sig in sigs:
                if sig in hay:
                    hits.append(tech)
                    break
        return ToolResult(
            ok=True,
            output=json.dumps({"url": url, "technologies": sorted(set(hits))}, indent=2),
            meta={"technologies": sorted(set(hits))},
        )
