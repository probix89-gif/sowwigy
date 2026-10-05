"""
browser_tool — Playwright actions exposed as a Tool.

Actions:
  - goto: navigate to a URL, capture HTML + cookies
  - click: click a selector
  - fill: fill an input
  - eval: run JS and return the result
  - screenshot: save a PNG
  - get_cookies: current browser cookies
  - import_cookies: push HTTP cookies into the browser context

The browser is a single shared instance (owned by the runtime) so
auth state persists across calls.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from ..logging_setup import get_logger
from ..scanner.scope import ScopeGuard, ScopeViolation
from .base import Tool, ToolResult

log = get_logger(__name__)


class BrowserTool(Tool):
    name = "browser"
    description = (
        "Drive a headless browser (Playwright Chromium, stealth-hardened). "
        "Use when an endpoint requires JS execution to produce valid "
        "requests or when you need to observe rendered state. "
        "Actions: goto, click, fill, eval, screenshot, get_cookies, "
        "import_cookies, current_url."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "goto", "click", "fill", "eval", "screenshot",
                    "get_cookies", "import_cookies", "current_url",
                ],
            },
            "url": {"type": "string"},
            "selector": {"type": "string"},
            "value": {"type": "string"},
            "js": {"type": "string"},
            "path": {"type": "string"},
            "cookies": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
            "wait_until": {
                "type": "string",
                "enum": ["load", "domcontentloaded", "networkidle"],
                "default": "domcontentloaded",
            },
        },
        "required": ["action"],
    }

    def __init__(self, browser_provider, scope: ScopeGuard | None = None,
                 screenshot_dir: str | Path = "./data/screenshots"):
        self.browser_provider = browser_provider
        self.scope = scope
        self.screenshot_dir = Path(screenshot_dir)
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

    async def _get_browser(self):
        b = self.browser_provider() if callable(self.browser_provider) else self.browser_provider
        if b is None:
            raise RuntimeError("browser not available (playwright not initialized)")
        # lazy start
        if getattr(b, "_page", None) is None:
            await b.start()
        return b

    async def run(self, **kwargs: Any) -> ToolResult:
        action = kwargs.get("action")
        if not action:
            return ToolResult(ok=False, output="", error="missing action")

        try:
            browser = await self._get_browser()
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))

        try:
            if action == "goto":
                return await self._goto(browser, kwargs)
            if action == "click":
                return await self._click(browser, kwargs)
            if action == "fill":
                return await self._fill(browser, kwargs)
            if action == "eval":
                return await self._eval(browser, kwargs)
            if action == "screenshot":
                return await self._screenshot(browser, kwargs)
            if action == "get_cookies":
                return await self._get_cookies(browser)
            if action == "import_cookies":
                return await self._import_cookies(browser, kwargs)
            if action == "current_url":
                url = await browser.current_url()
                return ToolResult(ok=True, output=url)
        except Exception as e:
            log.exception("browser_tool.failed", action=action)
            return ToolResult(ok=False, output="", error=f"{type(e).__name__}: {e}")

        return ToolResult(ok=False, output="", error=f"unknown action: {action}")

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------

    async def _goto(self, browser, kw) -> ToolResult:
        url = kw.get("url") or ""
        if not url:
            return ToolResult(ok=False, output="", error="missing url")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if self.scope is not None:
            try:
                self.scope.check(url)
            except ScopeViolation as e:
                return ToolResult(ok=False, output="", error=f"scope: {e}")

        result = await browser.goto(url, wait_until=kw.get("wait_until", "domcontentloaded"))
        html_preview = result.html[:5000]
        lines = [
            f"=== goto {result.url} ===",
            f"title: {result.title}",
            f"status: {result.status}",
            f"cookies: {len(result.cookies)}",
            "",
            "--- html (first 5000) ---",
            html_preview,
        ]
        return ToolResult(
            ok=200 <= result.status < 400,
            output="\n".join(lines),
            meta={"url": result.url, "title": result.title,
                  "cookies": result.cookies, "status": result.status},
        )

    async def _click(self, browser, kw) -> ToolResult:
        sel = kw.get("selector")
        if not sel:
            return ToolResult(ok=False, output="", error="missing selector")
        await browser.click(sel)
        return ToolResult(ok=True, output=f"clicked {sel}")

    async def _fill(self, browser, kw) -> ToolResult:
        sel = kw.get("selector")
        val = kw.get("value") or ""
        if not sel:
            return ToolResult(ok=False, output="", error="missing selector")
        await browser.fill(sel, val)
        return ToolResult(ok=True, output=f"filled {sel}")

    async def _eval(self, browser, kw) -> ToolResult:
        js = kw.get("js")
        if not js:
            return ToolResult(ok=False, output="", error="missing js")
        out = await browser.eval(js)
        import json
        try:
            text = json.dumps(out, indent=2, default=str)
        except Exception:
            text = str(out)
        return ToolResult(ok=True, output=text)

    async def _screenshot(self, browser, kw) -> ToolResult:
        name = kw.get("path") or f"shot_{int(__import__('time').time())}.png"
        if not name.endswith(".png"):
            name += ".png"
        path = self.screenshot_dir / Path(name).name
        await browser.screenshot(str(path))
        return ToolResult(ok=True, output=f"saved {path}", meta={"path": str(path)})

    async def _get_cookies(self, browser) -> ToolResult:
        cookies = await browser._dump_cookies()
        import json
        return ToolResult(ok=True, output=json.dumps(cookies, indent=2),
                          meta={"cookies": cookies})

    async def _import_cookies(self, browser, kw) -> ToolResult:
        cookies = kw.get("cookies") or {}
        if not cookies:
            return ToolResult(ok=False, output="", error="no cookies provided")
        await browser.import_cookies(cookies)
        return ToolResult(ok=True, output=f"imported {len(cookies)} cookies")
