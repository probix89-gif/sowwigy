"""
Browser — Playwright wrapper for JS-heavy flows.

Some endpoints (auth, checkout) require actual JS execution to produce
valid request signatures. The browser gives us that.

Design:
  - one Browser instance per StealthSession that needs it
  - real Chromium in headless mode (playwright's chromium)
  - stealth: real UA from fingerprint, timezone, locale, viewport
  - init scripts to nuke webdriver flags, patch navigator
  - cookie import/export so HTTP and browser share auth state
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from ..logging_setup import get_logger
from .fingerprint import Fingerprint

log = get_logger(__name__)


_STEALTH_INIT_SCRIPT = """
// Hide webdriver
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

// Fake plugins
Object.defineProperty(navigator, 'plugins', {
  get: () => [1, 2, 3, 4, 5].map(i => ({ name: 'Plugin ' + i })),
});

// Fake languages
Object.defineProperty(navigator, 'languages', {
  get: () => ['en-IN', 'en', 'en-GB'],
});

// Patch chrome runtime
window.chrome = window.chrome || { runtime: {} };

// Permissions API shim
const originalQuery = window.navigator.permissions && window.navigator.permissions.query;
if (originalQuery) {
  window.navigator.permissions.query = (parameters) =>
    parameters.name === 'notifications'
      ? Promise.resolve({ state: Notification.permission })
      : originalQuery(parameters);
}
"""


@dataclass
class BrowserResult:
    url: str
    title: str
    html: str
    cookies: dict[str, str]
    status: int = 200


class Browser:
    def __init__(self, fingerprint: Fingerprint, browser_cfg: Any):
        self.fp = fingerprint
        self.cfg = browser_cfg
        self._playwright: Any | None = None
        self._browser: Any | None = None
        self._context: Any | None = None
        self._page: Any | None = None

    async def start(self) -> None:
        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception as e:
            raise RuntimeError(f"playwright not installed: {e}")

        self._playwright = await async_playwright().start()
        # use bundled chromium (real Chrome via channel="chrome" is optional)
        launch_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process",
            "--no-sandbox",
            "--disable-dev-shm-usage",
        ]
        self._browser = await self._playwright.chromium.launch(
            headless=self.cfg.headless,
            args=launch_args,
        )
        self._context = await self._browser.new_context(
            user_agent=self.fp.ua,
            viewport={"width": self.fp.viewport[0], "height": self.fp.viewport[1]},
            locale="en-IN",
            timezone_id=self.fp.timezone,
            geolocation={"latitude": 12.9716, "longitude": 77.5946},  # Bengaluru
            permissions=["geolocation"],
            color_scheme="light",
        )
        await self._context.add_init_script(_STEALTH_INIT_SCRIPT)
        self._page = await self._context.new_page()
        log.info("browser.started", fp=self.fp.id)

    async def stop(self) -> None:
        try:
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None

    async def goto(self, url: str, wait_until: str = "domcontentloaded",
                   timeout_ms: int = 45000) -> BrowserResult:
        if self._page is None:
            await self.start()
        assert self._page is not None
        try:
            resp = await self._page.goto(url, wait_until=wait_until, timeout=timeout_ms)
            status = resp.status if resp else 200
        except Exception as e:
            log.warning("browser.goto_failed", url=url, error=str(e))
            status = 0
        html = await self._page.content()
        title = await self._page.title()
        cookies = await self._dump_cookies()
        return BrowserResult(url=url, title=title, html=html,
                             cookies=cookies, status=status)

    async def click(self, selector: str, timeout_ms: int = 15000) -> None:
        assert self._page is not None
        await self._page.click(selector, timeout=timeout_ms)

    async def fill(self, selector: str, value: str, timeout_ms: int = 15000) -> None:
        assert self._page is not None
        await self._page.fill(selector, value, timeout=timeout_ms)

    async def eval(self, js: str) -> Any:
        assert self._page is not None
        return await self._page.evaluate(js)

    async def wait_for_selector(self, selector: str, timeout_ms: int = 20000) -> None:
        assert self._page is not None
        await self._page.wait_for_selector(selector, timeout=timeout_ms)

    async def screenshot(self, path: str) -> None:
        assert self._page is not None
        await self._page.screenshot(path=path, full_page=True)

    async def export_cookies(self) -> dict[str, str]:
        """Public alias — used by the WAF gate to harvest challenge cookies."""
        return await self._dump_cookies()

    async def _dump_cookies(self) -> dict[str, str]:
        if self._context is None:
            return {}
        try:
            raw = await self._context.cookies()
            return {c["name"]: c["value"] for c in raw}
        except Exception:
            return {}

    async def import_cookies(self, cookies: dict[str, str], domain: str = ".swiggy.com") -> None:
        if self._context is None:
            return
        items = [
            {"name": k, "value": v, "domain": domain, "path": "/"}
            for k, v in cookies.items()
        ]
        try:
            await self._context.add_cookies(items)
        except Exception:
            log.exception("browser.cookie_import_failed")

    async def current_url(self) -> str:
        if self._page is None:
            return ""
        return self._page.url

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc):
        await self.stop()
