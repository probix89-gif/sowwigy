"""
WAF gate handling for swiggy.com /dapi/* endpoints.

Swiggy fronts its API with AWS WAF (challenge.js). Requests without a
valid `aws-waf-token` cookie receive `202` + `x-amzn-waf-action: challenge`.
The token can only be earned by executing challenge JS in a real browser.

WafGate:
  - solve(): open a headless Chromium (reusing the stealth Browser stack),
    wait for the challenge to auto-solve, export cookies
  - apply(): push those cookies into the StealthSession cookie jar
  - ensure_fresh(): called by StealthSession when a 202 WAF response is
    detected — solves once, applies cookies, retries the request

The solver is lazy: no browser is started until the first 202 is seen.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from ..logging_setup import get_logger
from .browser import Browser

log = get_logger(__name__)

WAF_HOME = "https://www.swiggy.com/restaurants"
WAF_TOKEN_COOKIE = "aws-waf-token"
_SOLVE_COOLDOWN_S = 30.0


def is_waf_challenge(status: int, body: bytes | str | None = None) -> bool:
    if status != 202:
        return False
    if body is None:
        return True
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    return "awswaf" in text or "challenge" in text.lower() or len(text.strip()) == 0


class WafGate:
    """Lazy AWS-WAF solver sharing the stealth Browser stack."""

    def __init__(self, fingerprint: Any, browser_cfg: Any):
        self._fp = fingerprint
        self._cfg = browser_cfg
        self._browser: Browser | None = None
        self._cookies: dict[str, str] = {}
        self._solved_at: float = 0.0
        self._solving: asyncio.Lock = asyncio.Lock()

    @property
    def cookies(self) -> dict[str, str]:
        return dict(self._cookies)

    @property
    def solved(self) -> bool:
        return bool(self._cookies.get(WAF_TOKEN_COOKIE))

    async def solve(self, timeout_s: float = 60.0) -> bool:
        """Solve the WAF challenge and cache the cookie set."""
        async with self._solving:
            # another task may have just solved it
            if self.solved and (time.time() - self._solved_at) < _SOLVE_COOLDOWN_S:
                return True
            log.info("waf.solve_start")
            try:
                if self._browser is None:
                    self._browser = Browser(self._fp, self._cfg)
                    await self._browser.start()
                res = await self._browser.goto(WAF_HOME, wait_until="domcontentloaded",
                                               timeout_ms=int(timeout_s * 1000))
                # challenge.js runs automatically; give it time to mint the token
                deadline = time.time() + timeout_s
                while time.time() < deadline:
                    self._cookies = await self._browser.export_cookies()
                    if self._cookies.get(WAF_TOKEN_COOKIE):
                        break
                    await asyncio.sleep(1.5)
                ok = self.solved
                self._solved_at = time.time()
                if ok:
                    log.info("waf.solved", cookies=len(self._cookies))
                else:
                    log.warning("waf.solve_timeout", waited_s=timeout_s)
                return ok
            except Exception:
                log.exception("waf.solve_failed")
                return False

    async def apply(self, session: Any) -> bool:
        """Push solved cookies into a StealthSession."""
        if not self.solved:
            return False
        session.set_cookies(self._cookies)
        return True

    async def close(self) -> None:
        if self._browser:
            await self._browser.stop()
            self._browser = None
