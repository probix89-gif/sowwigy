"""
StealthSession — one identity, one fingerprint, one cookie jar.

Every outbound HTTP call goes through:
    Behavior.pre_request(url)            # human delay + cool-down
    HeaderBuilder.build(fp, ctx)         # coherent headers
    underlying session.request(...)      # curl_cffi or httpx
    Behavior.post_response(status)       # 403/429 handling
    referer chain updated

On rotate_requested, the session transparently swaps its fingerprint
and clears the cookie jar (except auth-critical ones). This is what
lets long-running agents survive blocks without resetting the whole
run.

Public API mirrors requests/aiohttp closely enough that callers don't
care which engine is underneath.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..logging_setup import get_logger
from .behavior import Behavior
from .fingerprint import Fingerprint, FingerprintPool
from .headers import HeaderBuilder, RequestContext, RequestKind
from .timing import TimingModel
from .tls import engine_name, make_curl_session

log = get_logger(__name__)


@dataclass
class StealthResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str
    elapsed_ms: int
    fingerprint_id: str
    engine: str
    redirect_history: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.body)

    def to_capture(self, method: str, request_headers: dict[str, str],
                   request_body: str | None) -> dict[str, Any]:
        return {
            "request": {
                "method": method,
                "url": self.url,
                "headers": request_headers,
                "body": request_body,
            },
            "response": {
                "status": self.status,
                "headers": self.headers,
                "body": self.text[:200_000],
                "elapsed_ms": self.elapsed_ms,
            },
            "stealth": {
                "fingerprint": self.fingerprint_id,
                "engine": self.engine,
            },
        }


class StealthSession:
    def __init__(
        self,
        pool: FingerprintPool,
        timing_cfg,
        *,
        name: str = "default",
        referer_chain: bool = True,
        cookies: dict[str, str] | None = None,
        initial_url: str | None = None,
    ):
        self.name = name
        self.pool = pool
        self.fp: Fingerprint = pool.draw()
        self.timing = TimingModel(timing_cfg)
        self.behavior = Behavior(self.timing)
        self.headers = HeaderBuilder(referer_chain=referer_chain)
        self.engine = engine_name()
        self._session = make_curl_session(impersonate=self.fp.tls_impersonate)
        self._cookies: dict[str, str] = dict(cookies or {})
        self._lock = None  # not strictly needed; caller should serialize
        self._created_at = time.time()
        self._request_count = 0
        self._initial_url = initial_url

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        try:
            await self._session.close()
        except Exception:
            pass

    async def rotate(self) -> None:
        """Swap fingerprint + reset engine. Keeps auth cookies."""
        log.info("stealth.rotate", name=self.name, old_fp=self.fp.id)
        old = self.fp
        try:
            await self._session.close()
        except Exception:
            pass
        # draw a different fingerprint
        for _ in range(6):
            fp = self.pool.draw()
            if fp.id != old.id:
                self.fp = fp
                break
        self._session = make_curl_session(impersonate=self.fp.tls_impersonate)
        self.headers = HeaderBuilder(referer_chain=True)
        # keep auth cookies; drop the rest
        auth_keys = {"_session", "session", "swiggy_session", "access_token", "t_id", "sid"}
        self._cookies = {k: v for k, v in self._cookies.items() if k in auth_keys}
        log.info("stealth.rotated", name=self.name, new_fp=self.fp.id)

    # ------------------------------------------------------------------
    # cookies
    # ------------------------------------------------------------------

    def set_cookie(self, name: str, value: str) -> None:
        self._cookies[name] = value

    def set_cookies(self, cookies: dict[str, str]) -> None:
        self._cookies.update(cookies)

    def cookies(self) -> dict[str, str]:
        return dict(self._cookies)

    def _absorb_set_cookie(self, headers: dict[str, str] | Any) -> None:
        """Parse Set-Cookie headers from any HTTP client's response."""
        try:
            raw_list = headers.getall("set-cookie") if hasattr(headers, "getall") else None
        except Exception:
            raw_list = None
        if raw_list is None:
            sc = headers.get("set-cookie") or headers.get("Set-Cookie")
            raw_list = [sc] if sc else []
        for raw in raw_list or []:
            if not raw:
                continue
            first = raw.split(";")[0].strip()
            if "=" not in first:
                continue
            k, _, v = first.partition("=")
            self._cookies[k.strip()] = v.strip()

    # ------------------------------------------------------------------
    # request
    # ------------------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        data: Any = None,
        timeout: float = 45.0,
        kind: RequestKind = "xhr",
        allow_redirects: bool = True,
    ) -> StealthResponse:
        # 1. behavior pre-request
        await self.behavior.pre_request(url)

        # 2. build headers
        full_url = url
        if params:
            from urllib.parse import urlencode
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{urlencode(params)}"

        ctx = RequestContext(
            url=full_url,
            kind=kind,
            method=method,
            extra=headers or {},
        )
        req_headers = self.headers.build(self.fp, ctx)
        # inject cookies
        if self._cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            req_headers["cookie"] = cookie_str

        body_repr: str | None = None
        if json_body is not None:
            body_repr = json.dumps(json_body)[:4000]
        elif data is not None:
            body_repr = str(data)[:4000]

        # 3. send
        started = time.monotonic()
        try:
            resp = await self._session.request(
                method=method.upper(),
                url=full_url,
                headers=req_headers,
                json=json_body if json_body is not None else None,
                data=data if data is not None else None,
                timeout=timeout,
                allow_redirects=allow_redirects,
            )
        except Exception as e:
            # network-level failure: let caller handle
            elapsed = int((time.monotonic() - started) * 1000)
            self.behavior.post_response(0)
            log.warning("stealth.request_failed", url=full_url, error=str(e))
            raise

        # 4. normalize response
        status: int = int(getattr(resp, "status_code", 0) or getattr(resp, "status", 0) or 0)
        resp_headers = dict(getattr(resp, "headers", {}) or {})
        body = getattr(resp, "content", None)
        if body is None:
            body = getattr(resp, "text", "").encode("utf-8", errors="replace")
        elapsed = int((time.monotonic() - started) * 1000)

        # 5. behavior post-response
        retry_after = None
        try:
            ra = resp_headers.get("retry-after") or resp_headers.get("Retry-After")
            if ra:
                retry_after = int(ra)
        except Exception:
            pass
        self.behavior.post_response(status, retry_after=retry_after)

        # 6. absorb cookies + referer chain
        self._absorb_set_cookie(resp_headers)
        if 200 <= status < 400:
            self.headers.remember(full_url)

        # 7. auto-rotate if behavior says so
        if self.behavior.should_rotate():
            log.warning("stealth.auto_rotate", name=self.name)
            await self.rotate()

        self._request_count += 1

        return StealthResponse(
            status=status,
            headers=resp_headers,
            body=body,
            url=full_url,
            elapsed_ms=elapsed,
            fingerprint_id=self.fp.id,
            engine=self.engine,
        )

    # ------------------------------------------------------------------
    # convenience
    # ------------------------------------------------------------------

    async def get(self, url: str, **kw) -> StealthResponse:
        return await self.request("GET", url, kind=kw.pop("kind", "navigate"), **kw)

    async def post(self, url: str, **kw) -> StealthResponse:
        return await self.request("POST", url, kind=kw.pop("kind", "form"), **kw)

    async def api_get(self, url: str, **kw) -> StealthResponse:
        return await self.request("GET", url, kind="xhr", **kw)

    async def api_post(self, url: str, **kw) -> StealthResponse:
        return await self.request("POST", url, kind="xhr", **kw)

    # ------------------------------------------------------------------
    # info
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "fingerprint": self.fp.id,
            "engine": self.engine,
            "requests": self._request_count,
            "age_s": round(time.time() - self._created_at, 1),
            "cookies": list(self._cookies.keys()),
            "behavior": self.behavior.snapshot(),
        }
