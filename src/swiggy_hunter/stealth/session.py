"""
StealthSession — one identity, one fingerprint, one cookie jar, one TLS profile.

Every outbound HTTP call goes through:
    Behavior.pre_request(url)            # human delay + cool-down
    HeaderBuilder.build(fp, ctx)         # coherent headers
    underlying session.request(...)      # curl_cffi or httpx configured via TLSProfile
    Behavior.post_response(status)       # 403/429 handling
    referer chain updated

On rotate_requested, the session transparently swaps its fingerprint, adapts
its TLSProfile, and clears the cookie jar (except auth-critical ones).
This is what lets long-running agents survive blocks without resetting the whole run.

Public API mirrors requests/aiohttp closely enough that callers don't
care which engine is underneath.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from ..logging_setup import get_logger
from .behavior import Behavior
from .fingerprint import (
    Fingerprint,
    FingerprintPool,
    build_default_pool,
    get_profile,
    get_profile_for_fingerprint,
)
from .headers import HeaderBuilder, RequestContext, RequestKind
from .timing import TimingModel
from .tls import (
    TLSConnectionError,
    TLSProfile,
    TLSVerificationError,
    create_client,
    engine_name,
    sanitize_url,
)
from .waf import is_waf_challenge

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
    profile_name: str = ""
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
                "tls_profile": self.profile_name,
                "engine": self.engine,
            },
        }


class StealthSession:
    """
    HTTP session maintaining a single browser identity, coherent TLS ClientHello profile,
    and request lifecycle.
    """

    def __init__(
        self,
        pool: FingerprintPool | None = None,
        timing_cfg: Any = None,
        *,
        name: str = "default",
        referer_chain: bool = True,
        cookies: dict[str, str] | None = None,
        initial_url: str | None = None,
        profile: TLSProfile | str | None = None,
        tls_enabled: bool = True,
        allow_fallback: bool = False,
        proxy: str | None = None,
    ):
        self.name = name
        self.pool = pool if pool is not None else FingerprintPool(build_default_pool())
        self.fp: Fingerprint = self.pool.draw()
        if timing_cfg is None:
            from ..config import HumanTimingCfg
            timing_cfg = HumanTimingCfg(enabled=False)
        self.timing = TimingModel(timing_cfg)
        self.behavior = Behavior(self.timing)
        self.headers = HeaderBuilder(referer_chain=referer_chain)
        self.proxy = proxy
        self.tls_enabled = tls_enabled
        self.allow_fallback = allow_fallback

        # Resolve TLS profile deterministically via profile manager
        if not tls_enabled:
            self.profile: TLSProfile = get_profile("disabled")
        elif isinstance(profile, TLSProfile):
            self.profile = profile
        elif isinstance(profile, str):
            self.profile = get_profile(profile)
        else:
            self.profile = get_profile_for_fingerprint(self.fp)

        self.engine = engine_name()
        # Session creation consumes the selected TLS profile
        self._session = create_client(
            profile=self.profile,
            proxy=self.proxy,
            allow_fallback=self.allow_fallback,
        )
        self._cookies: dict[str, str] = dict(cookies or {})
        self._lock = None  # not strictly needed; caller should serialize
        self._created_at = time.time()
        self._request_count = 0
        self._initial_url = initial_url
        # AWS-WAF gate (lazy solver; only used when a 202 challenge is seen)
        self.waf = None  # type: ignore[assignment]  # set via attach_waf()

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        try:
            await self._session.close()
        except Exception:
            pass
        if getattr(self, "waf", None):
            try:
                await self.waf.close()
            except Exception:
                pass

    def attach_waf(self, waf_gate: Any) -> None:
        """Attach a WafGate so 202 challenges auto-solve and the request retries."""
        self.waf = waf_gate

    async def rotate(self) -> None:
        """Swap fingerprint + adapt TLS profile + reset engine. Keeps auth cookies."""
        log.info(
            "stealth.rotate",
            name=self.name,
            old_fp=self.fp.id,
            old_profile=self.profile.name,
        )
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

        # Adapt TLS profile to match new fingerprint
        if self.tls_enabled:
            self.profile = get_profile_for_fingerprint(self.fp)
        else:
            self.profile = get_profile("disabled")

        self._session = create_client(
            profile=self.profile,
            proxy=self.proxy,
            allow_fallback=self.allow_fallback,
        )
        self.headers = HeaderBuilder(referer_chain=True)
        # keep auth cookies; drop the rest
        auth_keys = {"_session", "session", "swiggy_session", "access_token", "t_id", "sid"}
        self._cookies = {k: v for k, v in self._cookies.items() if k in auth_keys}
        log.info(
            "stealth.rotated",
            name=self.name,
            new_fp=self.fp.id,
            new_profile=self.profile.name,
        )

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
        """Parse Set-Cookie headers from any HTTP client's response.

        Handles:
          - curl_cffi Headers (multi_items / getlist)
          - aiohttp CIMultiDict (getall)
          - WAF-retry path where headers are already a plain dict
        """
        raw_list: list[str] = []
        # curl_cffi Headers — multi_items preserves every duplicate header
        if hasattr(headers, "multi_items"):
            try:
                raw_list = [v for k, v in headers.multi_items()
                            if str(k).lower() == "set-cookie"]
            except Exception:
                raw_list = []
        # aiohttp-style getall
        if not raw_list and hasattr(headers, "getall"):
            try:
                raw_list = list(headers.getall("set-cookie") or [])
            except Exception:
                raw_list = []
        # curl_cffi also exposes getlist
        if not raw_list and hasattr(headers, "getlist"):
            try:
                raw_list = list(headers.getlist("set-cookie") or [])
            except Exception:
                raw_list = []
        if not raw_list:
            sc = None
            try:
                sc = headers.get("set-cookie") or headers.get("Set-Cookie")
            except Exception:
                sc = None
            raw_list = [sc] if sc else []
        for raw in raw_list:
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

        # 3. send with safe diagnostic observability
        started = time.monotonic()
        safe_target_url = sanitize_url(full_url)
        log.debug(
            "stealth.request_sent",
            method=method.upper(),
            url=safe_target_url,
            profile=self.profile.name,
            http_version=self.profile.http_version,
        )

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
            # capture the RAW headers object BEFORE dict conversion —
            # dict(headers) keeps only the first Set-Cookie and silently
            # drops the rest (Swiggy sets ~10 cookies incl. the session tid)
            raw_headers = getattr(resp, "headers", None)
        except Exception as e:
            elapsed = int((time.monotonic() - started) * 1000)
            self.behavior.post_response(0)
            err_lower = str(e).lower()
            log.warning(
                "stealth.request_failed",
                url=safe_target_url,
                profile=self.profile.name,
                elapsed_ms=elapsed,
                error=str(e),
            )
            # Map low-level network/TLS errors cleanly
            if any(term in err_lower for term in (
                "peer_failed_verification", "certificate verify failed", "cert", "ssl_error_bad_cert_domain"
            )):
                raise TLSVerificationError(f"TLS certificate verification failed for {safe_target_url}: {e}") from e
            elif any(term in err_lower for term in (
                "couldn't connect", "connection refused", "connecterror", "handshake failure", "tlsv1_alert"
            )):
                raise TLSConnectionError(f"Connection or TLS handshake failed for {safe_target_url}: {e}") from e
            raise

        # 4. normalize response
        elapsed = int((time.monotonic() - started) * 1000)
        status: int = int(getattr(resp, "status_code", 0) or getattr(resp, "status", 0) or 0)
        resp_headers = dict(getattr(resp, "headers", {}) or {})
        body = getattr(resp, "content", None)
        if body is None:
            body = getattr(resp, "text", "").encode("utf-8", errors="replace")

        log.debug(
            "stealth.request_done",
            method=method.upper(),
            url=safe_target_url,
            status=status,
            profile=self.profile.name,
            elapsed_ms=elapsed,
        )

        # 5. AWS-WAF challenge handling: solve once via headless browser, then retry
        if (
            getattr(self, "waf", None) is not None
            and status == 202
            and is_waf_challenge(status, body)
        ):
            log.info("stealth.waf_challenge", url=safe_target_url)
            solved = await self.waf.solve()
            if solved:
                await self.waf.apply(self)
                # single retry of the same request
                resp = await self._session.request(
                    method=method.upper(),
                    url=full_url,
                    headers=req_headers,
                    json=json_body if json_body is not None else None,
                    data=data if data is not None else None,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                )
                status = int(getattr(resp, "status_code", 0) or getattr(resp, "status", 0) or 0)
                raw_headers = getattr(resp, "headers", None)
                resp_headers = dict(getattr(resp, "headers", {}) or {})
                body = getattr(resp, "content", None)
                if body is None:
                    body = getattr(resp, "text", "").encode("utf-8", errors="replace")

        # 6. behavior post-response
        retry_after = None
        try:
            ra = resp_headers.get("retry-after") or resp_headers.get("Retry-After")
            if ra:
                retry_after = int(ra)
                log.info("stealth.retry_after_received", retry_after_s=retry_after)
        except Exception:
            pass
        self.behavior.post_response(status, retry_after=retry_after)

        # 6. absorb cookies + referer chain
        self._absorb_set_cookie(raw_headers if raw_headers is not None else resp_headers)
        if 200 <= status < 400:
            self.headers.remember(full_url)

        # 7. auto-rotate if behavior says so
        if self.behavior.should_rotate():
            log.warning("stealth.auto_rotate", name=self.name, profile=self.profile.name)
            await self.rotate()

        self._request_count += 1

        return StealthResponse(
            status=status,
            headers=resp_headers,
            body=body,
            url=full_url,
            elapsed_ms=elapsed,
            fingerprint_id=self.fp.id,
            profile_name=self.profile.name,
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
            "tls_profile": self.profile.name,
            "tls_enabled": self.profile.enabled,
            "http_version": self.profile.http_version,
            "engine": self.engine,
            "requests": self._request_count,
            "age_s": round(time.time() - self._created_at, 1),
            "cookies": list(self._cookies.keys()),
            "behavior": self.behavior.snapshot(),
        }


def create_session(
    profile: TLSProfile | str | None = None,
    pool: FingerprintPool | None = None,
    timing_cfg: Any = None,
    **kwargs: Any,
) -> StealthSession:
    """
    Factory helper to construct a StealthSession consuming a given TLSProfile or profile name.
    """
    return StealthSession(
        pool=pool,
        timing_cfg=timing_cfg,
        profile=profile,
        **kwargs,
    )
