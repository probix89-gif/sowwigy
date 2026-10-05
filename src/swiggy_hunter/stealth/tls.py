"""
curl_cffi session factory.

curl_cffi gives us real Chrome/Firefox TLS + HTTP/2 fingerprints, which
is the single biggest anti-bot signal after headers. We build one
session per StealthSession and reuse it.

If curl_cffi isn't installed, we fall back to httpx with HTTP/2 — less
stealthy but still usable.
"""
from __future__ import annotations

from typing import Any

from ..logging_setup import get_logger

log = get_logger(__name__)


def _try_curl_cffi() -> Any | None:
    try:
        from curl_cffi.requests import AsyncSession  # type: ignore
        return AsyncSession
    except Exception:
        return None


def _try_httpx() -> Any | None:
    try:
        import httpx  # type: ignore
        return httpx.AsyncClient
    except Exception:
        return None


def make_curl_session(impersonate: str = "chrome124", timeout: float = 45.0) -> Any:
    """
    Return an async HTTP session:
      - curl_cffi AsyncSession (preferred, TLS-impersonating)
      - else httpx.AsyncClient (fallback, http2 enabled)

    The returned object exposes:
        await session.request(method, url, headers=..., data=..., json=..., timeout=...)
        await session.close()
    """
    AsyncSession = _try_curl_cffi()
    if AsyncSession is not None:
        try:
            session = AsyncSession(
                impersonate=impersonate,
                timeout=timeout,
                allow_redirects=True,
                http_version="v2",
            )
            log.info("tls.curl_cffi", impersonate=impersonate)
            return session
        except Exception:
            log.exception("tls.curl_cffi_init_failed")

    AsyncClient = _try_httpx()
    if AsyncClient is not None:
        for use_http2 in (True, False):
            try:
                session = AsyncClient(
                    timeout=timeout,
                    follow_redirects=True,
                    http2=use_http2,
                    headers={},
                )
                log.warning("tls.httpx_fallback", impersonate=impersonate, http2=use_http2)
                return session
            except Exception:
                if not use_http2:
                    log.exception("tls.httpx_init_failed")

    raise RuntimeError(
        "no HTTP client available. install curl_cffi or httpx: "
        "pip install curl-cffi httpx[http2]"
    )


def engine_name() -> str:
    if _try_curl_cffi() is not None:
        return "curl_cffi"
    if _try_httpx() is not None:
        return "httpx"
    return "none"
