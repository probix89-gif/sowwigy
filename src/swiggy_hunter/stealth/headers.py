"""
HeaderBuilder — produces coherent request headers for a given fingerprint
and request context (top-level nav, XHR, form submit, etc.).

Anti-bot checks correlate:
  - sec-fetch-* against the request type
  - referer against the flow
  - accept / accept-language against the UA's typical locale
  - origin for cross-origin requests

The builder knows the "shape" of each request kind and fills accordingly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse

from .fingerprint import Fingerprint


RequestKind = Literal[
    "navigate",       # top-level page load
    "xhr",            # API fetch from JS
    "form",           # form POST
    "asset",          # static asset
    "preflight",      # OPTIONS
    "redirect",       # followed redirect
]


@dataclass
class RequestContext:
    url: str
    kind: RequestKind = "navigate"
    referer: str | None = None
    origin: str | None = None
    method: str = "GET"
    extra: dict[str, str] = field(default_factory=dict)


class HeaderBuilder:
    def __init__(self, referer_chain: bool = True):
        self.referer_chain = referer_chain
        self._chain: dict[str, str] = {}   # host -> last url visited

    def remember(self, url: str) -> None:
        """Track last-visited URL per host so referer chains stay coherent."""
        try:
            host = urlparse(url).netloc
            self._chain[host] = url
        except Exception:
            pass

    def referer_for(self, url: str, explicit: str | None = None) -> str | None:
        if explicit:
            return explicit
        if not self.referer_chain:
            return None
        try:
            host = urlparse(url).netloc
            return self._chain.get(host)
        except Exception:
            return None

    def build(self, fp: Fingerprint, ctx: RequestContext) -> dict[str, str]:
        headers = fp.to_headers()

        # ----- method-specific defaults -----
        method = ctx.method.upper()

        # ----- request kind shaping -----
        if ctx.kind == "navigate":
            headers.update({
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "none" if not ctx.referer else "same-origin",
                "sec-fetch-user": "?1",
                "upgrade-insecure-requests": "1",
                "accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,image/apng,*/*;q=0.8,"
                    "application/signed-exchange;v=b3;q=0.7"
                ),
            })

        elif ctx.kind == "xhr":
            headers.update({
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "accept": "application/json, text/plain, */*",
                "x-requested-with": "XMLHttpRequest",
            })
            if not ctx.origin:
                origin = self._derive_origin(ctx.url)
                if origin:
                    headers["origin"] = origin

        elif ctx.kind == "form":
            headers.update({
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "same-origin",
                "accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,*/*;q=0.8"
                ),
                "content-type": "application/x-www-form-urlencoded",
            })
            if not ctx.origin:
                origin = self._derive_origin(ctx.url)
                if origin:
                    headers["origin"] = origin

        elif ctx.kind == "asset":
            headers.update({
                "sec-fetch-dest": "script" if _looks_like_js(ctx.url) else "image",
                "sec-fetch-mode": "no-cors",
                "sec-fetch-site": "same-origin",
                "accept": "*/*",
            })

        elif ctx.kind == "preflight":
            headers.update({
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "access-control-request-method": method,
                "access-control-request-headers": "content-type",
                "accept": "*/*",
            })
            if not ctx.origin:
                origin = self._derive_origin(ctx.url)
                if origin:
                    headers["origin"] = origin

        elif ctx.kind == "redirect":
            headers.update({
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "same-origin",
                "accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "*/*;q=0.8"
                ),
            })

        # ----- referer -----
        ref = self.referer_for(ctx.url, ctx.referer)
        if ref:
            headers["referer"] = ref

        # ----- method-specific: content-type only if not already set -----
        if method in ("POST", "PUT", "PATCH", "DELETE") and "content-type" not in headers:
            if ctx.kind == "xhr":
                headers["content-type"] = "application/json;charset=UTF-8"

        # ----- merge extras last (never overridden) -----
        if ctx.extra:
            headers.update(ctx.extra)

        # ----- normalize case (curl_cffi expects lowercase cURL-style) -----
        return {k.lower(): v for k, v in headers.items()}

    # ------------------------------------------------------------------

    @staticmethod
    def _derive_origin(url: str) -> str | None:
        try:
            p = urlparse(url)
            if p.scheme and p.netloc:
                return f"{p.scheme}://{p.netloc}"
        except Exception:
            pass
        return None


def _looks_like_js(url: str) -> bool:
    return url.endswith(".js") or ".js?" in url or "/js/" in url
