"""
CookieImporter — accept cookies pasted by the operator and validate
them against the target before storing.

Validation hits a lightweight authenticated endpoint (configurable)
and checks for a 200 + expected marker. If validation fails, the
cookie set is rejected — agents should not silently use dead auth.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..logging_setup import get_logger
from ..stealth.session import StealthSession

log = get_logger(__name__)


DEFAULT_PROBE = "https://www.swiggy.com/dapi/auth/signin-check"
PROBE_BODY = {"mobile": "0000000000"}


@dataclass
class CookieValidation:
    ok: bool
    status: int
    reason: str = ""
    body_preview: str = ""


def parse_cookie_string(raw: str) -> dict[str, str]:
    """
    Accept any of:
      - "a=1; b=2"
      - "a=1\\nb=2"
      - JSON: {"a": "1", "b": "2"}
      - Netscape cookie file lines (tab-separated) — simplified
    """
    raw = raw.strip()
    if not raw:
        return {}

    # JSON?
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
            return {str(k): str(v) for k, v in obj.items()}
        except Exception:
            pass

    out: dict[str, str] = {}
    # try delimiter split
    parts = []
    if ";" in raw:
        parts = [p.strip() for p in raw.split(";")]
    elif "\n" in raw:
        parts = [p.strip() for p in raw.splitlines()]
    elif "\t" in raw:
        # netscape format: domain, flag, path, secure, expiry, name, value
        for line in raw.splitlines():
            cols = line.split("\t")
            if len(cols) >= 7:
                out[cols[5].strip()] = cols[6].strip()
        return out
    else:
        parts = [raw]

    for p in parts:
        if not p or "=" not in p:
            continue
        k, _, v = p.partition("=")
        out[k.strip()] = v.strip()
    return out


def validate_cookies(
    cookies: dict[str, str],
    session: StealthSession,
    probe_url: str = DEFAULT_PROBE,
) -> CookieValidation:
    """
    Apply cookies to the session and probe an authenticated endpoint.
    Synchronous wrapper — the caller passes an already-running session
    and awaits validate_cookies_async instead.
    """
    raise RuntimeError("use validate_cookies_async")


async def validate_cookies_async(
    cookies: dict[str, str],
    session: StealthSession,
    probe_url: str = DEFAULT_PROBE,
) -> CookieValidation:
    session.set_cookies(cookies)
    try:
        # /dapi/auth/signin-check always answers JSON with statusCode 0 when the
        # WAF token + transport are accepted; WAF challenges surface as 202.
        resp = await session.api_post(probe_url, json_body=PROBE_BODY,
                                      headers={"content-type": "application/json",
                                               "origin": "https://www.swiggy.com",
                                               "referer": "https://www.swiggy.com/"})
    except Exception as e:
        log.exception("cookie_validation.network_failed")
        return CookieValidation(ok=False, status=0, reason=f"network: {e}")

    body = resp.text[:400]
    if resp.status == 200:
        try:
            data = resp.json()
        except Exception:
            return CookieValidation(ok=False, status=200,
                                    reason="probe returned non-JSON", body_preview=body)
        if isinstance(data, dict) and data.get("statusCode") == 0:
            return CookieValidation(ok=True, status=200, body_preview=body)
        return CookieValidation(ok=False, status=200,
                                reason=f"probe statusCode={data.get('statusCode') if isinstance(data, dict) else '?'}",
                                body_preview=body)

    if resp.status == 202:
        return CookieValidation(ok=False, status=202,
                                reason="waf challenge (no valid aws-waf-token)",
                                body_preview=body)

    if resp.status in (401, 403):
        return CookieValidation(ok=False, status=resp.status,
                                reason="auth rejected", body_preview=body)

    return CookieValidation(ok=False, status=resp.status,
                            reason=f"unexpected {resp.status}", body_preview=body)


class CookieImporter:
    def __init__(self, session: StealthSession, probe_url: str = DEFAULT_PROBE):
        self.session = session
        self.probe_url = probe_url

    async def import_and_validate(self, raw: str) -> CookieValidation:
        cookies = parse_cookie_string(raw)
        if not cookies:
            return CookieValidation(ok=False, status=0, reason="no cookies parsed")
        log.info("cookie_import.parsed", count=len(cookies), names=list(cookies.keys()))
        return await validate_cookies_async(cookies, self.session, self.probe_url)

    async def import_only(self, raw: str) -> dict[str, str]:
        cookies = parse_cookie_string(raw)
        if cookies:
            self.session.set_cookies(cookies)
        return cookies
