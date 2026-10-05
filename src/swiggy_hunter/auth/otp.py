"""
OtpFlow — Swiggy's OTP login, split into two operator-driven steps.

Step 1 (send):  POST to send_endpoint with the phone number.
Step 2 (verify): POST to verify_endpoint with phone + OTP.

The flow is *interactive*: the operator reads the OTP from their phone
and sends it back via telegram (`/otp 123456`). The AuthManager holds
an OtpFlow instance during the pending window (default 5 min).

Everything goes through StealthSession so it looks like real browser
traffic.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from ..config import OtpAuthCfg
from ..logging_setup import get_logger
from ..stealth.session import StealthSession

log = get_logger(__name__)


class OtpFlowError(Exception):
    pass


@dataclass
class PendingOtp:
    phone: str
    sent_at: float
    attempts: int = 0
    last_error: str | None = None
    send_response: dict[str, Any] = field(default_factory=dict)


class OtpFlow:
    def __init__(self, cfg: OtpAuthCfg, session: StealthSession):
        self.cfg = cfg
        self.session = session
        self.pending: PendingOtp | None = None

    # ------------------------------------------------------------------
    # step 1 — send
    # ------------------------------------------------------------------

    async def send(self, phone: str) -> dict[str, Any]:
        if self.pending and (time.time() - self.pending.sent_at) < self.cfg.resend_cooldown_s:
            remaining = int(self.cfg.resend_cooldown_s - (time.time() - self.pending.sent_at))
            raise OtpFlowError(f"resend cooldown: {remaining}s remaining")

        payload = {self.cfg.phone_field: phone}
        resp = await self.session.api_post(
            self.cfg.send_endpoint,
            json_body=payload,
            headers={
                "content-type": "application/json",
                "origin": _origin_of(self.cfg.send_endpoint),
                "referer": _referer_of(self.cfg.send_endpoint),
            },
        )

        try:
            body = resp.json() if resp.body else {}
        except Exception:
            body = {"raw": resp.text[:400]}

        if resp.status >= 400:
            raise OtpFlowError(f"send failed: {resp.status} {str(body)[:200]}")

        self.pending = PendingOtp(phone=phone, sent_at=time.time(), send_response=body)
        log.info("otp.sent", phone=_mask(phone), status=resp.status)
        return body

    # ------------------------------------------------------------------
    # step 2 — verify
    # ------------------------------------------------------------------

    async def verify(self, otp: str) -> dict[str, Any]:
        if self.pending is None:
            raise OtpFlowError("no pending OTP — call /login first")

        if time.time() - self.pending.sent_at > 600:  # 10 min hard TTL
            self.pending = None
            raise OtpFlowError("OTP expired — resend")

        payload = {
            self.cfg.phone_field: self.pending.phone,
            self.cfg.otp_field: otp,
        }
        resp = await self.session.api_post(
            self.cfg.verify_endpoint,
            json_body=payload,
            headers={
                "content-type": "application/json",
                "origin": _origin_of(self.cfg.verify_endpoint),
                "referer": _referer_of(self.cfg.verify_endpoint),
            },
        )
        try:
            body = resp.json() if resp.body else {}
        except Exception:
            body = {"raw": resp.text[:400]}

        self.pending.attempts += 1

        if resp.status >= 400:
            self.pending.last_error = f"{resp.status}: {str(body)[:200]}"
            raise OtpFlowError(f"verify failed: {self.pending.last_error}")

        cookies = self.session.cookies()
        if not cookies:
            log.warning("otp.verify_no_cookies")

        log.info("otp.verified", phone=_mask(self.pending.phone), cookies=len(cookies))
        result = {
            "body": body,
            "cookies": cookies,
            "status": resp.status,
            "phone": self.pending.phone,
        }
        self.pending = None
        return result

    # ------------------------------------------------------------------
    # state
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        if not self.pending:
            return {"pending": False}
        return {
            "pending": True,
            "phone": _mask(self.pending.phone),
            "age_s": round(time.time() - self.pending.sent_at, 1),
            "attempts": self.pending.attempts,
            "last_error": self.pending.last_error,
        }

    def clear(self) -> None:
        self.pending = None


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

def _origin_of(url: str) -> str:
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _referer_of(url: str) -> str:
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}/"


def _mask(phone: str) -> str:
    if len(phone) <= 4:
        return "***"
    return phone[:2] + "***" + phone[-2:]
