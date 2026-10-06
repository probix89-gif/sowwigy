"""
AuthManager — ties OTP + cookies + vault + StealthSession together.

Responsibilities:
  - own the primary StealthSession used for authenticated traffic
  - expose login_otp_send / login_otp_verify / login_cookie
  - persist sessions to the vault after success
  - restore session on boot if a valid one exists
  - check_auth() probes the target and reports state
  - rotate / logout

Design note: AuthManager is a *singleton per runtime*. Agents ask it
for the current session; they don't each maintain their own identity.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ..config import AppConfig
from ..logging_setup import get_logger
from ..state.schemas import SessionInfo
from ..stealth.fingerprint import FingerprintPool
from ..stealth.session import StealthSession
from ..stealth.waf import WafGate
from .cookies import CookieImporter, validate_cookies_async
from .otp import OtpFlow, OtpFlowError
from .vault import SessionVault

log = get_logger(__name__)


DEFAULT_PROBE = "https://www.swiggy.com/dapi/auth/signin-check"


@dataclass
class AuthResult:
    ok: bool
    message: str
    status: int = 0
    cookies_count: int = 0
    phone: str | None = None
    extra: dict[str, Any] | None = None


class AuthManager:
    def __init__(
        self,
        cfg: AppConfig,
        pool: FingerprintPool,
        session: StealthSession | None = None,
    ):
        self.cfg = cfg
        self.pool = pool
        self.session = session or StealthSession(
            pool=pool,
            timing_cfg=cfg.stealth.human_timing,
            name="primary",
            referer_chain=cfg.stealth.referer_chain,
            profile=cfg.stealth.tls_profile,
            tls_enabled=cfg.stealth.tls_enabled,
            allow_fallback=cfg.stealth.tls_fallback_allowed,
        )
        self.vault = SessionVault(
            data_dir=cfg.paths.data_dir,
            key=(cfg.secrets.swiggy_session_vault_key
                 if cfg.secrets and cfg.secrets.swiggy_session_vault_key else None),
        )
        # AWS-WAF gate: lazily solves the challenge in headless Chromium when a
        # 202 challenge is seen, then injects aws-waf-token cookies into the session.
        waf_cfg = getattr(cfg, "browser", None)
        self.waf = WafGate(self.session.fp, waf_cfg)
        self.session.attach_waf(self.waf)
        self.otp = OtpFlow(cfg.auth.otp, self.session)
        self.importer = CookieImporter(self.session, probe_url=DEFAULT_PROBE)
        self._current: SessionInfo | None = None

    # ------------------------------------------------------------------
    # restore on boot
    # ------------------------------------------------------------------

    async def restore(self, name: str = "primary") -> AuthResult:
        s = self.vault.load(name)
        if s is None:
            return AuthResult(ok=False, message="no stored session")
        if s.expires_at and s.expires_at < time.time():
            return AuthResult(ok=False, message="stored session expired")
        # apply
        self.session.set_cookies(s.cookies)
        self.session.fp = self.pool.by_id(s.fingerprint_id or "") or self.session.fp
        v = await validate_cookies_async(s.cookies, self.session, DEFAULT_PROBE)
        if v.ok:
            self._current = s
            log.info("auth.restored", name=name, cookies=len(s.cookies))
            return AuthResult(ok=True, message="restored",
                              status=v.status, cookies_count=len(s.cookies),
                              phone=s.phone)
        # stale
        self.vault.delete(name)
        return AuthResult(ok=False, message=f"stored session invalid: {v.reason}",
                          status=v.status)

    # ------------------------------------------------------------------
    # OTP login
    # ------------------------------------------------------------------

    async def login_otp_send(self, phone: str) -> AuthResult:
        try:
            body = await self.otp.send(phone)
            return AuthResult(
                ok=True, message="OTP sent",
                status=200, phone=phone,
                extra={"provider_response": body},
            )
        except OtpFlowError as e:
            return AuthResult(ok=False, message=str(e))

    async def login_otp_verify(self, otp: str) -> AuthResult:
        try:
            result = await self.otp.verify(otp)
        except OtpFlowError as e:
            return AuthResult(ok=False, message=str(e))

        cookies = result.get("cookies") or {}
        v = await validate_cookies_async(cookies, self.session, DEFAULT_PROBE)
        if not v.ok:
            return AuthResult(
                ok=False,
                message=f"login returned cookies but probe failed: {v.reason}",
                status=v.status,
                cookies_count=len(cookies),
            )

        info = SessionInfo(
            name="primary",
            phone=result.get("phone"),
            cookies=cookies,
            headers={},
            fingerprint_id=self.session.fp.id,
            expires_at=time.time() + 30 * 24 * 3600,  # 30d
        )
        self.vault.save(info)
        self._current = info
        return AuthResult(
            ok=True, message="logged in",
            status=v.status, cookies_count=len(cookies),
            phone=info.phone,
        )

    # ------------------------------------------------------------------
    # cookie login
    # ------------------------------------------------------------------

    async def login_cookie(self, raw: str, name: str = "primary") -> AuthResult:
        v = await self.importer.import_and_validate(raw)
        if not v.ok:
            return AuthResult(ok=False, message=f"cookie invalid: {v.reason}",
                              status=v.status)
        cookies = self.session.cookies()
        info = SessionInfo(
            name=name,
            phone=None,
            cookies=cookies,
            headers={},
            fingerprint_id=self.session.fp.id,
            expires_at=time.time() + 30 * 24 * 3600,
        )
        self.vault.save(info)
        self._current = info
        return AuthResult(ok=True, message="cookies imported",
                          status=v.status, cookies_count=len(cookies))

    # ------------------------------------------------------------------
    # state
    # ------------------------------------------------------------------

    async def check_auth(self) -> AuthResult:
        cookies = self.session.cookies()
        if not cookies:
            return AuthResult(ok=False, message="no cookies in session")
        v = await validate_cookies_async(cookies, self.session, DEFAULT_PROBE)
        return AuthResult(
            ok=v.ok,
            message="authenticated" if v.ok else v.reason,
            status=v.status,
            cookies_count=len(cookies),
            phone=(self._current.phone if self._current else None),
        )

    def current(self) -> SessionInfo | None:
        return self._current

    def otp_status(self) -> dict[str, Any]:
        return self.otp.status()

    def status(self) -> dict[str, Any]:
        cur = self._current
        return {
            "authenticated": cur is not None,
            "phone": cur.phone if cur else None,
            "cookies": len(self.session.cookies()),
            "fingerprint": self.session.fp.id,
            "session_name": self.session.name,
            "otp": self.otp.status(),
            "vault_sessions": self.vault.list_names(),
            "stealth": self.session.snapshot(),
        }

    async def rotate_session(self) -> AuthResult:
        await self.session.rotate()
        return AuthResult(ok=True, message="session rotated",
                          cookies_count=len(self.session.cookies()))

    def logout(self) -> AuthResult:
        self.session.set_cookies({})  # nukes auth cookies
        if self._current:
            self.vault.delete(self._current.name)
            self._current = None
        return AuthResult(ok=True, message="logged out")

    async def shutdown(self) -> None:
        await self.session.close()
