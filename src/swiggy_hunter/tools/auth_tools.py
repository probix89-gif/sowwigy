"""
Auth tools — expose AuthManager to the agents.

  - auth_status: current authentication state
  - auth_login_otp: send an OTP to a phone (starts the flow)
  - auth_login_cookie: import cookies from a raw string
  - auth_refresh_session: validate current session
  - session_rotate: swap fingerprint + drop non-auth cookies
  - auth_logout: nuke cookies + vault entry
"""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolResult


class AuthStatusTool(Tool):
    name = "auth_status"
    description = "Report the current authentication state (cookies, phone, fingerprint)."
    parameters = {"type": "object", "properties": {}}

    def __init__(self, auth_manager):
        self.auth = auth_manager

    async def run(self, **kwargs: Any) -> ToolResult:
        import json
        return ToolResult(ok=True, output=json.dumps(self.auth.status(), indent=2),
                          meta=self.auth.status())


class AuthLoginOtpTool(Tool):
    name = "auth_login_otp"
    description = (
        "Start OTP login for the given phone number. This sends the OTP. "
        "The operator then provides the code via telegram (/otp). Agents "
        "should not use this unless explicitly asked."
    )
    parameters = {
        "type": "object",
        "properties": {"phone": {"type": "string"}},
        "required": ["phone"],
    }

    def __init__(self, auth_manager):
        self.auth = auth_manager

    async def run(self, **kwargs: Any) -> ToolResult:
        phone = kwargs.get("phone", "")
        if not phone:
            return ToolResult(ok=False, output="", error="missing phone")
        result = await self.auth.login_otp_send(phone)
        return ToolResult(ok=result.ok, output=result.message,
                          error=None if result.ok else result.message,
                          meta={"phone": phone})


class AuthLoginCookieTool(Tool):
    name = "auth_login_cookie"
    description = (
        "Import cookies for an authenticated session. Accepts 'a=1; b=2', "
        "JSON, or Netscape-format lines. Validates before accepting."
    )
    parameters = {
        "type": "object",
        "properties": {"raw": {"type": "string"}},
        "required": ["raw"],
    }

    def __init__(self, auth_manager):
        self.auth = auth_manager

    async def run(self, **kwargs: Any) -> ToolResult:
        raw = kwargs.get("raw", "")
        if not raw:
            return ToolResult(ok=False, output="", error="no cookie string")
        result = await self.auth.login_cookie(raw)
        return ToolResult(ok=result.ok, output=result.message,
                          error=None if result.ok else result.message)


class AuthRefreshTool(Tool):
    name = "auth_refresh_session"
    description = "Probe the target to confirm the current session is still valid."
    parameters = {"type": "object", "properties": {}}

    def __init__(self, auth_manager):
        self.auth = auth_manager

    async def run(self, **kwargs: Any) -> ToolResult:
        result = await self.auth.check_auth()
        return ToolResult(ok=result.ok, output=result.message,
                          error=None if result.ok else result.message)


class SessionRotateTool(Tool):
    name = "session_rotate"
    description = (
        "Rotate the browser fingerprint and drop non-auth cookies. Use "
        "after consecutive 403/429 or when behavior flags a block."
    )
    parameters = {"type": "object", "properties": {}}

    def __init__(self, auth_manager):
        self.auth = auth_manager

    async def run(self, **kwargs: Any) -> ToolResult:
        result = await self.auth.rotate_session()
        return ToolResult(ok=result.ok, output=result.message)


class AuthLogoutTool(Tool):
    name = "auth_logout"
    description = "Clear cookies and delete the stored session from the vault."
    parameters = {"type": "object", "properties": {}}

    def __init__(self, auth_manager):
        self.auth = auth_manager

    async def run(self, **kwargs: Any) -> ToolResult:
        result = self.auth.logout()
        return ToolResult(ok=result.ok, output=result.message)
