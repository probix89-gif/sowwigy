"""
tools/__init__.py — registry builder for V2.

Two flavors:
  - build_base_registry(): pure tools (no blackboard, no auth)
  - build_agent_registry(name, ...): base + blackboard tools bound to
    the agent name

The orchestrator builds one per agent so blackboard writes carry the
right agent identity.
"""
from __future__ import annotations

from ..state.blackboard import Blackboard
from ..state.schemas import AgentName
from .analysis_tools import DiffTool, ExtractTool, JsonPathTool
from .auth_tools import (
    AuthLoginCookieTool,
    AuthLoginOtpTool,
    AuthLogoutTool,
    AuthRefreshTool,
    AuthStatusTool,
    SessionRotateTool,
)
from .base import Tool, ToolRegistry, ToolResult
from .blackboard_tools import register_blackboard_tools
from .browser_tool import BrowserTool
from .crypto_tools import DecodeTool, EncodeTool, HashTool, JwtInspectTool
from .file_tools import FileListTool, FileReadTool, FileWriteTool
from .installer import InstallerTool
from .recon_tools import EndpointDiscoveryTool, SubdomainEnumTool, TechFingerprintTool
from .shell import ShellTool
from .stealth_http import StealthHttpTool
from .stealth_race import StealthRaceTool
from .web_tools import CookieInspectTool, HeaderAnalysisTool, ParamFuzzTool


def build_base_registry(
    *,
    shell_timeout: int = 120,
    http_timeout: int = 45,
    session_provider=None,
    scope=None,
    auth_manager=None,
    browser_provider=None,
    allowed_installers: list[str] | None = None,
) -> ToolRegistry:
    reg = ToolRegistry()

    # local machine
    shell = ShellTool(default_timeout=shell_timeout)
    reg.register(shell)
    reg.register(FileReadTool())
    reg.register(FileWriteTool())
    reg.register(FileListTool())

    if allowed_installers:
        reg.register(InstallerTool(shell=shell, allowed_installers=allowed_installers))

    # crypto / analysis
    reg.register(HashTool())
    reg.register(EncodeTool())
    reg.register(DecodeTool())
    reg.register(JwtInspectTool())
    reg.register(DiffTool())
    reg.register(ExtractTool())
    reg.register(JsonPathTool())

    # target traffic — all go through stealth
    if session_provider is not None:
        reg.register(StealthHttpTool(
            session_provider=session_provider,
            scope=scope,
        ))
        reg.register(StealthRaceTool(
            session_provider=session_provider,
            scope=scope,
        ))
        reg.register(HeaderAnalysisTool(session_provider))
        reg.register(CookieInspectTool(session_provider))
        reg.register(ParamFuzzTool(session_provider))
        reg.register(EndpointDiscoveryTool(session_provider))
        reg.register(TechFingerprintTool(session_provider))

    # recon — no session needed for subdomain enum
    reg.register(SubdomainEnumTool())

    # browser
    if browser_provider is not None:
        reg.register(BrowserTool(browser_provider=browser_provider, scope=scope))

    # auth
    if auth_manager is not None:
        reg.register(AuthStatusTool(auth_manager))
        reg.register(AuthLoginOtpTool(auth_manager))
        reg.register(AuthLoginCookieTool(auth_manager))
        reg.register(AuthRefreshTool(auth_manager))
        reg.register(SessionRotateTool(auth_manager))
        reg.register(AuthLogoutTool(auth_manager))

    return reg


def build_agent_registry(
    agent_name: AgentName,
    blackboard: Blackboard,
    **base_kwargs,
) -> ToolRegistry:
    reg = build_base_registry(**base_kwargs)
    register_blackboard_tools(reg, blackboard, agent_name)
    return reg


__all__ = [
    "Tool",
    "ToolRegistry",
    "ToolResult",
    "build_base_registry",
    "build_agent_registry",
]
