"""
Shell tool. Runs commands with a timeout, captures stdout/stderr,
blocks a short list of destructive binaries. Working directory defaults
to ./data/workspace (created on init).
"""
from __future__ import annotations

import asyncio
import os
import shlex
from pathlib import Path
from typing import Any

from .base import Tool, ToolResult


BLOCKED_BINARIES: set[str] = {
    "rm", "dd", "mkfs", "shutdown", "reboot", "halt",
    "poweroff", "init", "systemctl", "kill", "killall", "pkill",
}


class ShellTool(Tool):
    name = "shell"
    description = (
        "Execute a shell command locally. Returns stdout, stderr, exit code. "
        "Use for security tools (curl, ffuf, nuclei, nmap, httpx, subfinder), "
        "package installs, and general recon. Timeout default 120s."
    )
    parameters = {
        "type": "object",
        "properties": {
            "command": {"type": "string"},
            "timeout": {"type": "integer", "default": 120},
            "cwd": {"type": "string", "default": "."},
            "env": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
        },
        "required": ["command"],
    }

    def __init__(self, default_timeout: int = 120,
                 workspace: str | Path = "./data/workspace"):
        self.default_timeout = default_timeout
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)

    def _blocked(self, command: str) -> str | None:
        try:
            parts = shlex.split(command)
        except ValueError:
            return None
        if not parts:
            return None
        head = os.path.basename(parts[0])
        if head in BLOCKED_BINARIES:
            return f"binary '{head}' is blocked"
        return None

    async def run(self, **kwargs: Any) -> ToolResult:
        command = (kwargs.get("command") or "").strip()
        if not command:
            return ToolResult(ok=False, output="", error="empty command")

        blocked = self._blocked(command)
        if blocked:
            return ToolResult(ok=False, output="", error=blocked)

        timeout = int(kwargs.get("timeout", self.default_timeout))
        cwd = kwargs.get("cwd") or str(self.workspace)
        extra_env = kwargs.get("env") or {}

        env = os.environ.copy()
        env.update(extra_env)

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
        except FileNotFoundError as e:
            return ToolResult(ok=False, output="", error=str(e))

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(ok=False, output="",
                              error=f"timeout after {timeout}s",
                              meta={"command": command})

        stdout = _truncate(stdout_b.decode("utf-8", errors="replace"), 32000)
        stderr = _truncate(stderr_b.decode("utf-8", errors="replace"), 8000)

        ok = proc.returncode == 0
        combined = f"$ {command}\n"
        if stdout:
            combined += f"--- stdout ---\n{stdout}\n"
        if stderr:
            combined += f"--- stderr ---\n{stderr}\n"
        combined += f"--- exit {proc.returncode} ---"

        return ToolResult(
            ok=ok, output=combined,
            error=None if ok else f"exit {proc.returncode}",
            meta={"command": command, "exit": proc.returncode, "cwd": cwd},
        )


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-(limit // 2):]
    return f"{head}\n... [truncated {len(text) - limit} chars] ...\n{tail}"
