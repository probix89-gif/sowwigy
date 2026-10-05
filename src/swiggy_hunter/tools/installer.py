"""
installer — install binaries on demand.

Allow-listed installers only. Verifies the binary exists afterward.
Audit-logs every install to ./data/install_log.jsonl.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

from ..logging_setup import get_logger
from .base import Tool, ToolResult
from .shell import ShellTool

log = get_logger(__name__)


class InstallerTool(Tool):
    name = "install_tool"
    description = (
        "Install a binary or library. Managers: apt-get, pip, pip3, go, "
        "cargo, npm, git. Only allow-listed managers permitted. "
        "After install, verifies the binary is on PATH if requested. "
        "Example: install_tool(manager='go', package='github.com/"
        "projectdiscovery/nuclei/v3/cmd/nuclei@latest', verify_binary='nuclei')"
    )
    parameters = {
        "type": "object",
        "properties": {
            "manager": {
                "type": "string",
                "enum": ["apt-get", "pip", "pip3", "go", "cargo", "npm", "git"],
            },
            "package": {"type": "string"},
            "verify_binary": {"type": "string"},
            "extra_args": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["manager", "package"],
    }

    def __init__(
        self,
        shell: ShellTool,
        allowed_installers: list[str],
        log_path: str | Path = "./data/install_log.jsonl",
    ):
        self.shell = shell
        self.allowed = set(allowed_installers)
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _render(self, manager: str, package: str, extra: list[str]) -> str:
        if manager == "apt-get":
            return "sudo apt-get install -y " + " ".join([package, *extra])
        if manager in ("pip", "pip3"):
            return f"{manager} install --upgrade " + " ".join([package, *extra])
        if manager == "go":
            return "go install " + " ".join([package, *extra])
        if manager == "cargo":
            return "cargo install " + " ".join([package, *extra])
        if manager == "npm":
            return "npm install -g " + " ".join([package, *extra])
        if manager == "git":
            return "git clone --depth 1 " + " ".join([package, *extra])
        raise ValueError(f"unsupported: {manager}")

    async def run(self, **kwargs: Any) -> ToolResult:
        manager = kwargs["manager"]
        package = kwargs["package"]
        extra = kwargs.get("extra_args") or []
        verify = kwargs.get("verify_binary")

        if manager not in self.allowed:
            return ToolResult(
                ok=False, output="",
                error=f"installer '{manager}' not allowed. allowed={sorted(self.allowed)}",
            )

        cmd = self._render(manager, package, extra)
        result = await self.shell.safe_run(command=cmd, timeout=600)

        entry = {
            "at": time.time(),
            "manager": manager,
            "package": package,
            "command": cmd,
            "exit": result.meta.get("exit") if result.meta else None,
            "ok": result.ok,
        }
        self._append_log(entry)

        if not result.ok:
            return result

        if verify:
            found = shutil.which(verify)
            if not found:
                return ToolResult(
                    ok=False, output=result.output,
                    error=f"install reported success but '{verify}' not on PATH",
                )
            entry["resolved_path"] = found
            self._append_log({"verify": entry})

        return ToolResult(
            ok=True,
            output=result.output + (
                f"\n[install ok] {manager} {package}"
                + (f" -> {shutil.which(verify)}" if verify else "")
            ),
            meta=entry,
        )

    def _append_log(self, entry: dict) -> None:
        try:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except Exception:
            log.exception("installer.log_failed")
