"""
File read/write/list, confined to ./data/.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import Tool, ToolResult


WORKSPACE_ROOT = Path("./data").resolve()


def _resolve(path_str: str, workspace_only: bool = True) -> Path:
    p = Path(path_str)
    if not p.is_absolute():
        p = WORKSPACE_ROOT / p
    p = p.resolve()
    if workspace_only and not str(p).startswith(str(WORKSPACE_ROOT)):
        raise PermissionError(f"outside workspace: {p}")
    return p


class FileReadTool(Tool):
    name = "file_read"
    description = "Read a UTF-8 file under ./data/. Truncates at 128KB."
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "max_bytes": {"type": "integer", "default": 131072},
        },
        "required": ["path"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        try:
            p = _resolve(kwargs.get("path", ""))
        except PermissionError as e:
            return ToolResult(ok=False, output="", error=str(e))
        if not p.exists():
            return ToolResult(ok=False, output="", error=f"not found: {p}")
        if p.is_dir():
            return ToolResult(ok=False, output="", error=f"is a directory: {p}")
        try:
            data = p.read_bytes()[: int(kwargs.get("max_bytes", 131072))]
            return ToolResult(ok=True, output=data.decode("utf-8", errors="replace"),
                              meta={"path": str(p), "bytes": len(data)})
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))


class FileWriteTool(Tool):
    name = "file_write"
    description = "Write UTF-8 text to a file under ./data/. Creates parents."
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
            "append": {"type": "boolean", "default": False},
        },
        "required": ["path", "content"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        try:
            p = _resolve(kwargs.get("path", ""))
        except PermissionError as e:
            return ToolResult(ok=False, output="", error=str(e))
        p.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if kwargs.get("append") else "w"
        content = kwargs.get("content", "")
        try:
            with p.open(mode, encoding="utf-8") as fh:
                fh.write(content)
            return ToolResult(ok=True, output=f"wrote {len(content)} chars to {p}",
                              meta={"path": str(p)})
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))


class FileListTool(Tool):
    name = "file_list"
    description = "List files under a directory in ./data/."
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "default": "."},
            "recursive": {"type": "boolean", "default": False},
        },
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        try:
            p = _resolve(kwargs.get("path", "."))
        except PermissionError as e:
            return ToolResult(ok=False, output="", error=str(e))
        if not p.exists():
            return ToolResult(ok=False, output="", error=f"not found: {p}")
        entries: list[str] = []
        try:
            it = p.rglob("*") if kwargs.get("recursive") else p.iterdir()
            for child in sorted(it):
                kind = "d" if child.is_dir() else "f"
                size = child.stat().st_size if child.is_file() else 0
                rel = child.relative_to(WORKSPACE_ROOT)
                entries.append(f"{kind} {size:>10} {rel}")
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))
        return ToolResult(ok=True, output="\n".join(entries) or "(empty)")
