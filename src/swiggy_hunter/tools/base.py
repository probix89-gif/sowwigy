"""
Tool contract.

Every tool the agents can call:
  - name: str, unique, snake_case
  - description: str, shown to the LLM in the tool schema
  - parameters: JSON-schema dict for arguments
  - async run(**kwargs) -> ToolResult

ToolRegistry serializes tools to OpenAI-compatible schemas and
dispatches calls by name. Thread-safe-ish (single event loop).
"""
from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolResult:
    ok: bool
    output: str
    error: str | None = None
    elapsed_ms: int = 0
    meta: dict[str, Any] = field(default_factory=dict)

    def to_content(self) -> str:
        if self.ok:
            return self.output if self.output else "(empty result)"
        parts = []
        if self.error:
            parts.append(f"ERROR: {self.error}")
        if self.output:
            parts.append(self.output)
        return "\n".join(parts) or "(error)"


class Tool(ABC):
    name: str = ""
    description: str = ""
    parameters: dict[str, Any] = {}

    @abstractmethod
    async def run(self, **kwargs: Any) -> ToolResult:  # pragma: no cover
        ...

    def schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    async def safe_run(self, **kwargs: Any) -> ToolResult:
        start = time.monotonic()
        try:
            result = await self.run(**kwargs)
        except Exception as e:
            result = ToolResult(ok=False, output="", error=f"{type(e).__name__}: {e}")
        result.elapsed_ms = int((time.monotonic() - start) * 1000)
        return result


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._lock = asyncio.Lock()

    def register(self, tool: Tool) -> None:
        if not tool.name:
            raise ValueError("tool has no name")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools.keys())

    def schemas(self, allow: list[str] | None = None) -> list[dict[str, Any]]:
        tools = list(self._tools.values())
        if allow is not None:
            allowed = set(allow)
            tools = [t for t in tools if t.name in allowed]
        return [t.schema() for t in tools]

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(ok=False, output="", error=f"unknown tool: {name}")
        return await tool.safe_run(**arguments)
