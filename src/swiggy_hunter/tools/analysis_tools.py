"""
Diff, regex extract, JSON path. Stdlib only.
"""
from __future__ import annotations

import difflib
import json
import re
from typing import Any

from .base import Tool, ToolResult


class DiffTool(Tool):
    name = "diff"
    description = "Unified diff between two strings. Great for comparing responses."
    parameters = {
        "type": "object",
        "properties": {
            "a": {"type": "string"},
            "b": {"type": "string"},
            "label_a": {"type": "string", "default": "a"},
            "label_b": {"type": "string", "default": "b"},
            "context": {"type": "integer", "default": 3},
        },
        "required": ["a", "b"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        a = kwargs["a"].splitlines(keepends=True)
        b = kwargs["b"].splitlines(keepends=True)
        d = difflib.unified_diff(
            a, b,
            fromfile=kwargs.get("label_a", "a"),
            tofile=kwargs.get("label_b", "b"),
            n=int(kwargs.get("context", 3)),
        )
        out = "".join(d)
        return ToolResult(ok=True, output=out or "(identical)")


class ExtractTool(Tool):
    name = "extract"
    description = "Regex-extract matches from a text."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string"},
            "pattern": {"type": "string"},
            "flags": {"type": "string", "default": ""},
            "max_results": {"type": "integer", "default": 200},
        },
        "required": ["text", "pattern"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        text = kwargs["text"]
        pattern = kwargs["pattern"]
        fs = kwargs.get("flags", "")
        flags = 0
        if "i" in fs:
            flags |= re.IGNORECASE
        if "m" in fs:
            flags |= re.MULTILINE
        if "s" in fs:
            flags |= re.DOTALL
        try:
            rx = re.compile(pattern, flags)
        except re.error as e:
            return ToolResult(ok=False, output="", error=f"bad regex: {e}")
        maxr = int(kwargs.get("max_results", 200))
        matches: list[Any] = []
        for m in rx.finditer(text):
            if len(matches) >= maxr:
                break
            matches.append(list(m.groups()) if m.groups() else m.group(0))
        return ToolResult(ok=True, output=json.dumps(matches, indent=2),
                          meta={"count": len(matches)})


class JsonPathTool(Tool):
    name = "json_path"
    description = "Navigate JSON by dotted path. '*' iterates dicts/arrays."
    parameters = {
        "type": "object",
        "properties": {
            "json_text": {"type": "string"},
            "path": {"type": "string"},
        },
        "required": ["json_text", "path"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        try:
            data = json.loads(kwargs["json_text"])
        except Exception as e:
            return ToolResult(ok=False, output="", error=f"bad json: {e}")

        def walk(node: Any, parts: list[str]) -> Any:
            if not parts:
                return node
            key, rest = parts[0], parts[1:]
            if key == "*":
                if isinstance(node, dict):
                    return {k: walk(v, rest) for k, v in node.items()}
                if isinstance(node, list):
                    return [walk(v, rest) for v in node]
                return None
            if isinstance(node, dict):
                return walk(node.get(key), rest)
            if isinstance(node, list):
                try:
                    i = int(key)
                except ValueError:
                    return None
                return walk(node[i], rest) if 0 <= i < len(node) else None
            return None

        parts = [p for p in kwargs["path"].split(".") if p]
        return ToolResult(ok=True, output=json.dumps(walk(data, parts), indent=2))
