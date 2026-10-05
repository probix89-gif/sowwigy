"""
Hash, encode/decode, JWT inspect. Stdlib only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
from typing import Any

from .base import Tool, ToolResult


class HashTool(Tool):
    name = "hash"
    description = "md5/sha1/sha256/sha512 of a string."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string"},
            "algo": {"type": "string",
                     "enum": ["md5", "sha1", "sha256", "sha512"],
                     "default": "sha256"},
        },
        "required": ["text"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        try:
            h = hashlib.new(kwargs.get("algo", "sha256"))
            h.update(kwargs.get("text", "").encode("utf-8"))
            return ToolResult(ok=True, output=h.hexdigest())
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))


class EncodeTool(Tool):
    name = "encode"
    description = "Encode: base64, base64url, hex, url."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string"},
            "scheme": {"type": "string",
                       "enum": ["base64", "base64url", "hex", "url"],
                       "default": "base64"},
        },
        "required": ["text"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        text = kwargs.get("text", "")
        scheme = kwargs.get("scheme", "base64")
        raw = text.encode("utf-8")
        try:
            if scheme == "base64":
                out = base64.b64encode(raw).decode()
            elif scheme == "base64url":
                out = base64.urlsafe_b64encode(raw).decode().rstrip("=")
            elif scheme == "hex":
                out = raw.hex()
            elif scheme == "url":
                out = urllib.parse.quote(text, safe="")
            else:
                return ToolResult(ok=False, output="", error=f"unknown scheme {scheme}")
            return ToolResult(ok=True, output=out)
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))


class DecodeTool(Tool):
    name = "decode"
    description = "Decode: base64, base64url, hex, url."
    parameters = {
        "type": "object",
        "properties": {
            "text": {"type": "string"},
            "scheme": {"type": "string",
                       "enum": ["base64", "base64url", "hex", "url"],
                       "default": "base64"},
        },
        "required": ["text"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        text = kwargs.get("text", "").strip()
        scheme = kwargs.get("scheme", "base64")
        try:
            pad = "=" * (-len(text) % 4)
            if scheme == "base64":
                out = base64.b64decode(text + pad).decode("utf-8", errors="replace")
            elif scheme == "base64url":
                out = base64.urlsafe_b64decode(text + pad).decode("utf-8", errors="replace")
            elif scheme == "hex":
                out = bytes.fromhex(text).decode("utf-8", errors="replace")
            elif scheme == "url":
                out = urllib.parse.unquote(text)
            else:
                return ToolResult(ok=False, output="", error=f"unknown scheme {scheme}")
            return ToolResult(ok=True, output=out)
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))


class JwtInspectTool(Tool):
    name = "jwt_inspect"
    description = "Decode a JWT header+payload without verifying. Flags alg=none."
    parameters = {
        "type": "object",
        "properties": {"token": {"type": "string"}},
        "required": ["token"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        token = (kwargs.get("token") or "").strip()
        parts = token.split(".")
        if len(parts) < 2:
            return ToolResult(ok=False, output="", error="not a JWT")

        def b64(s: str) -> bytes:
            return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

        try:
            header = json.loads(b64(parts[0]))
            payload = json.loads(b64(parts[1]))
            notes: list[str] = []
            alg = (header.get("alg") or "").lower()
            if alg == "none":
                notes.append("!! alg=none — signature bypass candidate")
            if alg.startswith("hs"):
                notes.append("HMAC-signed; check for weak key / kid injection")
            if len(parts) < 3 or not parts[2]:
                notes.append("!! signature segment missing")
            out = json.dumps({"header": header, "payload": payload, "notes": notes}, indent=2)
            return ToolResult(ok=True, output=out,
                              meta={"header": header, "payload": payload, "notes": notes})
        except Exception as e:
            return ToolResult(ok=False, output="", error=str(e))
