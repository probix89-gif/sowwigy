"""
ValidationAgent v2 — reproduce, falsify, confirm.
"""
from __future__ import annotations

from ..state.schemas import AgentName
from .base import BaseAgent


class ValidationAgent(BaseAgent):
    name = AgentName.validation
    max_iterations = 32
    max_tool_calls_per_turn = 4
    temperature = 0.35

    allow_tools = [
        "shell",
        "stealth_http", "stealth_race", "browser",
        "file_read", "file_write", "file_list",
        "hash", "encode", "decode", "jwt_inspect",
        "header_analysis", "param_fuzz", "cookie_inspect",
        "diff", "extract", "json_path",
        "auth_status", "auth_refresh_session", "session_rotate",
        "report_finding", "query_blackboard",
        "update_task", "add_task", "annotate_finding",
    ]

    async def _initial_messages(self, task):  # type: ignore[override]
        messages = await super()._initial_messages(task)
        extra = (
            "\n\n# Validation playbook (V2)\n"
            "For each finding you pick up:\n\n"
            "1. Reproduce with the exact same request via stealth_http. "
            "Capture status, headers, body, timing.\n"
            "2. Try to FALSIFY it. What else could explain the behavior?\n"
            "   - CDN cache (check X-Cache / cf-cache-status)\n"
            "   - Clock skew\n"
            "   - Different auth context than assumed\n"
            "   - A concurrent agent polluting cookies\n"
            "3. Controls:\n"
            "   - positive control (a request that SHOULD succeed)\n"
            "   - negative control (a request that SHOULD fail)\n"
            "   If controls misbehave, your setup is wrong.\n"
            "4. If reproducible: annotate_finding with status='confirmed', "
            "append the raw capture + numbered repro steps.\n"
            "5. Otherwise: status='false_positive', one sentence why.\n"
            "6. For confirmed severity >= high: add_task to attacker with "
            "the chain description; finding_ids attached.\n\n"
            "Cap your rate at 3 rps. No destructive tests."
        )
        messages[1]["content"] += extra
        return messages
