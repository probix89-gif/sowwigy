"""
ReconAgent v2 — attack-surface mapping through the stealth session.

The initial-message builder injects a playbook tuned for V2 tooling.
"""
from __future__ import annotations

from ..state.schemas import AgentName
from .base import BaseAgent


class ReconAgent(BaseAgent):
    name = AgentName.recon
    max_iterations = 32
    max_tool_calls_per_turn = 5
    temperature = 0.40

    allow_tools = [
        "shell", "install_tool",
        "stealth_http", "browser",
        "file_read", "file_write", "file_list",
        "hash", "encode", "decode",
        "header_analysis", "cookie_inspect",
        "diff", "extract", "json_path",
        "subdomain_enum", "endpoint_discovery", "tech_fingerprint",
        "auth_status", "auth_refresh_session",
        "report_finding", "query_blackboard",
        "update_task", "add_task", "annotate_finding",
    ]

    async def _initial_messages(self, task):  # type: ignore[override]
        messages = await super()._initial_messages(task)
        extra = (
            "\n\n# Recon playbook (V2)\n"
            "You map the attack surface using the stealth session.\n\n"
            "Sequence:\n"
            "1. tech_fingerprint on the apex domain. Note the stack.\n"
            f"2. subdomain_enum for {self.ctx.config.target.domain}.\n"
            "3. For each interesting subdomain (api, m, auth, partner), run "
            "endpoint_discovery.\n"
            "4. Fetch the main web app HTML + JS bundles with stealth_http "
            "(kind='navigate' for HTML, kind='asset' for scripts). Use "
            "extract to pull /api/... paths from JS.\n"
            "5. When you confirm a new endpoint, report_finding with "
            "category='recon' and include the raw capture as evidence.\n"
            "6. If a page requires JS execution to reveal endpoints, drive "
            "it with the browser tool.\n"
            "7. Every interesting flow you identify → add_task for "
            "business_logic with a concrete test description.\n\n"
            "Stay stealthy: do NOT fire requests faster than 5 rps. If you "
            "hit 403/429, back off and let the behavior layer cool down."
        )
        messages[1]["content"] += extra
        return messages
