"""
ResearchAgent v2 — outward-facing.
"""
from __future__ import annotations

from ..state.schemas import AgentName
from .base import BaseAgent


class ResearchAgent(BaseAgent):
    name = AgentName.research
    max_iterations = 26
    max_tool_calls_per_turn = 4
    temperature = 0.5

    allow_tools = [
        "shell", "install_tool",
        "stealth_http",
        "file_read", "file_write", "file_list",
        "hash", "encode", "decode",
        "diff", "extract", "json_path",
        "tech_fingerprint",
        "report_finding", "query_blackboard",
        "update_task", "add_task", "annotate_finding",
    ]

    async def _initial_messages(self, task):  # type: ignore[override]
        messages = await super()._initial_messages(task)
        extra = (
            "\n\n# Research playbook (V2)\n"
            "You have shell + stealth_http. Use them sparingly for public "
            "sources — you are not stealth-testing those, so rate yourself "
            "to ~1 rps on external sites.\n\n"
            "High-value queries:\n"
            "1. Public bug-bounty writeups about food-delivery coupon / "
            "checkout / wallet logic. Extract the technique and reshape it "
            "as a hypothesis for business_logic.\n"
            "2. Fetch swiggy.com/robots.txt, /sitemap.xml, "
            "/.well-known/security.txt via stealth_http.\n"
            "3. Fetch the web app's main JS bundle and grep for API base "
            "URLs, feature flags, internal endpoint names.\n"
            "4. Look for mobile app reverse-engineering notes on GitHub "
            "(search 'swiggy api' 'swiggy reverse' 'swiggy signature').\n"
            "5. Check for CVEs on the stack returned by tech_fingerprint.\n\n"
            "Every useful finding → report_finding with category='research' "
            "and the source URL. Every actionable hypothesis → add_task "
            "for business_logic or hermes with a concrete test."
        )
        messages[1]["content"] += extra
        return messages
