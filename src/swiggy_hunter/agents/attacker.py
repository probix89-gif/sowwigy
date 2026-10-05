"""
AttackerAgent v2 — one of the two main agents (with decision-maker).

Builds and executes multi-step chains. Uses stealth_race for legitimate
concurrency tests, installs tools on demand, produces self-contained
PoC scripts in ./data/exploits/<finding_id>.py.
"""
from __future__ import annotations

from ..state.schemas import AgentName
from .base import BaseAgent


class AttackerAgent(BaseAgent):
    name = AgentName.attacker
    max_iterations = 42
    max_tool_calls_per_turn = 6
    temperature = 0.55

    allow_tools = [
        "shell", "install_tool",
        "stealth_http", "stealth_race", "browser",
        "file_read", "file_write", "file_list",
        "hash", "encode", "decode", "jwt_inspect",
        "header_analysis", "param_fuzz", "cookie_inspect",
        "diff", "extract", "json_path",
        "endpoint_discovery",
        "auth_status", "auth_refresh_session", "session_rotate",
        "report_finding", "query_blackboard",
        "update_task", "add_task", "annotate_finding",
    ]

    async def _initial_messages(self, task):  # type: ignore[override]
        messages = await super()._initial_messages(task)
        extra = (
            "\n\n# Attacker playbook (V2)\n"
            "You are one of the two MAIN agents. You build and execute "
            "exploit chains from confirmed findings.\n\n"
            "Tool installation:\n"
            "If you need ffuf, nmap, nuclei, httpx, subfinder, jq, curl, or "
            "any other binary — install it via install_tool. Examples:\n"
            "  install_tool(manager='apt-get', package='ffuf', "
            "verify_binary='ffuf')\n"
            "  install_tool(manager='go', package='github.com/"
            "projectdiscovery/nuclei/v3/cmd/nuclei@latest', "
            "verify_binary='nuclei')\n"
            "  install_tool(manager='pip', package='requests')\n\n"
            "Process:\n"
            "1. Read the confirmed finding + linked recon map.\n"
            "2. Design the minimal chain. Examples:\n"
            "   - Coupon race: stealth_race count=20 against apply-coupon. "
            "     race_indicator=True + more than one 2xx = win.\n"
            "   - Payment bypass: create order, tamper total before payment "
            "     intent, complete payment, verify charged amount.\n"
            "   - Cart tamper: PUT quantity=-1, check total.\n"
            "   - Replay: capture 'order-placed', modify order_id, replay.\n"
            "3. Write the chain as a standalone script at "
            "   ./data/exploits/<finding_id>.py using only stdlib + "
            "   curl_cffi (for stealth). Must run cleanly from scratch.\n"
            "4. Run it via shell. Capture stdout + any JSON dumps.\n"
            "5. On success: full evidence bundle with finding_id, "
            "   chain_steps, per-step request/response, observed impact, "
            "   repro notes. annotate_finding status='confirmed', "
            "   severity adjusted to impact.\n"
            "6. On failure: record WHERE it failed and why.\n\n"
            "Hard rules:\n"
            "  - Never more than 5 rps against any host.\n"
            "  - stealth_race max count = 20.\n"
            "  - No mass-account creation. No destructive writes.\n"
            "  - Every script saved. Every request logged via stealth_http "
            "    or stealth_race."
        )
        messages[1]["content"] += extra
        return messages
