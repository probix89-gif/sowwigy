"""
HermesAgent v2 — the stealth navigator.

Hermes drives end-to-end user flows in a browser-accurate way, using
the shared stealth session and the browser tool when JS execution is
needed. It observes state transitions and hands actionable hypotheses
to business_logic or attacker via add_task.

Named after the messenger — it carries signals between the site's
reacting state and the other agents' hypotheses.
"""
from __future__ import annotations

from ..state.schemas import AgentName
from .base import BaseAgent


class HermesAgent(BaseAgent):
    name = AgentName.hermes
    max_iterations = 45
    max_tool_calls_per_turn = 6
    temperature = 0.60

    allow_tools = [
        "shell", "install_tool",
        "stealth_http", "stealth_race", "browser",
        "file_read", "file_write", "file_list",
        "hash", "encode", "decode", "jwt_inspect",
        "header_analysis", "param_fuzz", "cookie_inspect",
        "diff", "extract", "json_path",
        "endpoint_discovery", "tech_fingerprint",
        "auth_status", "auth_login_otp", "auth_login_cookie",
        "auth_refresh_session", "session_rotate", "auth_logout",
        "report_finding", "query_blackboard",
        "update_task", "add_task", "annotate_finding",
    ]

    async def _initial_messages(self, task):  # type: ignore[override]
        messages = await super()._initial_messages(task)
        extra = (
            "\n\n# Hermes — stealth navigator (V2)\n"
            "You browse Swiggy the way a real user does. Your purpose is to "
            "reach state that other agents cannot — authenticated checkout "
            "flows, JS-gated endpoints, offer selection, wallet apply.\n\n"
            "Method:\n"
            "1. Ensure auth first: check auth_status. If not authenticated, "
            "start OTP with auth_login_otp(phone) — the operator will "
            "confirm. If the operator has already pasted cookies, "
            "auth_login_cookie works too.\n"
            "2. Warm up: GET the homepage with stealth_http kind='navigate' "
            "to acquire cookies. Then GET /restaurants.\n"
            "3. Pick a restaurant, view its menu, add an item to cart. At "
            "every step, extract hidden fields, tokens, offer IDs from the "
            "HTML/JSON. Use the browser tool when the page is JS-rendered "
            "and the fetch-based flow would produce invalid signatures.\n"
            "4. Apply a coupon. Note the exact request the site sends — "
            "capture it verbatim for business_logic.\n"
            "5. Enter checkout. Before placing the order, stop. Do NOT "
            "actually complete a payment. Hand off to attacker with the "
            "captured pre-payment state.\n"
            "6. Detect where the server trusts the client:\n"
            "   - price fields in cart payload\n"
            "   - hidden coupon/discount fields\n"
            "   - wallet apply order relative to coupon\n"
            "   - delivery-fee / surge-fee fields\n"
            "   - payment_status / order_status fields\n"
            "   Each of these is a finding with category='hermes_flow'.\n\n"
            "State hygiene:\n"
            "  - Keep ONE session alive across the whole flow. Do not "
            "    rotate mid-flow; rotation is for after a block.\n"
            "  - Never fire back-to-back requests. The timing layer "
            "    already paces you if you use stealth_http — do not bypass "
            "    it by firing shell curl calls.\n"
            "  - If you hit 403/429, wait for the behavior cool-down, "
            "    then try ONE retry. If that fails, session_rotate, then "
            "    try once. If that fails, note the block and stop.\n\n"
            "Handoffs:\n"
            "  - Every state transition you observe → report_finding "
            "    category='hermes_flow' with the full cookie + response "
            "    capture.\n"
            "  - Every hypothesis you form → add_task for business_logic "
            "    with the exact test to run.\n"
            "  - Every confirmed server trust → add_task for attacker "
            "    with finding_ids attached."
        )
        messages[1]["content"] += extra
        return messages
