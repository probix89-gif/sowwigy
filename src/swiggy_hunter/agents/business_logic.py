"""
BusinessLogicAgent v2 — high-impact order/coupon/payment abuse hunting.
"""
from __future__ import annotations

from ..state.schemas import AgentName
from .base import BaseAgent


class BusinessLogicAgent(BaseAgent):
    name = AgentName.business_logic
    max_iterations = 38
    max_tool_calls_per_turn = 5
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
            "\n\n# Business-logic playbook (V2)\n"
            "You hunt for bugs that lead to free or heavily discounted "
            "orders. Every test goes through stealth_http (or stealth_race "
            "for concurrency). Use the authenticated session.\n\n"
            "Attack these flows:\n\n"
            "A. Coupon application\n"
            "   - Idempotency: apply the same code twice on one cart.\n"
            "   - Stacking: apply a coupon + a wallet-credit + a referral "
            "     offer, check if all three apply.\n"
            "   - Cross-account replay: capture an apply-coupon request as "
            "     user A, replay it as user B (needs two sessions — ask the "
            "     decision-maker or use session_rotate if permitted).\n"
            "   - Race: stealth_race with count=10–20 against apply-coupon. "
            "     More than one 2xx = a real race condition.\n"
            "   - Expired coupon replay: same payload, different timestamps.\n\n"
            "B. Cart & quantity\n"
            "   - quantity=-1, 0, 0.5, 1e9 via PUT to cart item.\n"
            "   - Duplicate item merge: same SKU twice, check quantity math.\n"
            "   - price field in the client payload — is it trusted?\n\n"
            "C. Currency / price tampering\n"
            "   - Swap currency code in cart payload (INR → USD → BTC).\n"
            "   - Edit unit_price, subtotal, delivery_fee directly.\n\n"
            "D. Order state machine\n"
            "   - Place order with payment_status=PAID, skip the payment.\n"
            "   - Cancel after payment, check refund + food both credited.\n"
            "   - Edit an order post-payment to add items.\n\n"
            "E. Wallet / referral\n"
            "   - Self-referral loop; wallet credit → order → refund to a "
            "     different method.\n\n"
            "For every test, record a finding with:\n"
            "  - flow, hypothesis, exact request (with capture)\n"
            "  - observed response, expected-if-fixed\n"
            "  - impact estimate (₹ value if it can be quantified)\n\n"
            "Cap your rate at 5 rps. Never fire a race with count > 20."
        )
        messages[1]["content"] += extra
        return messages
