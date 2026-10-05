"""
Telegram-friendly prompt templates for the OTP flow.

Kept as plain strings so the bot can send them without pulling in the
auth layer.
"""
from __future__ import annotations

from .otp import OtpFlowError  # noqa: F401 (kept for type parity)


OTP_ASK_PHONE = (
    "📱 <b>OTP login</b>\n\n"
    "Send your Swiggy phone number (10 digits):\n"
    "<code>/login 9876543210</code>"
)


OTP_ASK_CODE = (
    "📨 <b>OTP sent</b>\n\n"
    "Enter the 6-digit code you received:\n"
    "<code>/otp 123456</code>\n\n"
    "You have 10 minutes. Resend with <code>/login &lt;phone&gt;</code>."
)


OTP_VERIFIED = "✅ Logged in. Session stored in vault."


COOKIE_ASK = (
    "🍪 <b>Cookie login</b>\n\n"
    "Paste cookies from your logged-in browser session. Any of these work:\n"
    "• <code>a=1; b=2</code>\n"
    "• JSON: <code>{\"a\":\"1\",\"b\":\"2\"}</code>\n"
    "• Netscape cookie file lines\n\n"
    "Then send:\n"
    "<code>/cookie a=1; b=2</code>"
)
