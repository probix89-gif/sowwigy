"""
Inline keyboards for destructive confirmations.
"""
from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup


def confirm_keyboard(
    action: str,
    yes_label: str = "yes, do it",
    no_label: str = "cancel",
) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton(yes_label, callback_data=f"confirm:{action}"),
        InlineKeyboardButton(no_label, callback_data=f"cancel:{action}"),
    ]])


def control_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("▶ resume", callback_data="ctl:resume"),
            InlineKeyboardButton("⏸ pause", callback_data="ctl:pause"),
        ],
        [
            InlineKeyboardButton("📊 status", callback_data="ctl:status"),
            InlineKeyboardButton("📈 progress", callback_data="ctl:progress"),
        ],
        [
            InlineKeyboardButton("🛑 stop", callback_data="ctl:stop_confirm"),
        ],
    ])


def auth_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔍 check", callback_data="auth:check"),
            InlineKeyboardButton("🔄 rotate", callback_data="auth:rotate"),
        ],
        [
            InlineKeyboardButton("🚪 logout", callback_data="auth:logout_confirm"),
        ],
    ])
