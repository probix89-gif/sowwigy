"""
Chat-id gate. Only the configured chat may issue commands.
Everyone else gets a terse refusal and is not logged further.
"""
from __future__ import annotations

import os
from functools import wraps
from typing import Any, Callable

from telegram import Update
from telegram.ext import ContextTypes


AUTHORIZED_CHAT_ID: str = os.environ.get("TELEGRAM_CHAT_ID", "").strip()


def is_authorized(update: Update) -> bool:
    if not AUTHORIZED_CHAT_ID:
        return False
    chat = update.effective_chat
    if chat is None:
        return False
    return str(chat.id) == AUTHORIZED_CHAT_ID


def require_auth(handler: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(handler)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not is_authorized(update):
            if update.effective_message:
                await update.effective_message.reply_text("not authorized.")
            return
        return await handler(update, context)

    return wrapper
