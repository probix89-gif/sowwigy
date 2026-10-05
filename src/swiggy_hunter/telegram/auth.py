"""
Chat-id gate. Only the configured chat may issue commands.
Everyone else gets a terse refusal and is not logged further.

NOTE on require_auth: it must implement the descriptor protocol. PTB
registers `self.cmd_start` (a bound method) and later calls it with
(update, context). A plain @wraps closure breaks that: the closure is
not a descriptor, so `self.cmd_start` returns the raw function and the
call becomes handler(update, context) with `update` landing in `self`
-> "takes 2 positional arguments but 3 were given".
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


class _AuthBound:
    """Bound async wrapper: __get__ on the instance produced this."""

    def __init__(self, func: Callable[..., Any], obj: Any):
        self._func, self._obj = func, obj
        wraps(func)(self)

    async def __call__(self, update: Update, context: ContextTypes.DEFAULT_TYPE = None):
        if not is_authorized(update):
            msg = getattr(update, "effective_message", None) if update else None
            if msg:
                await msg.reply_text("not authorized.")
            return
        return await self._func(self._obj, update, context)


class _AuthDescriptor:
    def __init__(self, func: Callable[..., Any]):
        self._func = func
        wraps(func)(self)

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self._func
        return _AuthBound(self._func, obj)


def require_auth(handler: Callable[..., Any]) -> Callable[..., Any]:
    """Auth gate that preserves bound-method semantics (see module docstring)."""
    return _AuthDescriptor(handler)
