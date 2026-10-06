"""
Notifier — outbound side of the bot.

All sends pass through `send`, which:
  - splits long messages
  - throttles ~1 msg/sec per chat
  - swallows network errors

Event helpers compose pretty short messages for findings/tasks/etc.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from telegram import Bot
from telegram.constants import ParseMode
from telegram.error import TelegramError

from ..logging_setup import get_logger
from .auth import AUTHORIZED_CHAT_ID
from .formatters import SEVERITY_MARK, escape, fmt_ts, split_message

log = get_logger(__name__)


class Notifier:
    def __init__(self, bot: Bot, chat_id: str | None = None):
        self.bot = bot
        self.chat_id = chat_id or AUTHORIZED_CHAT_ID
        self._lock = asyncio.Lock()
        self._last_send_ts = 0.0
        self._min_interval = 0.9

    async def send(self, text: str, *, silent: bool = False) -> None:
        if not self.chat_id:
            log.warning("notifier.no_chat_id")
            return
        for chunk in split_message(text):
            await self._send_one(chunk, silent=silent)

    async def _send_one(self, text: str, *, silent: bool) -> None:
        async with self._lock:
            wait = self._min_interval - (time.monotonic() - self._last_send_ts)
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                await self.bot.send_message(
                    chat_id=self.chat_id,
                    text=text,
                    parse_mode=ParseMode.HTML,
                    disable_notification=silent,
                    disable_web_page_preview=True,
                )
            except TelegramError as e:
                log.warning("notifier.send_failed", error=str(e))
            finally:
                self._last_send_ts = time.monotonic()

    # ------------------------------------------------------------------
    # event helpers
    # ------------------------------------------------------------------

    async def notify_finding(self, finding: Any) -> None:
        # HIGH-IMPACT TRIAGE GATE (telegram layer): only findings that have
        # been independently validated (status=confirmed/reported) AND carry
        # HIGH/CRITICAL severity reach the operator. New/validating findings
        # are logged but stay silent — the validation agent decides what is
        # real, and the reporter loop publishes validated results.
        sev = finding.severity.value
        status = finding.status.value
        if status not in ("confirmed", "reported"):
            log.info(
                "notifier.finding_held",
                id=finding.id, sev=sev, status=status,
                reason="awaiting validation — not reported to operator",
            )
            return
        if sev not in ("high", "critical"):
            log.info(
                "notifier.finding_below_threshold",
                id=finding.id, sev=sev, status=status,
                reason="severity below report threshold",
            )
            return
        mark = SEVERITY_MARK.get(sev, "•")
        text = (
            f"{mark} <b>Validated finding</b> {escape(sev.upper())}\n"
            f"• id: {escape(finding.id)}\n"
            f"• title: {escape(finding.title)}\n"
            f"• category: {escape(finding.category)}\n"
            f"• by: {escape(finding.discovered_by.value)}\n"
            f"• status: {escape(status)}\n"
            f"• at: {escape(fmt_ts(finding.discovered_at))}"
        )
        if finding.endpoint:
            text += (
                f"\n• endpoint: "
                f"{escape(finding.method or 'GET')} {escape(finding.endpoint)}"
            )
        await self.send(text)

    async def notify_task(self, task: Any) -> None:
        status = task.status.value
        if status not in ("done", "failed"):
            return
        mark = "✅" if status == "done" else "❌"
        text = (
            f"{mark} <b>Task {escape(status)}</b>\n"
            f"• id: {escape(task.id)}\n"
            f"• agent: {escape(task.assignee.value)}\n"
            f"• title: {escape(task.title)}"
        )
        if task.result:
            text += f"\n• result: {escape(task.result[:400])}"
        await self.send(text, silent=True)

    async def notify_lifecycle(self, state: str) -> None:
        await self.send(f"⚙️ runtime state → {escape(state)}", silent=True)

    async def notify_operator_reply(self, text: str) -> None:
        await self.send(f"🧠 <b>decision-maker</b>\n{escape(text)}")

    async def notify_block(self, host: str, status: int, seconds: float) -> None:
        await self.send(
            f"🚫 <b>Block detected</b>\n"
            f"• host: {escape(host)}\n"
            f"• status: {code(str(status))}\n"
            f"• cooling down for {code(str(int(seconds)) + 's')}",
            silent=True,
        )


def code(text: str) -> str:
    return f"<code>{escape(text)}</code>"
