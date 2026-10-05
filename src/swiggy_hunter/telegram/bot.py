"""
TelegramBot v2 — full command surface.

Plain text messages (not starting with /) become directives to the
decision-maker. Structured commands cover everything else.
"""
from __future__ import annotations

import asyncio
from typing import Any

from telegram import Update
from telegram.constants import ParseMode
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from ..logging_setup import get_logger
from .auth import AUTHORIZED_CHAT_ID, is_authorized, require_auth
from .formatters import (
    code,
    escape,
    render_auth_status,
    render_directives,
    render_findings_list,
    render_status,
)
from .keyboards import auth_keyboard, confirm_keyboard, control_keyboard
from .notifier import Notifier

log = get_logger(__name__)


HELP_TEXT = (
    "<b>Swiggy Hunter v2 — Commands</b>\n"
    "\n"
    "<b>Runtime</b>\n"
    "• /start — show this help\n"
    "• /scan — start the scanner\n"
    "• /resume — resume after pause\n"
    "• /pause — pause all agents\n"
    "• /stop — stop the runtime\n"
    "• /restart — stop and start cleanly\n"
    "• /emergency — kill switch (immediate)\n"
    "\n"
    "<b>Talk to decision-maker (Agent 0)</b>\n"
    "• send plain text — becomes a directive\n"
    "• /ask &lt;msg&gt; — explicit chat\n"
    "• /inject &lt;task&gt; — force a task\n"
    "• /note &lt;text&gt; — append to plan notes\n"
    "• /directives — recent directives + replies\n"
    "\n"
    "<b>Auth</b>\n"
    "• /login &lt;phone&gt; — start OTP login\n"
    "• /otp &lt;code&gt; — enter the OTP\n"
    "• /cookie &lt;raw&gt; — paste cookies\n"
    "• /auth — show auth state\n"
    "• /rotate — rotate fingerprint\n"
    "• /logout — clear session\n"
    "• /restore — reload from vault\n"
    "\n"
    "<b>Tools</b>\n"
    "• /download &lt;mgr&gt; &lt;pkg&gt; [bin] — install a tool\n"
    "\n"
    "<b>Info</b>\n"
    "• /status — full runtime status\n"
    "• /usage — token usage today\n"
    "• /progress — progress summary\n"
    "• /findings — latest findings\n"
    "• /report — full markdown report\n"
    "• /target — current target\n"
    "• /scope — allowed scope\n"
    "• /model — model + reasoning info\n"
    "\n"
    "<b>Control</b>\n"
    "• /reason low|medium|high — reasoning level\n"
    "• /interval &lt;minutes&gt; — report interval\n"
    "• /retest &lt;id&gt; — recheck a finding\n"
    "• /clear — clear scan data\n"
    "\n"
    "<i>All commands scoped to your chat.</i>"
)


class TelegramBot:
    def __init__(self, token: str, chat_id: str | None = None):
        self.token = token
        self.chat_id = chat_id or AUTHORIZED_CHAT_ID
        self.app: Application | None = None
        self.notifier: Notifier | None = None
        self.orchestrator: Any | None = None
        self._started = False

    # ------------------------------------------------------------------
    # build / lifecycle
    # ------------------------------------------------------------------

    async def build(self) -> None:
        if self.app is not None:
            return
        app = ApplicationBuilder().token(self.token).build()
        self.app = app
        self.notifier = Notifier(app.bot, self.chat_id)
        self._register_handlers()
        log.info("telegram.built")

    def set_orchestrator(self, orch: Any) -> None:
        self.orchestrator = orch
        # wire reply hook for decision-maker
        if getattr(orch, "decision", None):
            async def _reply(text: str) -> None:
                if self.notifier:
                    await self.notifier.notify_operator_reply(text)
            orch.decision.set_reply_hook(_reply)
        # wire finding + task hooks for the notifier if the orchestrator
        # hasn't already been bound to another hook chain
        if getattr(orch, "ctx", None):
            prev_finding = orch.ctx.finding_hook
            prev_task = orch.ctx.task_hook

            async def _finding(f):
                if self.notifier:
                    await self.notifier.notify_finding(f)
                if prev_finding:
                    try:
                        await prev_finding(f)
                    except Exception:
                        pass

            async def _task(t):
                if self.notifier:
                    await self.notifier.notify_task(t)
                if prev_task:
                    try:
                        await prev_task(t)
                    except Exception:
                        pass

            orch.ctx.finding_hook = _finding
            orch.ctx.task_hook = _task
            for agent in getattr(orch, "agents", {}).values():
                agent.ctx.finding_hook = _finding
                agent.ctx.task_hook = _task

    async def start(self) -> None:
        if self.app is None:
            await self.build()
        assert self.app is not None
        await self.app.initialize()
        await self.app.start()
        if self.app.updater:
            await self.app.updater.start_polling(
                allowed_updates=Update.ALL_TYPES,
                drop_pending_updates=True,
            )
        self._started = True
        log.info("telegram.started")
        if self.notifier:
            await self.notifier.send(
                "🟢 <b>Swiggy Hunter v2 online.</b>\n"
                "Use /start for commands.\n"
                "Send any plain text to talk to the decision-maker.",
                silent=True,
            )

    async def stop(self) -> None:
        if not self._started or self.app is None:
            return
        try:
            if self.app.updater:
                await self.app.updater.stop()
            await self.app.stop()
            await self.app.shutdown()
        except Exception:
            log.exception("telegram.stop_failed")
        self._started = False
        log.info("telegram.stopped")

    # ==================================================================
    # handler registration
    # ==================================================================

    def _register_handlers(self) -> None:
        assert self.app is not None
        app = self.app

        # runtime
        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("help", self.cmd_start))
        app.add_handler(CommandHandler("scan", self.cmd_scan))
        app.add_handler(CommandHandler("resume", self.cmd_resume))
        app.add_handler(CommandHandler("pause", self.cmd_pause))
        app.add_handler(CommandHandler("stop", self.cmd_stop))
        app.add_handler(CommandHandler("restart", self.cmd_restart))
        app.add_handler(CommandHandler("emergency", self.cmd_emergency))

        # decision-maker chat
        app.add_handler(CommandHandler("ask", self.cmd_ask))
        app.add_handler(CommandHandler("inject", self.cmd_inject))
        app.add_handler(CommandHandler("note", self.cmd_note))
        app.add_handler(CommandHandler("directives", self.cmd_directives))

        # auth
        app.add_handler(CommandHandler("login", self.cmd_login))
        app.add_handler(CommandHandler("otp", self.cmd_otp))
        app.add_handler(CommandHandler("cookie", self.cmd_cookie))
        app.add_handler(CommandHandler("auth", self.cmd_auth))
        app.add_handler(CommandHandler("rotate", self.cmd_rotate))
        app.add_handler(CommandHandler("logout", self.cmd_logout))
        app.add_handler(CommandHandler("restore", self.cmd_restore))

        # tools
        app.add_handler(CommandHandler("download", self.cmd_download))

        # info
        app.add_handler(CommandHandler("status", self.cmd_status))
        app.add_handler(CommandHandler("usage", self.cmd_usage))
        app.add_handler(CommandHandler("progress", self.cmd_progress))
        app.add_handler(CommandHandler("findings", self.cmd_findings))
        app.add_handler(CommandHandler("report", self.cmd_report))
        app.add_handler(CommandHandler("target", self.cmd_target))
        app.add_handler(CommandHandler("scope", self.cmd_scope))
        app.add_handler(CommandHandler("model", self.cmd_model))

        # control
        app.add_handler(CommandHandler("reason", self.cmd_reason))
        app.add_handler(CommandHandler("interval", self.cmd_interval))
        app.add_handler(CommandHandler("retest", self.cmd_retest))
        app.add_handler(CommandHandler("clear", self.cmd_clear))

        # callbacks (inline keyboards)
        app.add_handler(CallbackQueryHandler(self.on_callback))

        # free text — must come last
        app.add_handler(MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            self.on_free_text,
        ))

    # ==================================================================
    # helpers
    # ==================================================================

    async def _reply(self, update: Update, text: str) -> None:
        if update.effective_message is None:
            return
        try:
            await update.effective_message.reply_text(
                text,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
        except TelegramError as e:
            log.warning("telegram.reply_failed", error=str(e))

    async def _require_orch(self, update: Update) -> Any | None:
        if self.orchestrator is None:
            await self._reply(update, "<i>orchestrator not attached yet.</i>")
            return None
        return self.orchestrator

    # ==================================================================
    # runtime commands
    # ==================================================================

    @require_auth
    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._reply(update, HELP_TEXT)

    @require_auth
    async def cmd_scan(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        await self._reply(update, "starting scanner…")
        ok = await orch.start()
        if ok:
            await self._reply(update, "🟢 scanner running. decision cycle fires shortly.")
        else:
            await self._reply(
                update,
                f"⚠️ start rejected. state: {code(orch.lifecycle.state.value)}",
            )

    @require_auth
    async def cmd_resume(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        ok = await orch.resume()
        msg = "▶ resumed" if ok else f"⚠️ resume rejected. state: {code(orch.lifecycle.state.value)}"
        await self._reply(update, msg)

    @require_auth
    async def cmd_pause(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        ok = await orch.pause()
        await self._reply(update, "⏸ paused" if ok else "⚠️ pause rejected (only when running)")

    @require_auth
    async def cmd_stop(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        await self._reply(update, "stopping…")
        ok = await orch.stop()
        await self._reply(update, "🛑 stopped" if ok else "⚠️ stop rejected")

    @require_auth
    async def cmd_restart(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        await self._reply(update, "restarting…")
        ok = await orch.restart()
        await self._reply(update, "🔄 restarted" if ok else "⚠️ restart failed")

    @require_auth
    async def cmd_emergency(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._reply(
            update,
            "⚠️ <b>Emergency stop</b> immediately halts all agents and closes sessions.\n"
            "Confirm?",
        )
        if update.effective_message:
            await update.effective_message.reply_text(
                "confirm:",
                reply_markup=confirm_keyboard("emergency", "kill now", "no"),
            )

    # ==================================================================
    # decision-maker chat
    # ==================================================================

    @require_auth
    async def cmd_ask(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        args = context.args or []
        if not args:
            await self._reply(update, "usage: /ask &lt;message&gt;\nor just send plain text.")
            return
        text = " ".join(args)
        await orch.ask_decision(text)
        await self._reply(update, "📨 queued for decision-maker.")

    @require_auth
    async def cmd_inject(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        args = context.args or []
        if not args:
            await self._reply(update, "usage: /inject &lt;task description&gt;")
            return
        await orch.inject_task(" ".join(args))
        await self._reply(update, "🎯 injected as task directive.")

    @require_auth
    async def cmd_note(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        args = context.args or []
        if not args:
            await self._reply(update, "usage: /note &lt;text&gt;")
            return
        await orch.note_to_plan(" ".join(args))
        await self._reply(update, "📝 noted for next decision cycle.")

    @require_auth
    async def cmd_directives(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        recent = await orch.directives_recent(limit=15)
        await self._reply(update, render_directives(recent))

    # ==================================================================
    # auth commands
    # ==================================================================

    @require_auth
    async def cmd_login(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        args = context.args or []
        if not args:
            await self._reply(
                update,
                "📱 <b>OTP login</b>\n\n"
                "Send: /login &lt;phone-number&gt;\n"
                "e.g. <code>/login 9876543210</code>",
            )
            return
        phone = args[0].strip()
        await self._reply(update, f"📨 sending OTP to {code(phone)}…")
        result = await orch.auth_send_otp(phone)
        if result.get("ok"):
            await self._reply(
                update,
                "📨 <b>OTP sent</b>\n\n"
                f"Enter the 6-digit code:\n<code>/otp 123456</code>\n\n"
                "You have 10 minutes.",
            )
        else:
            await self._reply(update, f"❌ {escape(result.get('message', 'failed'))}")

    @require_auth
    async def cmd_otp(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        args = context.args or []
        if not args:
            await self._reply(update, "usage: /otp &lt;code&gt;")
            return
        otp = args[0].strip()
        await self._reply(update, "verifying…")
        result = await orch.auth_verify_otp(otp)
        if result.get("ok"):
            await self._reply(
                update,
                f"✅ logged in.\n"
                f"• phone: {code(result.get('phone', '?'))}\n"
                f"• cookies: {code(result.get('cookies', 0))}\n"
                f"Session stored in vault.",
            )
        else:
            await self._reply(update, f"❌ {escape(result.get('message', 'failed'))}")

    @require_auth
    async def cmd_cookie(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        args = context.args or []
        if not args:
            await self._reply(
                update,
                "🍪 <b>Cookie login</b>\n\n"
                "Accepted formats:\n"
                "• <code>/cookie a=1; b=2</code>\n"
                "• <code>/cookie {\"a\":\"1\",\"b\":\"2\"}</code>\n"
                "• Netscape cookie file lines\n",
            )
            return
        raw = " ".join(args)
        await self._reply(update, "importing and validating…")
        result = await orch.auth_import_cookie(raw)
        if result.get("ok"):
            await self._reply(
                update,
                f"✅ cookies imported.\n"
                f"• count: {code(result.get('cookies', 0))}\n"
                f"• stored in vault.",
            )
        else:
            await self._reply(update, f"❌ {escape(result.get('message', 'failed'))}")

    @require_auth
    async def cmd_auth(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        status = await orch.auth_status()
        text = render_auth_status(status)
        if update.effective_message:
            await update.effective_message.reply_text(
                text, parse_mode=ParseMode.HTML,
                reply_markup=auth_keyboard(),
            )

    @require_auth
    async def cmd_rotate(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        await self._reply(update, "rotating fingerprint…")
        result = await orch.auth_rotate()
        if result.get("ok"):
            await self._reply(
                update,
                f"🔄 rotated.\n• cookies kept: {code(result.get('cookies', 0))}",
            )
        else:
            await self._reply(update, f"⚠️ {escape(result.get('message', 'failed'))}")

    @require_auth
    async def cmd_logout(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._reply(
            update,
            "⚠️ <b>Logout</b> clears cookies and deletes the stored session.\nConfirm?",
        )
        if update.effective_message:
            await update.effective_message.reply_text(
                "confirm:",
                reply_markup=confirm_keyboard("logout", "logout", "cancel"),
            )

    @require_auth
    async def cmd_restore(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        await self._reply(update, "restoring from vault…")
        result = await orch.auth_restore()
        if result.get("ok"):
            await self._reply(
                update,
                f"✅ restored.\n"
                f"• phone: {code(result.get('phone') or 'unknown')}\n"
                f"• cookies: {code(result.get('cookies', 0))}",
            )
        else:
            await self._reply(update, f"⚠️ {escape(result.get('message', 'no stored session'))}")

    # ==================================================================
    # tools
    # ==================================================================

    @require_auth
    async def cmd_download(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        args = context.args or []
        if len(args) < 2:
            await self._reply(
                update,
                "usage: /download &lt;manager&gt; &lt;package&gt; [binary]\n"
                "managers: apt-get pip pip3 go cargo npm git",
            )
            return
        manager, package = args[0], args[1]
        verify = args[2] if len(args) > 2 else None
        await self._reply(update, f"⬇ installing {code(f'{manager} {package}')}…")

        # find installer tool on any registered registry
        tool = None
        for agent in getattr(orch, "agents", {}).values():
            reg = getattr(agent, "registry", None)
            if reg:
                t = reg.get("install_tool")
                if t:
                    tool = t
                    break
        if tool is None:
            await self._reply(update, "⚠️ installer tool not enabled.")
            return

        result = await tool.safe_run(
            manager=manager, package=package, verify_binary=verify,
        )
        if result.ok:
            await self._reply(update, f"✅ installed.\n{escape((result.output or '')[-600:])}")
        else:
            await self._reply(update, f"❌ failed: {escape(result.error or '')}")

    # ==================================================================
    # info commands
    # ==================================================================

    @require_auth
    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        snap = await orch.status()
        await self._reply(update, render_status(snap))

    @require_auth
    async def cmd_usage(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        text = await orch.usage_report()
        await self._reply(update, text)

    @require_auth
    async def cmd_progress(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        text = await orch.progress_now()
        await self._reply(update, text)

    @require_auth
    async def cmd_findings(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        findings = await orch.blackboard.list_findings()
        payload = [f.model_dump(mode="json") for f in findings]
        await self._reply(update, render_findings_list(payload))

    @require_auth
    async def cmd_report(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        await self._reply(update, "building report…")
        report = await orch.full_report()
        # chunk into pre blocks
        max_len = 3500
        current = ""
        chunks: list[str] = []
        for line in report.splitlines():
            candidate = (current + "\n" + line) if current else line
            if len(candidate) > max_len:
                chunks.append(current)
                current = line
            else:
                current = candidate
        if current:
            chunks.append(current)
        for i, chunk in enumerate(chunks):
            header = (
                f"<b>report — part {i+1}/{len(chunks)}</b>\n"
                if len(chunks) > 1
                else ""
            )
            await self._reply(update, header + f"<pre>{escape(chunk)}</pre>")

    @require_auth
    async def cmd_target(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        text = await orch.target_info()
        await self._reply(update, text)

    @require_auth
    async def cmd_scope(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        lines = ["<b>Scope</b>", ""]
        for s in orch.config.target.scope:
            lines.append(f"• {code(s)}")
        await self._reply(update, "\n".join(lines))

    @require_auth
    async def cmd_model(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        text = await orch.model_info()
        await self._reply(update, text)

    # ==================================================================
    # control commands
    # ==================================================================

    @require_auth
    async def cmd_reason(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        args = context.args or []
        if not args:
            await self._reply(
                update,
                f"current: {code(orch._reasoning_level)}\nusage: /reason low|medium|high",
            )
            return
        level = args[0].lower()
        ok = await orch.set_reasoning(level)
        await self._reply(
            update,
            f"reasoning → {code(level)}" if ok else "⚠️ use low|medium|high",
        )

    @require_auth
    async def cmd_interval(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        args = context.args or []
        if not args:
            await self._reply(
                update,
                f"current: {code(str(orch._report_interval_minutes) + 'm')}\n"
                f"usage: /interval &lt;minutes&gt;",
            )
            return
        try:
            minutes = int(args[0])
        except ValueError:
            await self._reply(update, "⚠️ not a number")
            return
        ok = await orch.set_interval(minutes)
        await self._reply(
            update,
            f"interval → {code(str(minutes) + 'm')}" if ok
            else "⚠️ must be 1..1440",
        )

    @require_auth
    async def cmd_retest(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        orch = await self._require_orch(update)
        if orch is None:
            return
        args = context.args or []
        if not args:
            await self._reply(update, "usage: /retest &lt;finding_id&gt;")
            return
        fid = args[0]
        ok = await orch.retest_finding(fid)
        await self._reply(
            update,
            f"queued validation for {code(fid)}" if ok else "⚠️ finding not found",
        )

    @require_auth
    async def cmd_clear(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._reply(
            update,
            "⚠️ <b>Clear scan data</b>\nDeletes all findings and tasks.\nConfirm?",
        )
        if update.effective_message:
            await update.effective_message.reply_text(
                "confirm:",
                reply_markup=confirm_keyboard("clear", "clear data", "cancel"),
            )

    # ==================================================================
    # callbacks
    # ==================================================================

    async def on_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not is_authorized(update):
            return
        query = update.callback_query
        if query is None:
            return
        await query.answer()
        data = query.data or ""
        orch = self.orchestrator
        if orch is None:
            await query.edit_message_text("orchestrator not attached.")
            return

        # destructive
        if data == "confirm:emergency":
            await query.edit_message_text("🛑 emergency stop issued.")
            await orch.emergency()
            return
        if data == "cancel:emergency":
            await query.edit_message_text("cancelled.")
            return
        if data == "confirm:clear":
            await query.edit_message_text("clearing…")
            ok = await orch.clear_data()
            await query.edit_message_text("🧹 cleared." if ok else "⚠️ clear failed")
            return
        if data == "cancel:clear":
            await query.edit_message_text("cancelled.")
            return
        if data == "confirm:logout":
            await query.edit_message_text("logging out…")
            result = await orch.auth_logout()
            if result.get("ok"):
                await query.edit_message_text("🚪 logged out. vault cleared.")
            else:
                await query.edit_message_text(f"⚠️ {result.get('message', 'failed')}")
            return
        if data == "cancel:logout":
            await query.edit_message_text("cancelled.")
            return

        # control panel
        if data.startswith("ctl:"):
            action = data.split(":", 1)[1]
            if action == "resume":
                await orch.resume()
                await query.edit_message_text("▶ resumed.")
            elif action == "pause":
                await orch.pause()
                await query.edit_message_text("⏸ paused.")
            elif action == "status":
                snap = await orch.status()
                await query.edit_message_text(
                    render_status(snap), parse_mode=ParseMode.HTML,
                )
            elif action == "progress":
                txt = await orch.progress_now()
                await query.edit_message_text(txt, parse_mode=ParseMode.HTML)
            elif action == "stop_confirm":
                await query.edit_message_text(
                    "confirm stop?",
                    reply_markup=confirm_keyboard("emergency", "stop now", "cancel"),
                )
            return

        # auth panel
        if data.startswith("auth:"):
            action = data.split(":", 1)[1]
            if action == "check":
                await query.edit_message_text("checking…")
                result = await orch.auth_check()
                await query.edit_message_text(
                    f"{'🟢 ok' if result.get('ok') else '🔴 ' + result.get('message', 'failed')}\n"
                    f"cookies: {result.get('cookies', 0)}"
                )
            elif action == "rotate":
                await query.edit_message_text("rotating…")
                result = await orch.auth_rotate()
                await query.edit_message_text(
                    "🔄 rotated." if result.get("ok") else "⚠️ failed"
                )
            elif action == "logout_confirm":
                await query.edit_message_text(
                    "confirm logout?",
                    reply_markup=confirm_keyboard("logout", "logout", "cancel"),
                )
            return

    # ==================================================================
    # free text → decision-maker
    # ==================================================================

    async def on_free_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not is_authorized(update):
            return
        if update.effective_message is None:
            return
        text = (update.effective_message.text or "").strip()
        if not text:
            return
        orch = self.orchestrator
        if orch is None:
            await self._reply(update, "<i>orchestrator not attached.</i>")
            return
        if text.startswith("/"):
            await self._reply(update, "unknown command. /start for help.")
            return
        await self._reply(update, "📨 sending to decision-maker…")
        await orch.ask_decision(text)
