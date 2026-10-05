"""
Entrypoint. Boots runtime, orchestrator, telegram, wires everything,
blocks until stop, shuts down cleanly.
"""
from __future__ import annotations

import asyncio
import signal
import sys

from .config import load_config
from .logging_setup import get_logger, setup_logging
from .orchestrator import Orchestrator
from .orchestrator_patch import attach_runtime
from .runtime import Runtime
from .scheduler.report_builder import ReportBuilder

log = get_logger(__name__)


async def _make_bot(cfg):
    token = cfg.secrets.telegram_bot_token if cfg.secrets else ""
    if not token:
        log.warning("main.no_telegram_token")
        return None
    from .telegram import TelegramBot
    bot = TelegramBot(token=token, chat_id=cfg.secrets.telegram_chat_id or None)
    await bot.build()
    return bot


async def run_runtime(config_path: str = "config.yaml", no_bot: bool = False) -> int:
    setup_logging()
    cfg = load_config(config_path)
    log.info("main.boot", target=cfg.target.domain, model=cfg.model.name)

    runtime = Runtime(cfg)
    log.info("main.runtime_ready", **runtime.describe())

    bot = None
    report_sender = None
    if not no_bot:
        bot = await _make_bot(cfg)
        if bot is not None and bot.notifier is not None:
            report_sender = bot.notifier.send

    orch = Orchestrator(config_path=config_path, report_sender=report_sender)
    await orch.boot()
    attach_runtime(orch, runtime)

    if bot is not None:
        bot.set_orchestrator(orch)
        await bot.start()

    loop = asyncio.get_running_loop()
    stop_signal = asyncio.Event()

    def _on_signal(sig):
        log.info("main.signal", sig=sig)
        stop_signal.set()

    for sig_name in ("SIGINT", "SIGTERM"):
        try:
            loop.add_signal_handler(getattr(signal, sig_name), _on_signal, sig_name)
        except NotImplementedError:
            pass

    autostart = cfg.autostart
    if autostart:
        await orch.start()
        log.info("main.runtime_started")
    else:
        log.info("main.runtime_idle_awaiting_command")

    try:
        while not stop_signal.is_set():
            if orch.lifecycle.stop_event.is_set():
                break
            await asyncio.sleep(1.0)
    finally:
        log.info("main.shutting_down")
        await orch.stop()
        if bot is not None:
            await bot.stop()
        await runtime.shutdown()
        log.info("main.shutdown_complete")

    return 0


async def print_status(config_path: str = "config.yaml") -> int:
    setup_logging(level="WARNING")
    cfg = load_config(config_path)
    orch = Orchestrator(config_path=config_path)
    await orch.boot()
    snap = await orch.status()
    import json
    print(json.dumps(snap, indent=2, default=str))
    return 0


async def print_report(config_path: str = "config.yaml") -> int:
    setup_logging(level="WARNING")
    cfg = load_config(config_path)
    orch = Orchestrator(config_path=config_path)
    await orch.boot()
    builder = ReportBuilder(orch.blackboard)
    print(await builder.full_report())
    return 0


def main() -> int:
    from .cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
