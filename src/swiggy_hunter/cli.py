"""
CLI: swiggy-hunter run | status | report | version
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="swiggy-hunter",
        description="Autonomous stealth scanner for swiggy.com",
    )
    p.add_argument("--version", action="version",
                   version=f"swiggy-hunter {__version__}")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--no-bot", action="store_true")
    sub = p.add_subparsers(dest="command", required=False)
    sub.add_parser("run")
    sub.add_parser("status")
    sub.add_parser("report")
    sub.add_parser("version")
    return p


async def _run(args: argparse.Namespace) -> int:
    from .main import run_runtime
    return await run_runtime(config_path=args.config, no_bot=args.no_bot)


async def _status(args: argparse.Namespace) -> int:
    from .main import print_status
    return await print_status(config_path=args.config)


async def _report(args: argparse.Namespace) -> int:
    from .main import print_report
    return await print_report(config_path=args.config)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.command or "run"
    if cmd == "version":
        print(f"swiggy-hunter {__version__}")
        return 0
    if cmd == "run":
        return asyncio.run(_run(args))
    if cmd == "status":
        return asyncio.run(_status(args))
    if cmd == "report":
        return asyncio.run(_report(args))
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
