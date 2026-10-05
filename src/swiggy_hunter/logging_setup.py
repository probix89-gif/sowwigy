"""
Structured logging. Console = pretty, file = JSONL.
Every event carries a `component` field for filtering.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import structlog


_CONFIGURED = False


def _add_component(_, __, event_dict: dict[str, Any]) -> dict[str, Any]:
    if "component" not in event_dict:
        logger_name = event_dict.get("logger", "")
        event_dict["component"] = logger_name.split(".")[-1] if logger_name else "root"
    return event_dict


def setup_logging(
    log_dir: str | Path = "./logs",
    level: str = "INFO",
    json_file: bool = True,
) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    if json_file:
        file_path = Path(log_dir) / "swiggy_hunter.jsonl"
        fh = logging.FileHandler(file_path, encoding="utf-8")
        fh.setLevel(log_level)
        fh.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger().addHandler(fh)

    shared = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        _add_component,
    ]

    structlog.configure(
        processors=shared + [  # type: ignore[arg-type]
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty()),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    _CONFIGURED = True


def get_logger(name: str):
    return structlog.get_logger(name)
