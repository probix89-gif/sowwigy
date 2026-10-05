from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from swiggy_hunter.config import (
    AppConfig,
    AuthCfg,
    BudgetCfg,
    BrowserCfg,
    ModelCfg,
    PathsCfg,
    RateLimitCfg,
    ReporterCfg,
    Secrets,
    StealthCfg,
    TargetCfg,
    ToolsAutoloadCfg,
)
from swiggy_hunter.state.blackboard import Blackboard


@pytest.fixture
def tmp_config(tmp_path: Path) -> AppConfig:
    cfg = AppConfig(
        model=ModelCfg(name="test", base_url="http://localhost:1"),
        rate_limit=RateLimitCfg(requests_per_minute=1000, safety_margin=1, max_concurrent=5),
        budget=BudgetCfg(daily_token_limit=1_000_000, warn_at_percent=80),
        reporter=ReporterCfg(interval_minutes=30),
        target=TargetCfg(domain="example.com", scope=["example.com", "*.example.com"]),
        stealth=StealthCfg(),
        auth=AuthCfg(),
        browser=BrowserCfg(enabled=False),
        tools_autoload=ToolsAutoloadCfg(),
        paths=PathsCfg(
            data_dir=str(tmp_path / "data"),
            log_dir=str(tmp_path / "logs"),
            blackboard=str(tmp_path / "data" / "state.md"),
            findings=str(tmp_path / "data" / "findings.json"),
            usage=str(tmp_path / "data" / "usage.json"),
            directives=str(tmp_path / "data" / "directives.jsonl"),
        ),
    )
    cfg.secrets = Secrets(
        glm_api_key="test",
        glm_base_url="http://localhost:1",
        telegram_bot_token="",
        telegram_chat_id="",
    )
    return cfg


@pytest.fixture
async def blackboard(tmp_path: Path) -> Blackboard:
    bb = Blackboard(tmp_path / "state.md")
    await bb.load()
    return bb
