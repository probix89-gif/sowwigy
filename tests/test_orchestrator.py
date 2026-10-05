from __future__ import annotations

from pathlib import Path
import pytest
import yaml

from swiggy_hunter.config import (
    AppConfig, AuthCfg, BudgetCfg, BrowserCfg, ModelCfg, PathsCfg,
    RateLimitCfg, ReporterCfg, Secrets, StealthCfg, TargetCfg, ToolsAutoloadCfg
)
from swiggy_hunter.orchestrator import Orchestrator

@pytest.mark.asyncio
async def test_orchestrator_usage_report(tmp_path: Path):
    cfg = AppConfig(
        model=ModelCfg(name="GLM-5.3-Flash", base_url="http://localhost:1"),
        rate_limit=RateLimitCfg(requests_per_minute=45, safety_margin=1, max_concurrent=4),
        budget=BudgetCfg(daily_token_limit=1_000_000, warn_at_percent=80),
        reporter=ReporterCfg(interval_minutes=30),
        target=TargetCfg(domain="swiggy.com", scope=["swiggy.com", "*.swiggy.com"]),
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
    
    test_yaml_path = tmp_path / "config.yaml"
    with test_yaml_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg.model_dump(exclude={"secrets"}), f)

    orch = Orchestrator(config_path=test_yaml_path)
    await orch.boot()

    # Verify status
    status = await orch.status()
    assert status["target"] == "swiggy.com"
    assert status["lifecycle"]["state"] == "idle"

    # Verify usage_report does not throw NameError for time
    report = await orch.usage_report()
    assert "Token usage" in report
    assert "Total today" in report

    # Verify full_report
    full = await orch.full_report()
    assert "Full Report" in full and "## Summary" in full

    await orch.stop()
