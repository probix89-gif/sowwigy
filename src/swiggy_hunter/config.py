"""
Pydantic config models. Every field has a default so partial configs work.

The full config is loaded from `config.yaml`, then Secrets are injected
from `.env` via pydantic-settings.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# ==========================================================================
# sub-models
# ==========================================================================

class ThinkingWindowCfg(BaseModel):
    enabled: bool = True
    min_seconds: float = 12.0
    max_seconds: float = 32.0
    agents: list[str] = Field(default_factory=lambda: ["decision", "attacker"])


class ModelCfg(BaseModel):
    name: str = "GLM-5.3-Flash"
    base_url: str = "https://top-tools-ai.com/v1"
    max_output_tokens: int = 16384
    default_temperature: float = 0.6
    thinking_window: ThinkingWindowCfg = Field(default_factory=ThinkingWindowCfg)


class RateLimitCfg(BaseModel):
    requests_per_minute: int = 45
    safety_margin: int = 1
    max_concurrent: int = 4


class BudgetCfg(BaseModel):
    daily_token_limit: int = 1_000_000_000
    warn_at_percent: int = 85


class ReporterCfg(BaseModel):
    interval_minutes: int = 30


class TargetCfg(BaseModel):
    domain: str = "swiggy.com"
    scope: list[str] = Field(default_factory=lambda: ["swiggy.com", "*.swiggy.com"])


class HumanTimingCfg(BaseModel):
    enabled: bool = True
    base_delay_ms: int = 350
    jitter_ms: int = 700
    think_pauses_prob: float = 0.18
    think_pause_min_s: float = 1.4
    think_pause_max_s: float = 4.8
    burst_pause_prob: float = 0.08
    burst_pause_min_s: float = 6.0
    burst_pause_max_s: float = 22.0


class StealthCfg(BaseModel):
    enabled: bool = True
    impersonate: list[str] = Field(
        default_factory=lambda: ["chrome124", "chrome125", "chrome126"]
    )
    rotate_fingerprint_per_session: bool = True
    human_timing: HumanTimingCfg = Field(default_factory=HumanTimingCfg)
    referer_chain: bool = True
    respect_robots: bool = False
    honor_retry_after: bool = True
    tls_impersonation: bool = True
    header_randomization: bool = True


class OtpAuthCfg(BaseModel):
    enabled: bool = True
    send_endpoint: str = "https://www.swiggy.com/api/auth/send-otp"
    verify_endpoint: str = "https://www.swiggy.com/api/auth/verify-otp"
    resend_cooldown_s: int = 45
    phone_field: str = "mobile"
    otp_field: str = "otp"


class CookieAuthCfg(BaseModel):
    enabled: bool = True


class VaultCfg(BaseModel):
    enabled: bool = True
    cipher: str = "fernet"


class AuthCfg(BaseModel):
    otp: OtpAuthCfg = Field(default_factory=OtpAuthCfg)
    cookie: CookieAuthCfg = Field(default_factory=CookieAuthCfg)
    vault: VaultCfg = Field(default_factory=VaultCfg)


class ViewportCfg(BaseModel):
    width: int = 1366
    height: int = 800


class BrowserCfg(BaseModel):
    enabled: bool = True
    engine: str = "playwright"
    headless: bool = True
    timezone: str = "Asia/Kolkata"
    locale: str = "en-IN"
    viewport: ViewportCfg = Field(default_factory=ViewportCfg)
    user_data_dir: str = "./data/browser_profile"


class ToolsAutoloadCfg(BaseModel):
    auto_install: bool = True
    allowed_installers: list[str] = Field(
        default_factory=lambda: ["apt-get", "pip", "pip3", "go", "cargo", "npm", "git"]
    )
    prefer_binaries: list[str] = Field(default_factory=list)


class AgentTuningCfg(BaseModel):
    temperature: float = 0.5
    max_iterations: int = 30


class PathsCfg(BaseModel):
    data_dir: str = "./data"
    log_dir: str = "./logs"
    blackboard: str = "./data/state.md"
    findings: str = "./data/findings.json"
    usage: str = "./data/usage.json"
    directives: str = "./data/directives.jsonl"


# ==========================================================================
# secrets
# ==========================================================================

class Secrets(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    glm_api_key: str = ""
    glm_base_url: str = "https://top-tools-ai.com/v1"
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    swiggy_phone: str = ""
    swiggy_cookie: str = ""
    swiggy_session_vault_key: str = ""


# ==========================================================================
# root
# ==========================================================================

class AppConfig(BaseModel):
    model: ModelCfg = Field(default_factory=ModelCfg)
    rate_limit: RateLimitCfg = Field(default_factory=RateLimitCfg)
    budget: BudgetCfg = Field(default_factory=BudgetCfg)
    reporter: ReporterCfg = Field(default_factory=ReporterCfg)
    target: TargetCfg = Field(default_factory=TargetCfg)
    stealth: StealthCfg = Field(default_factory=StealthCfg)
    auth: AuthCfg = Field(default_factory=AuthCfg)
    browser: BrowserCfg = Field(default_factory=BrowserCfg)
    tools_autoload: ToolsAutoloadCfg = Field(default_factory=ToolsAutoloadCfg)
    paths: PathsCfg = Field(default_factory=PathsCfg)
    agents: dict[str, AgentTuningCfg] = Field(default_factory=dict)
    autostart: bool = True

    secrets: Secrets | None = None


def load_config(path: str | Path = "config.yaml") -> AppConfig:
    p = Path(path)
    raw: dict[str, Any] = {}
    if p.exists():
        with p.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

    cfg = AppConfig(**raw)
    cfg.secrets = Secrets()

    # fallback: env override for base_url if set
    if cfg.secrets.glm_base_url:
        cfg.model.base_url = cfg.secrets.glm_base_url

    Path(cfg.paths.data_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.paths.log_dir).mkdir(parents=True, exist_ok=True)

    return cfg
