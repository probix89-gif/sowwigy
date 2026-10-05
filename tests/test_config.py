from __future__ import annotations

from pathlib import Path
import pytest
import yaml

from swiggy_hunter.config import load_config, AppConfig, Secrets

def test_config_yaml_syntax():
    """Verify that root config.yaml is valid YAML and business_logic parses as a dict."""
    config_file = Path("config.yaml")
    assert config_file.exists()
    data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    assert "agents" in data
    assert "business_logic" in data["agents"]
    assert isinstance(data["agents"]["business_logic"], dict)
    assert data["agents"]["business_logic"]["temperature"] == 0.55

def test_load_config_default():
    """Verify load_config works without errors when Secrets are initialized."""
    cfg = load_config("config.yaml")
    assert isinstance(cfg, AppConfig)
    assert cfg.target.domain == "swiggy.com"
    assert cfg.secrets is not None
    assert isinstance(cfg.secrets.glm_api_key, str)
