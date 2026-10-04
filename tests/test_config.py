"""Server configuration: environment parsing."""

from __future__ import annotations

import json

import pytest

from agentfiles_server.config import (
    DEFAULT_BODY_MAX_BYTES,
    Config,
    ConfigError,
    load,
)


def _base_env(monkeypatch, workspace) -> None:
    monkeypatch.setenv("AF_WORKSPACE", str(workspace))
    monkeypatch.setenv("AF_TOKENS", json.dumps({"tok": "sec"}))
    monkeypatch.delenv("AF_BODY_MAX", raising=False)


def test_body_max_default_is_8mb():
    assert DEFAULT_BODY_MAX_BYTES == 8 * 1024 * 1024
    assert Config(workspace="ws").max_body_bytes == DEFAULT_BODY_MAX_BYTES


def test_body_max_comes_from_the_environment(tmp_path, monkeypatch):
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AF_BODY_MAX", "12345")
    assert load().max_body_bytes == 12345


def test_body_max_falls_back_to_the_default(tmp_path, monkeypatch):
    _base_env(monkeypatch, tmp_path)
    assert load().max_body_bytes == DEFAULT_BODY_MAX_BYTES


def test_rg_timeout_default_and_env(tmp_path, monkeypatch):
    _base_env(monkeypatch, tmp_path)
    assert load().rg_timeout == 30.0
    monkeypatch.setenv("AF_RG_TIMEOUT", "2.5")
    assert load().rg_timeout == 2.5


@pytest.mark.parametrize("value", ["soon", "0", "-1"])
def test_a_bad_number_is_a_config_error(tmp_path, monkeypatch, value):
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AF_RG_TIMEOUT", value)
    with pytest.raises(ConfigError):
        load()
