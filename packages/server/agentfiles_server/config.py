"""Server configuration from environment variables.

AF_WORKSPACE      root directory the server may touch (mandatory)
AF_TOKENS         JSON object mapping bearer token -> HMAC secret (mandatory)
AF_ADDR           listen address, default 127.0.0.1:8443
AF_TLS_CERT       path to PEM cert   (TLS termination can also be delegated to a proxy)
AF_TLS_KEY        path to PEM key
AF_MAX_SKEW       signature timestamp window in seconds, default 300
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from agentfiles_shared.auth import DEFAULT_MAX_SKEW


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    workspace: str
    tokens: dict[str, str] = field(default_factory=dict)
    addr: str = "127.0.0.1:8443"
    tls_cert: str | None = None
    tls_key: str | None = None
    max_skew: int = DEFAULT_MAX_SKEW

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_cert and self.tls_key)


def load() -> Config:
    workspace = os.environ.get("AF_WORKSPACE", "").strip()
    if not workspace:
        raise ConfigError("AF_WORKSPACE is not set")

    raw = os.environ.get("AF_TOKENS", "").strip()
    if not raw:
        raise ConfigError("AF_TOKENS is not set (JSON: {token: secret})")
    try:
        tokens = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"AF_TOKENS is not valid JSON: {exc}") from exc
    if not isinstance(tokens, dict) or not tokens:
        raise ConfigError("AF_TOKENS must be a non-empty JSON object")
    for token, secret in tokens.items():
        if not isinstance(token, str) or not isinstance(secret, str) or not secret:
            raise ConfigError("AF_TOKENS entries must be non-empty strings")

    return Config(
        workspace=os.path.abspath(workspace),
        tokens=tokens,
        addr=os.environ.get("AF_ADDR", "127.0.0.1:8443"),
        tls_cert=os.environ.get("AF_TLS_CERT") or None,
        tls_key=os.environ.get("AF_TLS_KEY") or None,
        max_skew=int(os.environ.get("AF_MAX_SKEW", DEFAULT_MAX_SKEW)),
    )
