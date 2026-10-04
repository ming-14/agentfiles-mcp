"""Server configuration from environment variables.

AF_WORKSPACE           root directory the server may touch (mandatory)
AF_TOKENS              JSON object mapping bearer token -> HMAC secret (mandatory)
AF_ADDR                 listen address, default 127.0.0.1:8443
AF_TLS_CERT             path to PEM cert   (TLS termination can also be delegated to a proxy)
AF_TLS_KEY              path to PEM key
AF_MAX_SKEW             signature timestamp window in seconds, default 300
AF_EXTERNAL_WHITELIST   JSON array of directories allowed outside the workspace
                        (default []: everything outside the workspace is rejected)
AF_READ_DENY            JSON array of wildcard patterns that may never be read
                        (default ["*.env", "*.env.*"])
AF_WRITE_DENY           JSON array of wildcard patterns that may never be
                        written/edited (default ["*.env", "*.env.*"])
AF_TRANSPORT_MAX        max bytes for a single file transport, default 100MB
AF_BODY_MAX             max bytes for a single request body, default 8MB
                        (a larger body is refused before it is buffered)
AF_RIPGREP_PATH         path to the rg binary (default: search PATH)
AF_RG_TIMEOUT           seconds a single ripgrep run may take end to end
                        (reading its output and waiting for it to exit), default 30
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field

from agentfiles_shared.auth import DEFAULT_MAX_SKEW
from agentfiles_shared.transport import DEFAULT_TRANSPORT_MAX_BYTES

DEFAULT_READ_DENY = ["*.env", "*.env.*"]
# A tool call carries JSON arguments, not file contents: write is the only
# body that can be big, and anything a model can produce fits in here.
DEFAULT_BODY_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_RG_TIMEOUT = 30.0


class ConfigError(Exception):
    pass


def _number(name: str, default: str, cast: Callable[[str], float]) -> float:
    raw = os.environ.get(name, "").strip() or default
    try:
        value = cast(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be greater than 0")
    return value


def _json_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return list(default)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{name} is not valid JSON: {exc}") from exc
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{name} must be a JSON array of strings")
    return value


@dataclass(frozen=True)
class Config:
    workspace: str
    tokens: dict[str, str] = field(default_factory=dict)
    addr: str = "127.0.0.1:8443"
    tls_cert: str | None = None
    tls_key: str | None = None
    max_skew: int = DEFAULT_MAX_SKEW
    external_whitelist: list[str] = field(default_factory=list)
    read_deny: list[str] = field(default_factory=lambda: list(DEFAULT_READ_DENY))
    write_deny: list[str] = field(default_factory=lambda: list(DEFAULT_READ_DENY))
    transport_max: int = DEFAULT_TRANSPORT_MAX_BYTES
    max_body_bytes: int = DEFAULT_BODY_MAX_BYTES
    ripgrep_path: str | None = None
    rg_timeout: float = DEFAULT_RG_TIMEOUT

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
        max_skew=int(_number("AF_MAX_SKEW", str(DEFAULT_MAX_SKEW), int)),
        external_whitelist=[
            os.path.abspath(p) for p in _json_list("AF_EXTERNAL_WHITELIST", [])
        ],
        read_deny=_json_list("AF_READ_DENY", DEFAULT_READ_DENY),
        write_deny=_json_list("AF_WRITE_DENY", DEFAULT_READ_DENY),
        transport_max=int(
            _number("AF_TRANSPORT_MAX", str(DEFAULT_TRANSPORT_MAX_BYTES), int)
        ),
        max_body_bytes=int(
            _number("AF_BODY_MAX", str(DEFAULT_BODY_MAX_BYTES), int)
        ),
        ripgrep_path=os.environ.get("AF_RIPGREP_PATH") or None,
        rg_timeout=_number("AF_RG_TIMEOUT", str(DEFAULT_RG_TIMEOUT), float),
    )
