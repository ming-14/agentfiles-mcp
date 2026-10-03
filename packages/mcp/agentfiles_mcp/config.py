"""Client configuration from environment variables.

AF_URL      base URL of agentfiles-server, e.g. https://files.example.com
AF_TOKEN    bearer token
AF_SECRET   HMAC secret for AF_TOKEN
AF_TIMEOUT  request timeout in seconds (default 30)
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    url: str
    token: str
    secret: str
    timeout: float = 30.0


def load() -> Config:
    url = os.environ.get("AF_URL", "").strip().rstrip("/")
    token = os.environ.get("AF_TOKEN", "").strip()
    secret = os.environ.get("AF_SECRET", "").strip()
    missing = [
        name
        for name, value in (("AF_URL", url), ("AF_TOKEN", token), ("AF_SECRET", secret))
        if not value
    ]
    if missing:
        raise ConfigError(f"Missing environment variables: {', '.join(missing)}")
    if not url.startswith(("http://", "https://")):
        raise ConfigError("AF_URL must start with http:// or https://")
    return Config(
        url=url,
        token=token,
        secret=secret,
        timeout=float(os.environ.get("AF_TIMEOUT", "30")),
    )
