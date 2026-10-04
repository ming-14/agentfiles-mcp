"""Entry point: ``python -m agentfiles_server`` (env-driven, see config.py)."""

from __future__ import annotations

import sys

import uvicorn

from . import rg
from .app import create_app
from .config import Config, load


def _warn_on_broken_deny_globs(config: Config) -> None:
    """A deny glob rg cannot parse makes every search come back empty."""
    try:
        binary = rg.find_binary(config.ripgrep_path)
        complaint = rg.validate_deny_globs(binary, config.read_deny)
    except (rg.ToolError, rg.InvalidPattern):
        # the probe is best effort: both surface on the search call itself
        return
    if complaint:
        print(
            f"warning: AF_READ_DENY glob rejected by ripgrep ({complaint}); "
            "every search will return nothing until it is fixed",
            file=sys.stderr,
        )


def main() -> None:
    config = load()
    _warn_on_broken_deny_globs(config)
    host, _, port = config.addr.partition(":")
    uvicorn.run(
        create_app(config),
        host=host or "127.0.0.1",
        port=int(port or "8443"),
        ssl_certfile=config.tls_cert,
        ssl_keyfile=config.tls_key,
    )


if __name__ == "__main__":
    main()
