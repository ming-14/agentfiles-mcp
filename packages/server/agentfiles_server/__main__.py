"""Entry point: ``python -m agentfiles_server`` (env-driven, see config.py)."""

from __future__ import annotations

import uvicorn

from .app import create_app
from .config import load


def main() -> None:
    config = load()
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
