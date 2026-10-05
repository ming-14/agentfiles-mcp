"""``agentfiles-mcp`` entry point: run the stdio MCP server."""

from __future__ import annotations

import logging

from .server import mcp

# stderr is the proxy's only log sink, and an undrained pipe wedges the process
# once it fills. Set before run(): configure_logging() only touches the root.
_QUIET_LOGGERS = ("mcp", "httpx")


def main() -> None:
    for name in _QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
