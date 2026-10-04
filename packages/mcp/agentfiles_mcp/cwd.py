"""Per-process working directory for the MCP proxy.

State, not security: this is only the base for resolving relative paths, and
the server re-verifies every file that results from it against its own
handle. Starting empty is deliberate -- a relative path with no cwd is
rejected with ``cwd_not_set`` instead of silently resolving against some
arbitrary default. Changing the cwd does not move files: it changes what
"src/a.ts" means on the *next* call.
"""

from __future__ import annotations

_cwd: str | None = None


def get() -> str | None:
    return _cwd


def set(value: str) -> str:
    global _cwd
    _cwd = value
    return value


def clear() -> None:
    global _cwd
    _cwd = None


def describe() -> str:
    if _cwd is None:
        return "Working directory: not set. Use set_cwd before relative paths."
    return f"Working directory: {_cwd}"
