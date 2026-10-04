"""Version receipts: remember the last observed file version per (cwd, path).

The table is what enforces "read before you write": a write/edit call attaches
the receipt it holds, and the server verifies it against the live fstat. No
receipt -> the server answers version_missing -> the model must read first.

Keyed by cwd *and* path: the same relative spelling means different files
after set_cwd, so a receipt must not follow the path across a cwd switch (the
old entry stays until LRU evicts it; a wrong match would fail server-side
anyway, because the version's own path is compared -- fail-closed).

Process-local, LRU-bounded, never persisted: a restart fails closed (re-read),
and stale entries are rejected by the server anyway, so eviction is harmless.
"""

from __future__ import annotations

import os
from collections import OrderedDict

from agentfiles_shared.schema import Version

MAX_RECEIPTS = 512


def _key(cwd: str | None, path: str) -> str:
    normalized = path.replace("\\", "/")
    if os.name == "nt":
        normalized = normalized.lower()
    base = (cwd or "").replace("\\", "/")
    if os.name == "nt":
        base = base.lower()
    return f"{base}\n{normalized}" if base else normalized


class ReceiptBook:
    def __init__(self, max_entries: int = MAX_RECEIPTS) -> None:
        self._max = max_entries
        self._entries: OrderedDict[str, dict] = OrderedDict()

    def remember(self, version: Version | dict) -> None:
        data = version.model_dump(by_alias=True) if isinstance(version, Version) else dict(version)
        if not data.get("path"):
            return
        # keyed by the server's own view of the file (no cwd known here)
        self._store(_key(None, data["path"]), data)

    def remember_for(self, request_path: str, version: dict, cwd: str | None = None) -> None:
        """Key the receipt by the (cwd, path) the model used, not the server's."""
        if not version.get("path"):
            return
        self._store(_key(cwd, request_path), dict(version))

    def _store(self, key: str, data: dict) -> None:
        self._entries[key] = data
        self._entries.move_to_end(key)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def lookup(self, path: str, cwd: str | None = None) -> dict | None:
        return self._entries.get(_key(cwd, path))

    def forget(self, path: str, cwd: str | None = None) -> None:
        self._entries.pop(_key(cwd, path), None)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


def record_result(book: ReceiptBook, request_path: str, result: dict,
                  cwd: str | None = None) -> None:
    """Store the version a successful read/write/edit just returned.

    Keyed by ``(cwd, request_path)`` (how the model referred to the file) so a
    later write using the same spelling under the same cwd finds its receipt,
    even when the model sent a relative path and the server answered with an
    absolute one.
    """
    version = result.get("version")
    if isinstance(version, dict) and version.get("path") and request_path:
        book.remember_for(request_path, version, cwd)
