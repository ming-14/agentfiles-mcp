"""Version receipts: remember the last observed file version per path.

The table is what enforces "read before you write": a write/edit call attaches
the receipt it holds, and the server verifies it against the live fstat. No
receipt -> the server answers version_missing -> the model must read first.

Process-local, LRU-bounded, never persisted: a restart fails closed (re-read),
and stale entries are rejected by the server anyway, so eviction is harmless.
"""

from __future__ import annotations

import os
from collections import OrderedDict

from agentfiles_shared.schema import Version

MAX_RECEIPTS = 512


def _key(path: str) -> str:
    normalized = path.replace("\\", "/")
    return normalized.lower() if os.name == "nt" else normalized


class ReceiptBook:
    def __init__(self, max_entries: int = MAX_RECEIPTS) -> None:
        self._max = max_entries
        self._entries: OrderedDict[str, dict] = OrderedDict()

    def remember(self, version: Version | dict) -> None:
        data = version.model_dump(by_alias=True) if isinstance(version, Version) else dict(version)
        if not data.get("path"):
            return
        self._store(data["path"], data)

    def remember_for(self, request_path: str, version: dict) -> None:
        """Key the receipt by the path the model used, not the server's."""
        if not version.get("path"):
            return
        self._store(request_path, dict(version))

    def _store(self, key_path: str, data: dict) -> None:
        key = _key(key_path)
        self._entries[key] = data
        self._entries.move_to_end(key)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def lookup(self, path: str) -> dict | None:
        return self._entries.get(_key(path))

    def forget(self, path: str) -> None:
        self._entries.pop(_key(path), None)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


def record_result(book: ReceiptBook, request_path: str, result: dict) -> None:
    """Store the version a successful read/write/edit just returned.

    Keyed by ``request_path`` (how the model referred to the file) so a later
    write using the same spelling finds its receipt, even when the model sent
    a relative path and the server answered with an absolute one.
    """
    version = result.get("version")
    if isinstance(version, dict) and version.get("path") and request_path:
        book.remember_for(request_path, version)
