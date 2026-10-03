"""Strict-mode file mutation primitives.

Guarantees (the "strict" in strict mode):
  * version verification and the subsequent write happen through the SAME
    open file handle -- never a second open by path -- so a file swapped at
    the path between check and write cannot receive the payload
  * edit re-stats (fstat) after reading, so a change landing mid-read is
    caught before any matching happens
  * version markers come from fstat(st_mtime_ns, st_size), integer nanoseconds

Locks are per-canonical-path and process-local, mirroring V2's KeyedMutex.
Handlers run in a threadpool, so these are threading.Lock, not asyncio.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass

from agentfiles_shared.errors import ToolError, version_mismatch_edit, \
    version_mismatch_write, version_missing_edit, version_missing_write
from agentfiles_shared.schema import Version

# O_BINARY matters on Windows: without it, \n <-> \r\n translation corrupts bytes.
_O_BINARY = getattr(os, "O_BINARY", 0)

_locks_guard = threading.Lock()
_locks: dict[str, threading.Lock] = {}


def target_lock(canonical: str) -> threading.Lock:
    key = canonical.replace("\\", "/").lower() if os.name == "nt" else canonical
    with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = _locks[key] = threading.Lock()
        return lock


@dataclass
class VersionedFile:
    """An open, version-verified file. All IO goes through ``fd``."""

    fd: int
    canonical: str
    content: bytes
    had_bom: bool

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def split_bom(data: bytes) -> tuple[bool, bytes]:
    """Strip any run of leading BOMs; V2 writes exactly one back."""
    stripped = data.lstrip(b"\xef\xbb\xbf")
    had = len(stripped) != len(data)
    return had, stripped


def join_bom(text: bytes, had_bom: bool) -> bytes:
    body = text.lstrip(b"\xef\xbb\xbf")
    return (b"\xef\xbb\xbf" + body) if had_bom else body


def version_of(fd: int, canonical: str) -> Version:
    stat = os.fstat(fd)
    return Version(mtime_ns=stat.st_mtime_ns, size=stat.st_size, path=canonical)


def _same_path(a: str, b: str) -> bool:
    norm = (lambda p: p.replace("\\", "/").lower()) if os.name == "nt" else \
           (lambda p: p.replace("\\", "/"))
    return norm(a) == norm(b)


def _verify(stat: os.stat_result, expected: Version, canonical: str, on_mismatch) -> None:
    # path first: a marker for another file is a mismatch even if size matches
    if not _same_path(expected.path, canonical):
        raise on_mismatch
    if stat.st_mtime_ns != expected.mtime_ns or stat.st_size != expected.size:
        raise on_mismatch


def open_verified(
    canonical: str,
    expected: Version | None,
    *,
    on_missing,
    on_mismatch,
    create: bool,
) -> VersionedFile | None:
    """Open and verify ``canonical``; return None when the caller may create it.

    create=True (write tool only): an absent file with no expected version
    yields None so the caller can do an O_EXCL create.
    """
    try:
        fd = os.open(canonical, os.O_RDWR | _O_BINARY)
    except FileNotFoundError:
        if expected is not None:
            raise on_mismatch from None
        if create:
            return None
        raise on_missing from None
    except IsADirectoryError:
        raise on_missing from None

    try:
        if expected is None:
            # file exists but the client never read it
            raise on_missing
        _verify(os.fstat(fd), expected, canonical, on_mismatch)
        content = _read_all(fd)
        had_bom, _ = split_bom(content)
        return VersionedFile(fd=fd, canonical=canonical, content=content, had_bom=had_bom)
    except BaseException:
        os.close(fd)
        raise


def _read_all(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 64 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def refstat(handle: VersionedFile) -> os.stat_result:
    """fstat the live handle -- used to detect a mid-read modification."""
    return os.fstat(handle.fd)


def verify_unchanged(handle: VersionedFile, before: os.stat_result, on_mismatch) -> None:
    after = os.fstat(handle.fd)
    if after.st_mtime_ns != before.st_mtime_ns or after.st_size != before.st_size:
        raise on_mismatch


def modify(handle: VersionedFile, data: bytes) -> None:
    """Replace the file's contents through the verified handle."""
    os.lseek(handle.fd, 0, os.SEEK_SET)
    os.ftruncate(handle.fd, 0)
    view = memoryview(data)
    while view:
        written = os.write(handle.fd, view)
        view = view[written:]


def create_with_dirs(canonical: str, data: bytes) -> VersionedFile:
    """Create parent directories and the file atomically (O_EXCL)."""
    parent = os.path.dirname(canonical)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd = os.open(canonical, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o664)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        return VersionedFile(fd=fd, canonical=canonical, content=b"", had_bom=False)
    except BaseException:
        os.close(fd)
        raise


def finish(handle: VersionedFile) -> Version:
    """Close and re-stat by path for the returned marker.

    The write itself went through the verified handle; this stat only seeds
    the client's next expectedVersion. A stale marker here fails closed
    (version_mismatch -> re-read), never open.
    """
    fd = handle.fd
    handle.fd = -1
    os.close(fd)
    return version_of_path(handle.canonical)


def version_of_path(canonical: str) -> Version:
    stat = os.stat(canonical)
    return Version(mtime_ns=stat.st_mtime_ns, size=stat.st_size, path=canonical)


__all__ = [
    "VersionedFile", "target_lock", "split_bom", "join_bom", "version_of",
    "version_of_path", "open_verified", "refstat", "verify_unchanged",
    "modify", "create_with_dirs", "finish",
    "ToolError", "version_missing_edit", "version_missing_write",
    "version_mismatch_edit", "version_mismatch_write",
]
