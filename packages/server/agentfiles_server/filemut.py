"""Strict-mode file mutation primitives.

Guarantees (the "strict" in strict mode):
  * version verification and the subsequent write happen through the SAME
    open file handle -- never a second open by path -- so a file swapped at
    the path between check and write cannot receive the payload
  * the fstat taken while verifying is kept on the handle, *before* the
    content is read; edit re-checks it after decoding, so any change landing
    between the read and the match is caught (see ``verify_unchanged``)
  * version markers come from one fstat: mtime_ns, size and the file identity
    (st_ino/st_dev), integer nanoseconds

Locks are per-canonical-path and process-local, mirroring V2's KeyedMutex.
Handlers run in a threadpool, so these are threading.Lock, not asyncio.
"""

from __future__ import annotations

import contextlib
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass

from agentfiles_shared.errors import ToolError, version_mismatch_edit, \
    version_mismatch_write, version_missing_edit, version_missing_write
from agentfiles_shared.schema import Version

# O_BINARY matters on Windows: without it, \n <-> \r\n translation corrupts bytes.
_O_BINARY = getattr(os, "O_BINARY", 0)

_locks_guard = threading.Lock()
_locks: dict[str, threading.Lock] = {}
# callers currently inside each entry: the entry survives until the last one
# leaves, so nobody can grab a lock that was dropped and replaced underneath
_locks_in_use: dict[str, int] = {}


@contextlib.contextmanager
def target_lock(canonical: str) -> Iterator[threading.Lock]:
    """Per-canonical-path mutual exclusion; process-local, like V2's KeyedMutex.

    Entries are reference-counted rather than evicted on release: a long-lived
    server must not keep one lock per path it has ever mutated, but the object
    has to outlive anyone still waiting on it.

    The lock is *acquired* here, not merely handed out: callers write
    ``with target_lock(path):``, and a context manager that only yielded the
    Lock would be a critical section in appearance only.
    """
    key = canonical.replace("\\", "/").lower() if os.name == "nt" else canonical
    with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = _locks[key] = threading.Lock()
        _locks_in_use[key] = _locks_in_use.get(key, 0) + 1
    try:
        # outside _locks_guard: blocking here must not stall other paths
        with lock:
            yield lock
    finally:
        with _locks_guard:
            remaining = _locks_in_use.get(key, 0) - 1
            if remaining > 0:
                _locks_in_use[key] = remaining
            else:
                _locks_in_use.pop(key, None)
                _locks.pop(key, None)


@dataclass
class VersionedFile:
    """An open, version-verified file. All IO goes through ``fd``.

    ``before`` is the fstat taken when the handle was verified -- i.e. before
    the content was pulled out of it -- so ``verify_unchanged`` can tell a
    modification that landed mid-read from one that predates the read.
    """

    fd: int
    canonical: str
    content: bytes
    had_bom: bool
    before: os.stat_result

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


# The BOM is a 3-byte *sequence*. Stripping it with
# ``bytes.lstrip(b"\xef\xbb\xbf")`` would treat that as a set of bytes and eat
# the leading 0xEF of any character that starts with it (U+FF01 '！', 'ｱ',
# U+F000) -- mis-detecting a BOM and corrupting the payload on the way out.
_BOM = b"\xef\xbb\xbf"


def has_bom(data: bytes) -> bool:
    return data.startswith(_BOM)


def split_bom(data: bytes) -> tuple[bool, bytes]:
    """Strip any run of leading BOM *sequences*; V2 writes exactly one back."""
    had = False
    while has_bom(data):
        had = True
        data = data[len(_BOM):]
    return had, data


def join_bom(text: bytes, had_bom: bool) -> bytes:
    # the new content may itself carry (a) BOM(s): collapse to zero or one
    _, body = split_bom(text)
    return (_BOM + body) if had_bom else body


def _marker(stat: os.stat_result, canonical: str) -> Version:
    return Version(
        mtime_ns=stat.st_mtime_ns,
        size=stat.st_size,
        path=canonical,
        ino=stat.st_ino,
        dev=stat.st_dev,
    )


def version_of(fd: int, canonical: str) -> Version:
    return _marker(os.fstat(fd), canonical)


def _same_path(a: str, b: str) -> bool:
    norm = (lambda p: p.replace("\\", "/").lower()) if os.name == "nt" else \
           (lambda p: p.replace("\\", "/"))
    return norm(a) == norm(b)


def _matches(stat: os.stat_result, mtime_ns: int, size: int, ino: int,
             dev: int) -> bool:
    """Do ``stat`` and a marker carrying these fields describe one state?

    mtime + size always. The file identity (st_ino/st_dev) is compared
    whenever the volume reports one -- that is what catches a same-length
    rewrite stamped with the old mtime (exFAT and most network volumes store
    seconds).

    Omitting it is a mismatch, not a downgrade: the check must not get weaker
    because a caller stopped carrying ino/dev, and the server always mints
    them when the filesystem has them. Only a file with no identity of its
    own (``st_ino == 0``) falls back to mtime + size alone.
    """
    if stat.st_mtime_ns != mtime_ns or stat.st_size != size:
        return False
    if not stat.st_ino:
        return True  # filesystem without inodes: mtime + size is all there is
    return ino == stat.st_ino and dev == stat.st_dev


def _verify(stat: os.stat_result, expected: Version, canonical: str, on_mismatch) -> None:
    # path first: a marker for another file is a mismatch even if size matches
    if not _same_path(expected.path, canonical):
        raise on_mismatch
    if not _matches(stat, expected.mtime_ns, expected.size,
                    expected.ino, expected.dev):
        raise on_mismatch


def _state_changed(before: os.stat_result, after: os.stat_result) -> bool:
    """True once the handle's state moved on from its pre-read baseline."""
    return not _matches(after, before.st_mtime_ns, before.st_size,
                        before.st_ino, before.st_dev)


def open_verified(
    canonical: str,
    expected: Version | None,
    *,
    on_missing,
    on_mismatch,
    create: bool,
    max_bytes: int | None = None,
    on_too_large=None,
) -> VersionedFile | None:
    """Open and verify ``canonical``; return None when the caller may create it.

    create=True (write tool only): an absent file with no expected version
    yields None so the caller can do an O_EXCL create.

    ``max_bytes`` bounds what is pulled into memory (``on_too_large`` is
    required with it). It is checked on the verified handle -- after the CAS,
    so a stale marker still answers ``on_mismatch``, and before the read, so
    an oversized file is never slurped.
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
        # One fstat: the CAS check, and the baseline verify_unchanged compares
        # against. It has to precede _read_all -- otherwise a modification
        # landing inside the read becomes the baseline itself.
        stat = os.fstat(fd)
        _verify(stat, expected, canonical, on_mismatch)
        if max_bytes is not None and stat.st_size > max_bytes:
            raise on_too_large
        content = _read_all(fd)
        had_bom, _ = split_bom(content)
        return VersionedFile(fd=fd, canonical=canonical, content=content,
                             had_bom=had_bom, before=stat)
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


def verify_unchanged(handle: VersionedFile, on_mismatch) -> None:
    """Re-fstat the live handle against its pre-read baseline.

    ``handle.before`` predates the read, so a modification landing anywhere
    between then and now -- mid-read or while the caller was decoding -- is a
    mismatch. Comparing two post-read stats instead would always pass.
    """
    if _state_changed(handle.before, os.fstat(handle.fd)):
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
        return VersionedFile(fd=fd, canonical=canonical, content=b"",
                             had_bom=False, before=os.fstat(fd))
    except BaseException:
        os.close(fd)
        raise


def finish(handle: VersionedFile) -> Version:
    """Close the handle and return the marker for what it holds.

    The marker is an fstat of *this* handle, taken before it is closed: the
    write went through that handle, so it describes exactly that file. A stat
    of the path afterwards could describe a file swapped in during that
    window, and the next write would then verify against content the caller
    never saw (fail-open). A marker that is merely stale fails closed.
    """
    try:
        return version_of(handle.fd, handle.canonical)
    finally:
        handle.close()


__all__ = [
    "VersionedFile", "target_lock", "split_bom", "join_bom", "has_bom",
    "version_of", "open_verified", "verify_unchanged",
    "modify", "create_with_dirs", "finish",
    "ToolError", "version_missing_edit", "version_missing_write",
    "version_mismatch_edit", "version_mismatch_write",
]
