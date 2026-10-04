"""OS-level real paths: the kernel tells us what we actually opened.

The security model is open-then-verify: containment, type and deny decisions
are all made against the path *of the open handle*, never against a path
string we computed ourselves. This module is the platform seam:

  Windows  GetFinalPathNameByHandleW (via msvcrt fd -> HANDLE); directory
           handles need CreateFileW with FILE_FLAG_BACKUP_SEMANTICS because
           os.open() refuses directories.
  Linux    readlink /proc/self/fd/<n>
  macOS    fcntl F_GETPATH (= 50, XNU sys/fcntl.h; not to be confused with
           F_GETPATH_NOFIRMLINK = 102, nor with F_TRIM_ACTIVE_FILE = 100)

Anything that cannot produce a real path returns None / raises -- callers
must fail closed, never fall back to the lexical path.
"""

from __future__ import annotations

import os
import sys

_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)

# public so callers can compose flags (fslayer creates files with O_EXCL)
O_BINARY = _O_BINARY

# Opening for read with O_NONBLOCK: a FIFO cannot hang us, and on Windows the
# flag simply does not exist (no POSIX FIFOs there).
OPEN_RDONLY = os.O_RDONLY | _O_BINARY | _O_NONBLOCK
OPEN_RDWR = os.O_RDWR | _O_BINARY | _O_NONBLOCK

# Kept at module scope (not inside the darwin branch) so the number is
# assertable from any platform: it is a constant of XNU's ABI, and the wrong
# value here would silently fail every macOS request closed.
_F_GETPATH = 50
# Linux readlink appends this to /proc/self/fd/<n> for an unlinked file.
_LINUX_DELETED_SUFFIX = " (deleted)"

if sys.platform == "win32":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _CreateFileW = _k32.CreateFileW
    _CreateFileW.restype = wintypes.HANDLE
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    _GetFinalPathNameByHandleW = _k32.GetFinalPathNameByHandleW
    _GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
    ]

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 0x01
    _FILE_SHARE_WRITE = 0x02
    _FILE_SHARE_DELETE = 0x04
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    def _strip_dos_prefix(path: str) -> str:
        # GetFinalPathNameByHandleW returns \\?\C:\... or \\?\UNC\server\share
        if path.startswith("\\\\?\\UNC\\"):
            return "\\\\" + path[8:]
        if path.startswith("\\\\?\\"):
            return path[4:]
        return path

    def real_path_of_fd(fd: int) -> str | None:
        try:
            handle = msvcrt.get_osfhandle(fd)
        except OSError:
            return None
        if not handle or handle == _INVALID_HANDLE_VALUE:
            return None
        buf = ctypes.create_unicode_buffer(32768)
        n = _GetFinalPathNameByHandleW(handle, buf, len(buf), 0)
        if n == 0 or n >= len(buf):
            return None
        return _strip_dos_prefix(buf.value)

    def open_dir(path: str) -> int:
        """Open a directory and return a CRT fd (os.open refuses dirs here)."""
        handle = _CreateFileW(
            path,
            _GENERIC_READ,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle in (0, _INVALID_HANDLE_VALUE):
            err = ctypes.get_last_error()
            raise OSError(err, os.strerror(err), path)
        try:
            return msvcrt.open_osfhandle(handle, os.O_RDONLY)
        except OSError:
            ctypes.windll.kernel32.CloseHandle(handle)
            raise

else:
    import fcntl as _fcntl

    def real_path_of_fd(fd: int) -> str | None:
        if sys.platform == "darwin":
            buf = bytearray(4096)
            try:
                _fcntl.fcntl(fd, _F_GETPATH, buf)
            except OSError:
                return None
            raw = bytes(buf).split(b"\x00", 1)[0]
            return raw.decode("utf-8", "surrogateescape") or None
        try:
            link = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            return None
        # A file unlinked after open reads back as "<path> (deleted)": drop the
        # suffix, or the resource name carries it and deny patterns stop
        # matching. A file genuinely named "x (deleted)" is then reported under
        # its short name -- the wrong direction is the stricter one.
        if link.endswith(_LINUX_DELETED_SUFFIX):
            link = link[: -len(_LINUX_DELETED_SUFFIX)]
        return link or None

    def open_dir(path: str) -> int:
        return os.open(path, os.O_RDONLY | _O_BINARY | _O_DIRECTORY)


def _is_dir(path: str) -> bool:
    try:
        return os.path.isdir(path)
    except OSError:
        return False


def open_path(path: str, flags: int) -> int:
    """Open a file or directory, returning a verified-ready fd.

    On Windows os.open() raises PermissionError for directories (CreateFileW
    needs FILE_FLAG_BACKUP_SEMANTICS), so those route to open_dir(). The same
    error also covers a genuine access-denied *file* (read-only, sharing
    violation), so the fallback is gated on the target actually being a
    directory: otherwise a read-only file would be handed back as a read-only
    handle, pass the "is a regular file" check and only fail later, at write.
    """
    try:
        return os.open(path, flags)
    except PermissionError:
        if sys.platform == "win32" and _is_dir(path):
            return open_dir(path)
        raise


__all__ = ["real_path_of_fd", "open_dir", "open_path", "OPEN_RDONLY", "OPEN_RDWR", "O_BINARY"]
