"""OS-level real paths: the kernel tells us what we actually opened.

The security model is open-then-verify: containment, type and deny decisions
are all made against the path *of the open handle*, never against a path
string we computed ourselves. This module is the platform seam:

  Windows  GetFinalPathNameByHandleW (via msvcrt fd -> HANDLE); directory
           handles need CreateFileW with FILE_FLAG_BACKUP_SEMANTICS because
           os.open() refuses directories.
  Linux    readlink /proc/self/fd/<n>
  macOS    fcntl F_GETPATH (value 100, stable in XNU)

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
            # F_GETPATH = 100 (XNU sys/fcntl.h); stable across macOS releases
            buf = bytearray(4096)
            try:
                _fcntl.fcntl(fd, 100, buf)
            except OSError:
                return None
            raw = bytes(buf).split(b"\x00", 1)[0]
            return raw.decode("utf-8", "surrogateescape") or None
        try:
            return os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            return None

    def open_dir(path: str) -> int:
        return os.open(path, os.O_RDONLY | _O_BINARY | _O_DIRECTORY)


def open_path(path: str, flags: int) -> int:
    """Open a file or directory, returning a verified-ready fd.

    On Windows os.open() raises PermissionError for directories; route those
    to the CreateFileW path. A genuine access-denied on a *file* also lands
    here, and open_dir() then raises its own OSError -- same class of failure
    to the caller.
    """
    try:
        return os.open(path, flags)
    except PermissionError:
        if sys.platform == "win32":
            return open_dir(path)
        raise


__all__ = ["real_path_of_fd", "open_dir", "open_path", "OPEN_RDONLY", "OPEN_RDWR", "O_BINARY"]
