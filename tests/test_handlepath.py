"""The platform seam: a real path must come from the kernel, never from strings.

Whatever this module cannot answer has to come back as None (callers fail
closed), so the tests assert that property rather than the syscall details --
except for the one number that has no runtime guard: a wrong F_GETPATH would
make every macOS request fail closed without any test noticing.
"""

from __future__ import annotations

import os
import sys

import pytest

from agentfiles_server import handlepath
from conftest import IS_ROOT


def test_f_getpath_is_xnus_value():
    # 50 = F_GETPATH. 100 is F_TRIM_ACTIVE_FILE, 102 F_GETPATH_NOFIRMLINK:
    # either would leave the buffer empty and fail every macOS read closed.
    assert handlepath._F_GETPATH == 50


def test_real_path_of_file(tmp_path):
    target = tmp_path / "note.txt"
    target.write_text("hi", encoding="utf-8")
    fd = handlepath.open_path(str(target), handlepath.OPEN_RDONLY)
    try:
        real = handlepath.real_path_of_fd(fd)
    finally:
        os.close(fd)
    assert real is not None
    assert os.path.normcase(os.path.abspath(real)) == os.path.normcase(str(target))


def test_real_path_of_directory(tmp_path):
    fd = handlepath.open_dir(str(tmp_path))
    try:
        real = handlepath.real_path_of_fd(fd)
    finally:
        os.close(fd)
    assert real is not None
    assert os.path.normcase(os.path.abspath(real)) == os.path.normcase(str(tmp_path))


def test_open_path_opens_a_directory(tmp_path):
    fd = handlepath.open_path(str(tmp_path), handlepath.OPEN_RDONLY)
    try:
        assert handlepath.real_path_of_fd(fd) is not None
    finally:
        os.close(fd)


def test_open_path_rejects_a_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        handlepath.open_path(str(tmp_path / "nope.txt"), handlepath.OPEN_RDONLY)


@pytest.mark.skipif(IS_ROOT, reason="root ignores the permission bits")
def test_open_path_does_not_downgrade_a_read_only_file(tmp_path):
    """A read-only file must fail here, not come back as a read-only handle
    that passes the type check and only fails once we try to write."""
    target = tmp_path / "locked.txt"
    target.write_text("hi", encoding="utf-8")
    previous = target.stat().st_mode
    try:
        os.chmod(target, 0o444)
        with pytest.raises(PermissionError):
            handlepath.open_path(str(target), handlepath.OPEN_RDWR)
    finally:
        os.chmod(target, previous)


def test_real_path_of_closed_fd_returns_none(tmp_path):
    target = tmp_path / "note.txt"
    target.write_text("hi", encoding="utf-8")
    fd = handlepath.open_path(str(target), handlepath.OPEN_RDONLY)
    os.close(fd)
    assert handlepath.real_path_of_fd(fd) is None


def test_deleted_suffix_is_stripped(tmp_path):
    """An unlinked file must not carry Linux's ' (deleted)' into the resource
    name -- deny patterns stop matching once the suffix is in there."""
    if sys.platform == "win32":
        pytest.skip("readlink /proc/self/fd is POSIX only")
    target = tmp_path / "secret.env"
    target.write_text("KEY=1", encoding="utf-8")
    fd = handlepath.open_path(str(target), handlepath.OPEN_RDONLY)
    try:
        os.unlink(target)
        real = handlepath.real_path_of_fd(fd)
    finally:
        os.close(fd)
    assert real == str(target)
