"""Directory links for the tests that prove open-then-verify.

``os.symlink()`` on Windows needs SeCreateSymbolicLinkPrivilege (Developer Mode
or an elevated process). Most machines -- this one included -- have neither, so
the escape and deny tests that exercise the kernel-resolved handle path skip
silently exactly where the platform seam is most interesting.

A directory junction needs no privilege, and the kernel resolves it the same
way: GetFinalPathNameByHandleW reports the target, not the link. So on Windows
these tests run against a junction instead of skipping. On POSIX ``os.symlink``
just works and is used as-is.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def _junction(target: str, link: str) -> bool:
    if os.name != "nt":
        return False
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", link, target],
        capture_output=True,
    )
    return result.returncode == 0 and os.path.isdir(link)


@pytest.fixture()
def link_dir():
    """Point ``link`` at the directory ``target``; skip only if neither a
    symlink nor a junction can be made here. Links are removed afterwards --
    pytest's tmp_path cleanup would otherwise walk into a junction."""
    made: list[tuple[str, bool]] = []

    def _link(target: Path, link: Path) -> None:
        if not target.is_dir():
            raise AssertionError(f"{target} must be an existing directory")
        try:
            os.symlink(str(target), str(link), target_is_directory=True)
            made.append((str(link), False))
            return
        except (OSError, NotImplementedError):
            pass
        if _junction(str(target), str(link)):
            made.append((str(link), True))
            return
        pytest.skip("no symlinks or junctions available on this platform")

    yield _link

    for link, is_junction in made:
        try:
            # a junction comes off like a directory, and only the link goes
            if is_junction:
                os.rmdir(link)
            else:
                os.unlink(link)
        except OSError:
            pass


@pytest.fixture()
def fake_rg():
    """Point ``ripgrep_path`` at a script that emits ``payload`` verbatim.

    A real rg walk never produces a name that escapes the root it was given,
    so the step that resolves reported names has to be fed its own input.
    """
    def _script(directory: Path, payload: bytes) -> str:
        source = directory / "payload.bin"
        source.write_bytes(payload)
        if os.name == "nt":
            script = directory / "fake_rg.bat"
            script.write_text(f'@echo off\r\ntype "{source}"\r\n', encoding="ascii")
        else:
            script = directory / "fake_rg.sh"
            script.write_text(f'#!/bin/sh\ncat "{source}"\n', encoding="ascii")
            script.chmod(0o755)
        return str(script)

    return _script
