"""Resolver: containment, symlink escape, resource normalization."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentfiles_shared.errors import ToolError

from agentfiles_server.fslayer import Resolver, contains, slash


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.ts").write_text("hello\n", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("secret\n", encoding="utf-8")
    return root


def test_relative_file_resolves_inside(workspace: Path):
    resolved = Resolver(str(workspace)).resolve("src/main.ts")
    assert not resolved.external
    assert resolved.resource == "src/main.ts"
    assert resolved.canonical == os.path.realpath(workspace / "src" / "main.ts")


def test_absolute_inside_resolves(workspace: Path):
    target = str(workspace / "src" / "main.ts")
    resolved = Resolver(str(workspace)).resolve(target)
    assert not resolved.external
    assert resolved.resource == "src/main.ts"


def test_relative_escape_rejected(workspace: Path):
    with pytest.raises(ToolError) as exc:
        Resolver(str(workspace)).resolve("../outside.txt")
    assert exc.value.code == "path_escape"
    assert "relative_escape" in exc.value.message


def test_external_absolute_marked_external(workspace: Path, tmp_path: Path):
    target = str(tmp_path / "outside.txt")
    resolved = Resolver(str(workspace)).resolve(target)
    assert resolved.external
    assert resolved.resource == slash(target)


def test_resource_uses_forward_slashes(workspace: Path):
    resolved = Resolver(str(workspace)).resolve("src/main.ts")
    assert "\\" not in resolved.resource


def test_symlink_escape_rejected(workspace: Path, tmp_path: Path):
    link = workspace / "leak"
    try:
        os.symlink(str(tmp_path), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    with pytest.raises(ToolError) as exc:
        Resolver(str(workspace)).resolve("leak/outside.txt")
    assert exc.value.code == "path_escape"


def test_contains_rule(tmp_path: Path):
    parent = str(tmp_path)
    assert contains(parent, parent)
    assert contains(parent, str(tmp_path / "a" / "b"))
    assert not contains(parent, str(tmp_path / ".."))
