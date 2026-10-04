"""Resolver: locate (strings only locate) + open_checked (the OS decides).

The security contract changed from check-then-open to open-then-verify:
  * locate() never authorizes -- it only rejects poison and joins cwd
  * open_checked() authorizes against the OPEN HANDLE's kernel-resolved path
  * containment/type/deny failures raise ToolError; the tools collapse them
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentfiles_shared.errors import ToolError

from agentfiles_server.fslayer import Resolver, contains, slash
from agentfiles_server.handlepath import OPEN_RDONLY


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.ts").write_text("hello\n", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("secret\n", encoding="utf-8")
    return root


def open_ok(resolver: Resolver, path: str, **kw):
    """open_checked with defaults for tests; always closes the handle."""
    kw.setdefault("flags", OPEN_RDONLY)
    kw.setdefault("expect", "any")
    opened = resolver.open_checked(path, **kw)
    opened.close()
    return opened


# --- resolve_child: a name a search reported, resolved then containment-checked


def test_resolve_child_inside_is_workspace_relative(workspace: Path):
    resolver = Resolver(str(workspace))
    resource, real = resolver.resolve_child(resolver.root, "src/main.ts")
    assert resource == "src/main.ts"
    assert real == os.path.realpath(str(workspace / "src" / "main.ts"))


def test_resolve_child_outside_is_dropped(workspace: Path):
    """A hit resolving outside every root is dropped: search must not report
    -- and so must not map -- what a read of the same path would refuse."""
    resolver = Resolver(str(workspace))
    assert resolver.resolve_child(resolver.root, "../outside.txt") is None


def test_resolve_child_whitelisted_stays_absolute(workspace: Path, tmp_path: Path):
    resolver = Resolver(str(workspace), whitelist=[str(tmp_path)])
    resource, real = resolver.resolve_child(resolver.root, "../outside.txt")
    assert os.path.isabs(resource)
    assert resource == slash(real)


# --- locate: poison + cwd joining, no authorization --------------------------

def test_locate_absolute_is_normpath(workspace: Path):
    target = str(workspace / "src" / "main.ts")
    assert Resolver(str(workspace)).locate(target, None) == os.path.normpath(target)


def test_locate_relative_joins_cwd(workspace: Path):
    full = Resolver(str(workspace)).locate("main.ts", str(workspace / "src"))
    assert full == os.path.normpath(str(workspace / "src" / "main.ts"))


def test_locate_relative_without_cwd_is_cwd_not_set(workspace: Path):
    with pytest.raises(ToolError) as exc:
        Resolver(str(workspace)).locate("main.ts", None)
    assert exc.value.code == "cwd_not_set"


def test_locate_relative_with_relative_cwd_is_invalid(workspace: Path):
    with pytest.raises(ToolError) as exc:
        Resolver(str(workspace)).locate("main.ts", "not/absolute")
    assert exc.value.code == "invalid_input"


def test_poison_checks_live_in_the_schema():
    """NUL / drive-relative rejection happens at input validation (pydantic),
    before locate() ever sees the value -- locate only joins."""
    from pydantic import ValidationError

    from agentfiles_shared.schema import ReadInput

    with pytest.raises(ValidationError):
        ReadInput(path="a\x00b")
    if os.name == "nt":
        with pytest.raises(ValidationError):
            ReadInput(path="C:foo")


# --- open_checked: the handle decides ----------------------------------------

def test_open_inside_succeeds(workspace: Path):
    opened = open_ok(Resolver(str(workspace)), str(workspace / "src" / "main.ts"))
    assert not opened.external
    assert opened.resource == "src/main.ts"
    assert opened.is_file


def test_open_inside_via_relative_cwd(workspace: Path):
    resolver = Resolver(str(workspace))
    full = resolver.locate("src/main.ts", str(workspace))
    opened = open_ok(resolver, full)
    assert opened.resource == "src/main.ts"


def test_resource_uses_forward_slashes(workspace: Path):
    opened = open_ok(Resolver(str(workspace)), str(workspace / "src" / "main.ts"))
    assert "\\" not in opened.resource


def test_escape_is_path_escape_logged(workspace: Path):
    """Lexical escape still opens (the kernel resolves ../) -- the handle's
    real path lands outside containment and is rejected."""
    resolver = Resolver(str(workspace))
    full = resolver.locate("../outside.txt", str(workspace))
    assert os.path.isfile(full)  # the kernel would open it; we must not serve it
    with pytest.raises(ToolError) as exc:
        open_ok(resolver, full)
    assert exc.value.code == "path_escape"


def test_external_absolute_rejected_without_whitelist(workspace: Path, tmp_path: Path):
    with pytest.raises(ToolError) as exc:
        open_ok(Resolver(str(workspace)), str(tmp_path / "outside.txt"))
    assert exc.value.code == "path_escape"


def test_external_absolute_allowed_with_whitelist(workspace: Path, tmp_path: Path):
    resolver = Resolver(str(workspace), [str(tmp_path)])
    opened = open_ok(resolver, str(tmp_path / "outside.txt"))
    assert opened.external
    assert opened.resource == slash(str(tmp_path / "outside.txt"))


def test_whitelist_is_prefix_scoped(workspace: Path, tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "note.md").write_text("x")
    other = tmp_path / "other"
    other.mkdir()
    (other / "note.md").write_text("y")
    resolver = Resolver(str(workspace), [str(allowed)])
    assert open_ok(resolver, str(allowed / "note.md")).external
    with pytest.raises(ToolError):
        open_ok(resolver, str(other / "note.md"))


def test_link_escape_rejected(workspace: Path, tmp_path: Path, link_dir):
    """The whole point of open-then-verify: the kernel resolves the link and
    the handle's real path is outside containment."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    link_dir(outside, workspace / "leak")
    with pytest.raises(ToolError) as exc:
        open_ok(Resolver(str(workspace)), str(workspace / "leak"))
    assert exc.value.code == "path_escape"


def test_expect_type_mismatch_is_path_kind(workspace: Path):
    resolver = Resolver(str(workspace))
    with pytest.raises(ToolError) as exc:
        open_ok(resolver, str(workspace / "src"), expect="file")
    assert exc.value.code == "path_kind"


def test_devices_and_pipes_are_rejected(workspace: Path, tmp_path: Path):
    """Only regular files and directories: a FIFO must not hang us, a device
    must not be touched."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("no POSIX FIFOs on this platform")
    fifo = tmp_path / "pipe"
    try:
        os.mkfifo(str(fifo))
    except (OSError, NotImplementedError):
        pytest.skip("mkfifo unavailable on this platform")
    # symlink it into the workspace so containment passes and TYPE is the rule
    link = workspace / "pipe"
    try:
        os.symlink(str(fifo), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    resolver = Resolver(str(workspace))
    with pytest.raises(ToolError) as exc:
        open_ok(resolver, str(link))
    assert exc.value.code == "path_kind"


# --- deny ---------------------------------------------------------------------

def test_deny_matches_real_resource(workspace: Path, link_dir):
    """good.txt resolving to .env: the handle's real path is .env -> denied,
    even though the name the caller asked for is innocent."""
    (workspace / ".env").mkdir()
    link_dir(workspace / ".env", workspace / "good.txt")
    resolver = Resolver(str(workspace))
    with pytest.raises(ToolError) as exc:
        open_ok(resolver, str(workspace / "good.txt"), deny=["*.env"],
                on_deny=ToolError("read_deny", "denied"))
    assert exc.value.code == "read_deny"


def test_deny_matches_lexical_resource(workspace: Path, link_dir):
    """.env resolving to an ordinary name: the real resource is clean, so it
    is the lexical spelling that has to catch it."""
    (workspace / "notes").mkdir()
    link_dir(workspace / "notes", workspace / ".env")
    resolver = Resolver(str(workspace))
    with pytest.raises(ToolError) as exc:
        open_ok(resolver, str(workspace / ".env"), deny=["*.env"],
                on_deny=ToolError("read_deny", "denied"))
    assert exc.value.code == "read_deny"


def test_deny_miss_allows(workspace: Path):
    resolver = Resolver(str(workspace))
    opened = open_ok(resolver, str(workspace / "src" / "main.ts"),
                     deny=["*.env"], on_deny=ToolError("read_deny", "denied"))
    assert opened.resource == "src/main.ts"


def test_empty_deny_with_an_error_is_allowed(workspace: Path):
    """A server with no AF_*_DENY configured passes an empty list; the error
    rides along unused and must not be treated as a caller mistake."""
    resolver = Resolver(str(workspace))
    opened = open_ok(resolver, str(workspace / "src" / "main.ts"),
                     deny=[], on_deny=ToolError("read_deny", "denied"))
    assert opened.resource == "src/main.ts"


def test_deny_without_an_error_is_a_caller_mistake(workspace: Path):
    """Patterns with nothing to raise would fall through as `raise None`."""
    resolver = Resolver(str(workspace))
    with pytest.raises(ValueError):
        open_ok(resolver, str(workspace / "src" / "main.ts"), deny=["*.env"])


# --- create_file: parent verified first, deny before side effects ------------

def test_create_makes_parents(workspace: Path):
    resolver = Resolver(str(workspace))
    target = str(workspace / "a" / "b" / "c.txt")
    opened = resolver.create_file(target)
    try:
        assert opened.is_file
        assert opened.resource == "a/b/c.txt"
    finally:
        opened.close()
    assert (workspace / "a" / "b" / "c.txt").exists()


def test_create_denied_makes_no_side_effect(workspace: Path):
    resolver = Resolver(str(workspace))
    target = str(workspace / "app.env.local")
    with pytest.raises(ToolError) as exc:
        resolver.create_file(target, deny=["*.env.*"],
                             on_deny=ToolError("write_deny", "denied"))
    assert exc.value.code == "write_deny"
    # deny is matched before makedirs: nothing was created
    assert not (workspace / "app.env.local").exists()
    assert not (workspace / "src" / "app.env.local").exists()


def test_create_outside_containment_rejected(workspace: Path, tmp_path: Path):
    resolver = Resolver(str(workspace))
    target = str(tmp_path / "nope.txt")
    with pytest.raises(ToolError) as exc:
        resolver.create_file(target)
    assert exc.value.code == "path_escape"
    assert not (tmp_path / "nope.txt").exists()


# --- containment helpers -------------------------------------------------------

def test_contains_rule(tmp_path: Path):
    parent = str(tmp_path)
    assert contains(parent, parent)
    assert contains(parent, str(tmp_path / "a" / "b"))
    assert not contains(parent, str(tmp_path / ".."))


def test_contains_cross_drive_is_false_not_error():
    """Windows relpath raises ValueError across drives; containment must just fail."""
    if os.name != "nt":
        pytest.skip("cross-drive paths only exist on Windows")
    assert contains(r"C:\ws", r"D:\data\x.txt") is False
    assert contains(r"D:\whitelist", r"C:\ws\x.txt") is False
