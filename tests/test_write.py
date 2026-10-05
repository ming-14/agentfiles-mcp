"""write tool: strict-mode version verification, BOM, deny lists."""

from __future__ import annotations

import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from agentfiles_server.app import create_app
from agentfiles_server.config import Config
from conftest import IS_ROOT

TOKEN = "tok-w"
SECRET = "sec-w"


def signed_post(client: TestClient, path: str, payload: dict):
    from agentfiles_shared.auth import build_headers

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = build_headers(
        token=TOKEN, secret=SECRET, method="POST", path=path, body=body
    ).as_dict()
    headers["Content-Type"] = "application/json"
    return client.post(path, content=body, headers=headers)


@pytest.fixture()
def workspace(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def make_client(workspace, **overrides) -> TestClient:
    config = Config(
        workspace=str(workspace), tokens={TOKEN: SECRET},
        read_deny=overrides.get("read_deny", ["*.env", "*.env.*"]),
        write_deny=overrides.get("write_deny", ["*.env", "*.env.*"]),
        external_whitelist=overrides.get("external_whitelist", []),
    )
    client = TestClient(create_app(config))
    client.af_workspace = str(workspace)
    return client


def _with_cwd(client, payload: dict) -> dict:
    """Attach the request cwd unless the test set one explicitly (None = test
    the cwd_not_set rejection)."""
    payload.setdefault("cwd", getattr(client, "af_workspace", None))
    return payload


def read_version(client, path: str) -> dict:
    """Simulates the model's prior read: returns the version marker."""
    data = signed_post(
        client, "/v1/read", _with_cwd(client, {"path": path})
    ).json()
    assert data["ok"], data
    return data["result"]["version"]


def write(client, path: str, content: str, version: dict | None = None):
    payload: dict = {"path": path, "content": content}
    if version is not None:
        payload["expectedVersion"] = version
    return signed_post(client, "/v1/write", _with_cwd(client, payload)).json()


def touch(path, extra_sleep: bool = True):
    """External modification with a clearly different mtime."""
    if extra_sleep:
        time.sleep(0.02)
    with open(path, "ab") as handle:
        handle.write(b"\n")


# --- basics -----------------------------------------------------------------

def test_create_new_file(workspace):
    with make_client(workspace) as client:
        data = write(client, "src/new.txt", "hello")
    assert data["ok"] is True
    assert data["modelText"] == "Created file successfully: src/new.txt"
    assert data["result"]["existed"] is False
    assert data["result"]["resource"] == "src/new.txt"
    assert "\\" not in data["result"]["resource"]
    assert data["result"]["version"]["size"] == 5
    assert (workspace / "src" / "new.txt").read_bytes() == b"hello"


def test_read_then_overwrite(workspace):
    (workspace / "a.txt").write_bytes(b"old")
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        data = write(client, "a.txt", "new content", version)
    assert data["ok"] is True
    assert data["modelText"] == "Wrote file successfully: a.txt"
    assert data["result"]["existed"] is True
    assert data["result"]["version"] != version
    assert (workspace / "a.txt").read_bytes() == b"new content"


def test_overwrite_without_version_rejected(workspace):
    (workspace / "a.txt").write_bytes(b"old")
    with make_client(workspace) as client:
        data = write(client, "a.txt", "clobber")
    assert data["error"]["code"] == "version_missing"
    assert data["error"]["message"] == "Read the file before overwriting it."
    assert (workspace / "a.txt").read_bytes() == b"old"


def test_stale_version_rejected(workspace):
    (workspace / "a.txt").write_bytes(b"old")
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        touch(workspace / "a.txt")
        data = write(client, "a.txt", "clobber", version)
    assert data["error"]["code"] == "version_mismatch"
    assert "Read it again before writing." in data["error"]["message"]
    assert b"clobber" not in (workspace / "a.txt").read_bytes()


def test_file_deleted_after_read(workspace):
    (workspace / "a.txt").write_bytes(b"old")
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        (workspace / "a.txt").unlink()
        data = write(client, "a.txt", "resurrect", version)
    assert data["error"]["code"] == "version_mismatch"
    assert not (workspace / "a.txt").exists()


# --- BOM --------------------------------------------------------------------

def test_bom_from_old_file_kept(workspace):
    (workspace / "b.txt").write_bytes(b"\xef\xbb\xbfbefore")
    with make_client(workspace) as client:
        version = read_version(client, "b.txt")
        write(client, "b.txt", "after", version)
    assert (workspace / "b.txt").read_bytes() == b"\xef\xbb\xbfafter"


def test_bom_from_new_content_kept(workspace):
    with make_client(workspace) as client:
        write(client, "b.txt", "﻿after")
    assert (workspace / "b.txt").read_bytes() == b"\xef\xbb\xbfafter"


def test_bom_exactly_one_when_both(workspace):
    (workspace / "b.txt").write_bytes(b"\xef\xbb\xbfbefore")
    with make_client(workspace) as client:
        version = read_version(client, "b.txt")
        write(client, "b.txt", "﻿after", version)
    assert (workspace / "b.txt").read_bytes() == b"\xef\xbb\xbfafter"


def test_write_content_starting_with_ef_keeps_bytes(workspace):
    (workspace / "b.txt").write_bytes(b"\xef\xbb\xbfbefore")
    with make_client(workspace) as client:
        version = read_version(client, "b.txt")
        write(client, "b.txt", "！after", version)
    assert (workspace / "b.txt").read_bytes() == "\ufeff！after".encode()


def test_write_content_starting_with_ef_into_bomless_file(workspace):
    """No BOM in the old file: the leading 0xEF is content, not a marker."""
    (workspace / "c.txt").write_bytes("！before\n".encode())
    with make_client(workspace) as client:
        version = read_version(client, "c.txt")
        write(client, "c.txt", "！after\n", version)
    assert (workspace / "c.txt").read_bytes() == "！after\n".encode()


def test_write_ascii_into_cjk_leading_file_adds_no_bom(workspace):
    (workspace / "c.txt").write_bytes("！before\n".encode())
    with make_client(workspace) as client:
        version = read_version(client, "c.txt")
        write(client, "c.txt", "plain\n", version)
    assert (workspace / "c.txt").read_bytes() == b"plain\n"


def test_write_only_probes_the_old_file_for_a_bom(workspace, monkeypatch):
    """write replaces every byte, so the old file must not be pulled into
    memory just to learn whether it started with a BOM."""
    from agentfiles_server import filemut

    (workspace / "big.txt").write_bytes(b"\xef\xbb\xbf" + b"a" * 1_000_000)

    def boom(*args, **kwargs):
        raise AssertionError("write must not read the whole old file")

    monkeypatch.setattr(filemut, "_read_all", boom)
    with make_client(workspace) as client:
        version = read_version(client, "big.txt")
        data = write(client, "big.txt", "short", version)
    assert data["ok"] is True, data
    # the BOM came from the prefix probe, so it survives
    assert (workspace / "big.txt").read_bytes() == b"\xef\xbb\xbfshort"


# --- policy -----------------------------------------------------------------

def test_write_deny_blocks_even_after_read(workspace):
    (workspace / ".env").write_bytes(b"SECRET=1")
    config = Config(
        workspace=str(workspace), tokens={TOKEN: SECRET},
        read_deny=[],  # read allowed so a version can be obtained
        write_deny=["*.env"],
    )
    with TestClient(create_app(config)) as client:
        client.af_workspace = str(workspace)
        version = read_version(client, ".env")
        data = write(client, ".env", "clobber", version)
    assert data["error"]["code"] == "write_deny"
    assert data["error"]["message"] == "Unable to write .env"
    assert (workspace / ".env").read_bytes() == b"SECRET=1"


def test_read_deny_write_allowed_when_separate(workspace):
    """Separate lists: write_deny=[] lets a NEW .env be created even though
    read_deny would block reading it."""
    config = Config(
        workspace=str(workspace), tokens={TOKEN: SECRET},
        read_deny=["*.env"],
        write_deny=[],
    )
    with TestClient(create_app(config)) as client:
        client.af_workspace = str(workspace)
        read_data = signed_post(
            client, "/v1/read", {"path": ".env", "cwd": str(workspace)}
        ).json()
        data = write(client, ".env", "NEW=1")
    assert read_data["error"]["message"] == "Unable to read .env"
    assert data["ok"] is True
    assert (workspace / ".env").read_bytes() == b"NEW=1"


def test_external_whitelist_write(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "doc.md").write_text("old", encoding="utf-8")
    config = Config(
        workspace=str(ws), tokens={TOKEN: SECRET},
        external_whitelist=[str(shared)],
    )
    with TestClient(create_app(config)) as client:
        version = read_version(client, str(shared / "doc.md"))
        data = write(client, str(shared / "doc.md"), "new", version)
    assert data["ok"] is True
    assert (shared / "doc.md").read_text(encoding="utf-8") == "new"


def test_relative_escape_rejected(workspace, tmp_path):
    (tmp_path / "out.txt").write_bytes(b"x")
    with make_client(workspace) as client:
        data = write(client, "../out.txt", "clobber")
    # unified surface: escape reads exactly like any other write failure
    assert data["error"]["code"] == "unable_to_write"
    assert (tmp_path / "out.txt").read_bytes() == b"x"


def test_empty_content(workspace):
    with make_client(workspace) as client:
        data = write(client, "empty.txt", "")
    assert data["ok"] is True
    assert (workspace / "empty.txt").read_bytes() == b""
    assert data["result"]["version"]["size"] == 0


# --- filesystem failures -----------------------------------------------------

@pytest.mark.skipif(IS_ROOT, reason="root ignores the permission bits")
def test_readonly_file_reports_unable_to_write(workspace):
    """os.open(O_RDWR) raises PermissionError (not IsADirectoryError) on
    Windows and for any read-only file; it must not leak as `internal`."""
    target = workspace / "ro.txt"
    target.write_bytes(b"content\n")
    os.chmod(target, 0o444)
    try:
        with make_client(workspace) as client:
            version = read_version(client, "ro.txt")
            data = write(client, "ro.txt", "other\n", version)
    finally:
        os.chmod(target, 0o644)
    assert data["error"]["code"] == "unable_to_write"
    assert data["error"]["message"] == "Unable to write ro.txt"
    assert target.read_bytes() == b"content\n"
