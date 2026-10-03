"""edit tool: exact matching, strict version verification, diff preview."""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from agentfiles_server.app import create_app
from agentfiles_server.config import Config

TOKEN = "tok-e"
SECRET = "sec-e"


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
        read_deny=overrides.get("read_deny", []),
        write_deny=overrides.get("write_deny", []),
    )
    return TestClient(create_app(config))


def read_version(client, path: str) -> dict:
    data = signed_post(client, "/v1/read", {"path": path}).json()
    assert data["ok"], data
    return data["result"]["version"]


def edit(client, path, old, new, version=None, replace_all=None):
    payload: dict = {"path": path, "oldString": old, "newString": new}
    if version is not None:
        payload["expectedVersion"] = version
    if replace_all is not None:
        payload["replaceAll"] = replace_all
    return signed_post(client, "/v1/edit", payload).json()


EXPECTED_MODEL_TEXT = (
    "Edited file successfully: hello.txt\n"
    "Replacements: 1\n"
    "```diff\n"
    "-before\n"
    "+after\n"
    "```"
)


def test_exact_replace_model_text(workspace):
    (workspace / "hello.txt").write_bytes(b"before\n")
    with make_client(workspace) as client:
        version = read_version(client, "hello.txt")
        data = edit(client, "hello.txt", "before", "after", version)
    assert data["ok"] is True
    assert data["modelText"] == EXPECTED_MODEL_TEXT
    assert (workspace / "hello.txt").read_bytes() == b"after\n"
    info = data["result"]["files"][0]
    assert info["file"] == "hello.txt"
    assert info["status"] == "modified"
    assert info["additions"] == 1
    assert info["deletions"] == 1
    assert "-before" in info["patch"] and "+after" in info["patch"]
    assert data["result"]["replacements"] == 1


def test_multiple_matches_rejected(workspace):
    (workspace / "a.txt").write_bytes(b"x x x\n")
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        data = edit(client, "a.txt", "x", "y", version)
    assert data["error"]["message"] == (
        "Found multiple exact matches for oldString. Provide more surrounding "
        "context or set replaceAll to true."
    )
    assert (workspace / "a.txt").read_bytes() == b"x x x\n"


def test_replace_all(workspace):
    (workspace / "a.txt").write_bytes(b"x x x\n")
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        data = edit(client, "a.txt", "x", "y", version, replace_all=True)
    assert data["ok"] is True
    assert data["result"]["replacements"] == 3
    assert (workspace / "a.txt").read_bytes() == b"y y y\n"


def test_not_found(workspace):
    (workspace / "a.txt").write_bytes(b"hello\n")
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        data = edit(client, "a.txt", "absent", "x", version)
    assert data["error"]["message"] == (
        "Could not find oldString in the file. It must match exactly, "
        "including whitespace and indentation."
    )


def test_identical_args_no_io(workspace):
    (workspace / "a.txt").write_bytes(b"same\n")
    with make_client(workspace) as client:
        # no version attached: the precheck must fire before any file IO
        data = edit(client, "a.txt", "same", "same")
    assert data["error"]["message"] == (
        "No changes to apply: oldString and newString are identical."
    )


def test_empty_old_string_no_io(workspace):
    (workspace / "a.txt").write_bytes(b"content\n")
    with make_client(workspace) as client:
        data = edit(client, "a.txt", "", "x")
    assert data["error"]["message"] == (
        "oldString must not be empty. Use write to create or overwrite a file."
    )


def test_crlf_and_bom_preserved(workspace):
    (workspace / "win.txt").write_bytes(b"\xef\xbb\xbfbefore\r\nrest\r\n")
    with make_client(workspace) as client:
        version = read_version(client, "win.txt")
        # model sends LF-style strings; they must be converted to the file's CRLF
        data = edit(client, "win.txt", "before", "after", version)
    assert data["ok"] is True
    assert (workspace / "win.txt").read_bytes() == b"\xef\xbb\xbfafter\r\nrest\r\n"


def test_missing_version_rejected(workspace):
    (workspace / "a.txt").write_bytes(b"content\n")
    with make_client(workspace) as client:
        data = edit(client, "a.txt", "content", "other")
    assert data["error"]["code"] == "version_missing"
    assert data["error"]["message"] == "Read the file before editing it."
    assert (workspace / "a.txt").read_bytes() == b"content\n"


def test_stale_version_rejected(workspace):
    (workspace / "a.txt").write_bytes(b"content\n")
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        time.sleep(0.02)
        with open(workspace / "a.txt", "ab") as handle:
            handle.write(b"external\n")
        data = edit(client, "a.txt", "content", "other", version)
    assert data["error"]["code"] == "version_mismatch"
    assert data["error"]["message"] == (
        "File changed since it was last read. Read it again before editing."
    )
    assert b"external" in (workspace / "a.txt").read_bytes()
    assert b"other" not in (workspace / "a.txt").read_bytes()


def test_mid_read_change_detected(workspace, monkeypatch):
    """fstat after reading differs from before -> mismatch even though the
    initial version check passed."""
    from agentfiles_server import filemut

    (workspace / "a.txt").write_bytes(b"content\n")
    real_refstat = filemut.refstat
    calls = {"n": 0}

    def sneaky_refstat(handle):
        stat = real_refstat(handle)
        calls["n"] += 1
        if calls["n"] == 1:
            # simulate a write landing between verify and content consumption
            os_write = handle.fd
            import os

            os.lseek(os_write, 0, 0)
            os.ftruncate(os_write, 0)
            os.write(os_write, b"raced\n")
            os.lseek(os_write, 0, 0)
        return stat

    monkeypatch.setattr(filemut, "refstat", sneaky_refstat)
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        data = edit(client, "a.txt", "content", "other", version)
    assert data["error"]["code"] == "version_mismatch"


def test_deny_hides_match_information(workspace):
    """deny must return the same message whether or not oldString exists."""
    (workspace / ".env").write_bytes(b"SECRET=1\n")
    config = Config(
        workspace=str(workspace), tokens={TOKEN: SECRET},
        read_deny=[], write_deny=["*.env"],
    )
    with TestClient(create_app(config)) as client:
        version = read_version(client, ".env")
        hit = edit(client, ".env", "SECRET=1", "x", version)
        miss = edit(client, ".env", "ABSENT", "y", version)
    assert hit["error"] == miss["error"]
    assert hit["error"]["message"] == "Unable to edit .env"
    assert (workspace / ".env").read_bytes() == b"SECRET=1\n"


def test_missing_file(workspace):
    with make_client(workspace) as client:
        data = edit(client, "ghost.txt", "a", "b")
    # never read -> receipt missing (file existence is only checked later)
    assert data["error"]["code"] == "version_missing"


def test_preview_truncation(workspace):
    long_line = "z" * 500
    many = "\n".join(f"line{i}" for i in range(8))
    (workspace / "p.txt").write_bytes((many + "\n").encode())
    with make_client(workspace) as client:
        version = read_version(client, "p.txt")
        data = edit(client, "p.txt", "line0", long_line, version)
    lines = data["modelText"].splitlines()
    minus = [line for line in lines if line.startswith("-line")]
    plus = [line for line in lines if line.startswith("+")]
    assert len(minus) + 0 <= 6
    # 8 input lines -> preview capped at 6 plus an ellipsis marker
    assert lines[-1] == "+..." or len(plus) <= 7
    # long replacement line truncated at 240 chars with an ellipsis
    replaced = [line for line in plus if line.startswith("+z")]
    assert all(len(line) <= 241 + 3 for line in replaced)


def test_consecutive_edits_use_refreshed_version(workspace):
    """The version returned by edit #1 authorizes edit #2 without a re-read."""
    (workspace / "a.txt").write_bytes(b"one two\n")
    with make_client(workspace) as client:
        first = edit(client, "a.txt", "one", "1", read_version(client, "a.txt"))
        second = edit(client, "a.txt", "two", "2", first["result"]["version"])
    assert second["ok"] is True
    assert (workspace / "a.txt").read_bytes() == b"1 2\n"
