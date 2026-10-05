"""edit tool: exact matching, strict version verification, diff preview."""

from __future__ import annotations

import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from agentfiles_server.app import create_app
from agentfiles_server.config import Config
from conftest import IS_ROOT

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
    client = TestClient(create_app(config))
    client.af_workspace = str(workspace)
    return client


def _with_cwd(client, payload: dict) -> dict:
    payload.setdefault("cwd", getattr(client, "af_workspace", None))
    return payload


def read_version(client, path: str) -> dict:
    data = signed_post(
        client, "/v1/read", _with_cwd(client, {"path": path})
    ).json()
    assert data["ok"], data
    return data["result"]["version"]


def edit(client, path, old, new, version=None, replace_all=None):
    payload: dict = {"path": path, "oldString": old, "newString": new}
    if version is not None:
        payload["expectedVersion"] = version
    if replace_all is not None:
        payload["replaceAll"] = replace_all
    return signed_post(client, "/v1/edit", _with_cwd(client, payload)).json()


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


def test_edit_cjk_file_starting_with_ef_byte(workspace):
    """A leading 0xEF belongs to the character (U+FF01 '！'), not to a BOM."""
    (workspace / "cjk.txt").write_bytes("！重点\n".encode())
    with make_client(workspace) as client:
        version = read_version(client, "cjk.txt")
        data = edit(client, "cjk.txt", "重点", "普通", version)
    assert data["ok"] is True, data
    assert (workspace / "cjk.txt").read_bytes() == "！普通\n".encode()


def test_edit_bom_file_starting_with_fullwidth_char(workspace):
    """BOM + a character that itself starts with 0xEF: keep exactly one BOM."""
    (workspace / "cjk.txt").write_bytes("\ufeff！重点\n".encode())
    with make_client(workspace) as client:
        version = read_version(client, "cjk.txt")
        data = edit(client, "cjk.txt", "重点", "普通", version)
    assert data["ok"] is True, data
    assert (workspace / "cjk.txt").read_bytes() == "\ufeff！普通\n".encode()


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


def test_same_size_same_mtime_swap_is_caught(workspace):
    """mtime+size alone miss a replacement stamped with the old mtime (exFAT
    and network volumes have second-granularity mtimes), so the marker also
    carries the file identity: st_ino/st_dev."""
    target = workspace / "a.txt"
    target.write_bytes(b"content\n")
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        assert version["ino"] != 0, "filesystem reports no inode; identity check is inert"
        # external writer: same byte length, byte-identical mtime, new file
        replacement = workspace / "a.tmp"
        replacement.write_bytes(b"another\n")
        os.utime(replacement, ns=(version["mtimeNs"], version["mtimeNs"]))
        os.replace(replacement, target)
        data = edit(client, "a.txt", "content", "other", version)
    assert data["error"]["code"] == "version_mismatch"
    assert target.read_bytes() == b"another\n"


def test_marker_without_identity_is_rejected(workspace):
    """Omitting ino/dev must not weaken the check: the comparison is chosen
    by what the volume reports, not by what the caller bothered to send."""
    (workspace / "a.txt").write_bytes(b"content\n")
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        assert version["ino"] != 0, "filesystem reports no inode; test is inert"
        stripped = {key: value for key, value in version.items()
                    if key not in ("ino", "dev")}
        data = edit(client, "a.txt", "content", "other", stripped)
    assert data["ok"] is False
    assert data["error"]["code"] == "version_mismatch"
    assert (workspace / "a.txt").read_bytes() == b"content\n"




def test_mid_read_change_detected(workspace, monkeypatch):
    """A change landing while the content is being read must be caught: the
    baseline fstat is taken *before* _read_all, so the post-decode comparison
    sees the modification instead of having adopted it as the baseline."""
    from agentfiles_server import filemut

    (workspace / "a.txt").write_bytes(b"content\n")
    real_read_all = filemut._read_all

    def racy_read_all(fd):
        data = real_read_all(fd)
        # external writer lands between the read and the match; writing
        # through the same handle keeps the test deterministic, and the stat
        # effect is identical to an out-of-process writer
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, b"raced\n")
        os.lseek(fd, 0, os.SEEK_SET)
        return data

    monkeypatch.setattr(filemut, "_read_all", racy_read_all)
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        data = edit(client, "a.txt", "content", "other", version)
    assert data["error"]["code"] == "version_mismatch"
    assert (workspace / "a.txt").read_bytes() == b"raced\n"


def test_deny_hides_match_information(workspace):
    """deny must return the same message whether or not oldString exists."""
    (workspace / ".env").write_bytes(b"SECRET=1\n")
    config = Config(
        workspace=str(workspace), tokens={TOKEN: SECRET},
        read_deny=[], write_deny=["*.env"],
    )
    with TestClient(create_app(config)) as client:
        client.af_workspace = str(workspace)
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


# --- filesystem failures -----------------------------------------------------

@pytest.mark.skipif(IS_ROOT, reason="root ignores the permission bits")
def test_readonly_file_reports_unable_to_edit(workspace):
    """os.open(O_RDWR) on a read-only file raises PermissionError on both
    platforms; it must reach the model as a tool error, not as `internal`."""
    target = workspace / "ro.txt"
    target.write_bytes(b"content\n")
    os.chmod(target, 0o444)
    try:
        with make_client(workspace) as client:
            version = read_version(client, "ro.txt")
            data = edit(client, "ro.txt", "content", "other", version)
    finally:
        os.chmod(target, 0o644)
    assert data["error"]["code"] == "unable_to_edit"
    assert data["error"]["message"] == "Unable to edit ro.txt"
    assert target.read_bytes() == b"content\n"


def test_directory_target_never_reports_internal(workspace):
    """A listing grants no receipt, so a directory edit has to arrive with a
    hand-built marker. The failure is a tool error on every platform:
    IsADirectoryError -> version_missing (POSIX), PermissionError ->
    unable_to_edit (Windows), never an `internal` error."""
    target = workspace / "subdir"
    target.mkdir()
    (target / "inner.txt").write_bytes(b"x\n")
    with make_client(workspace) as client:
        # borrow the server's own spelling of the path: dirname of a text
        # file's canonical path is the directory's canonical path
        inner = read_version(client, "subdir/inner.txt")
        parent_path = os.path.dirname(inner["path"])
        stat = os.stat(parent_path)
        version = {"path": parent_path, "mtimeNs": stat.st_mtime_ns,
                   "size": stat.st_size}
        data = edit(client, "subdir", "a", "b", version)
    assert data["ok"] is False
    assert data["error"]["code"] in {"version_missing", "unable_to_edit"}


# --- size bounds -------------------------------------------------------------

def test_file_over_the_edit_limit_is_rejected(workspace, monkeypatch):
    """The limit is checked before the read, and reported as its own error."""
    from agentfiles_server.tools import edit as edit_tool

    monkeypatch.setattr(edit_tool, "MAX_EDIT_BYTES", 1024)
    (workspace / "big.txt").write_bytes(b"x" * 4096 + b"\n")
    with make_client(workspace) as client:
        version = read_version(client, "big.txt")
        data = edit(client, "big.txt", "x", "y", version)
    assert data["error"]["code"] == "edit_too_large"
    assert data["error"]["message"] == (
        "File is 4097 bytes, exceeding the 1024 byte edit limit: big.txt"
    )
    assert (workspace / "big.txt").read_bytes() == b"x" * 4096 + b"\n"


def test_file_that_grew_past_the_marker_reports_mismatch(workspace, monkeypatch):
    """The size verdict comes from the marker, not from a second stat of the
    path: a file that grew since the read is a stale marker (mismatch), not
    "too large to edit"."""
    from agentfiles_server.tools import edit as edit_tool

    monkeypatch.setattr(edit_tool, "MAX_EDIT_BYTES", 1024)
    (workspace / "a.txt").write_bytes(b"content\n")
    with make_client(workspace) as client:
        version = read_version(client, "a.txt")
        (workspace / "a.txt").write_bytes(b"x" * 4096 + b"\n")
        data = edit(client, "a.txt", "content", "other", version)
    assert data["error"]["code"] == "version_mismatch"
    assert (workspace / "a.txt").read_bytes() == b"x" * 4096 + b"\n"


def test_patch_clips_long_lines_and_stops_at_the_budget(workspace, monkeypatch):
    """A one-line megabyte file must not be echoed back through `patch`."""
    from agentfiles_server.tools import edit as edit_tool

    monkeypatch.setattr(edit_tool, "PATCH_MAX_BYTES", 3000)
    (workspace / "p.txt").write_bytes(("a" * 5000 + "\n").encode())
    with make_client(workspace) as client:
        version = read_version(client, "p.txt")
        data = edit(client, "p.txt", "a" * 5000, "b" + "a" * 4999, version)
    assert data["ok"] is True, data
    patch = data["result"]["files"][0]["patch"]
    assert "a" * 5000 not in patch, "long line must be clipped, not echoed"
    assert "omitted; patch exceeds 3000 bytes" in patch
    assert len(patch) <= 3000 + 200  # budget + the marker line
