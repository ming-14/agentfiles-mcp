"""cwd workflow + open-then-verify error unification.

Covers the agreed design:
  * workspace = server-configured root; cwd = per-request field from the client
  * relative path without cwd -> cwd_not_set (intercepted, not defaulted)
  * POST /v1/cwd validates through a handle; one message for all failures
  * MCP tools: workspace (own cwd only) and set_cwd (validate + store)
  * receipts are keyed by (cwd, path): a cwd switch must not reuse them
  * probing cannot map the server: existing-outside == missing == denied
"""

from __future__ import annotations

import json
import os

import httpx
import pytest
from fastapi.testclient import TestClient

import agentfiles_mcp.server as mcp_server
from agentfiles_mcp import cwd as cwd_state
from agentfiles_mcp.client import ToolClient
from agentfiles_mcp.config import Config as ClientConfig
from agentfiles_mcp.receipts import ReceiptBook
from agentfiles_server.app import create_app
from agentfiles_server.config import Config as ServerConfig
from agentfiles_shared.auth import build_headers

TOKEN = "tok-cwd"
SECRET = "sec-cwd"


def signed_post(client: TestClient, path: str, payload: dict):
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
    (ws / "sub").mkdir()
    (ws / "sub" / "a.txt").write_bytes(b"in workspace\n")
    return ws


@pytest.fixture()
def client(workspace):
    app = create_app(ServerConfig(workspace=str(workspace), tokens={TOKEN: SECRET}))
    with TestClient(app) as test_client:
        test_client.af_workspace = str(workspace)
        yield test_client


# --- intercepted: relative path with no cwd ----------------------------------

def test_relative_without_cwd_is_intercepted(client):
    data = signed_post(client, "/v1/read", {"path": "sub/a.txt"}).json()
    assert data["ok"] is False
    assert data["error"]["code"] == "cwd_not_set"
    assert "set_cwd" in data["error"]["message"]


def test_absolute_needs_no_cwd(client):
    # absolute path into the workspace works without any cwd
    abs_path = os.path.join(client.af_workspace, "sub", "a.txt")
    data = signed_post(client, "/v1/read", {"path": abs_path}).json()
    assert data["ok"] is True
    assert data["result"]["content"] == "in workspace\n"


def test_cwd_resolves_relative(client):
    data = signed_post(
        client, "/v1/read", {"path": "a.txt", "cwd": os.path.join(client.af_workspace, "sub")}
    ).json()
    assert data["ok"] is True
    assert data["result"]["content"] == "in workspace\n"


def test_relative_cwd_is_rejected(client):
    data = signed_post(client, "/v1/read", {"path": "a.txt", "cwd": "not/absolute"}).json()
    assert data["ok"] is False
    assert data["error"]["code"] == "invalid_input"


def test_cwd_joining_escape_is_unified(client):
    """cwd + ../.. may *locate* anything; the opened handle is what decides."""
    data = signed_post(
        client, "/v1/read",
        {"path": "../../etc/passwd", "cwd": os.path.join(client.af_workspace, "sub")},
    ).json()
    assert data["ok"] is False
    assert data["error"]["code"] == "unable_to_read"


# --- POST /v1/cwd -------------------------------------------------------------

def test_set_cwd_validates_and_returns_real_path(client):
    data = signed_post(client, "/v1/cwd", {"path": "sub"}).json()
    assert data["ok"] is True
    assert os.path.isabs(data["cwd"])
    # kernel-resolved: equals realpath of the workspace/sub
    assert os.path.normcase(data["cwd"]) == os.path.normcase(
        os.path.realpath(os.path.join(client.af_workspace, "sub"))
    )


def test_set_cwd_one_message_for_all_failures(client, tmp_path):
    """missing, file-not-dir, outside-containment: identical error, so set_cwd
    cannot be used to map the server's filesystem."""
    missing = signed_post(client, "/v1/cwd", {"path": "nope"}).json()
    outside = signed_post(client, "/v1/cwd", {"path": str(tmp_path)}).json()
    # a file, not a directory
    file_here = os.path.join(client.af_workspace, "sub", "a.txt")
    not_dir = signed_post(client, "/v1/cwd", {"path": file_here}).json()

    for data in (missing, outside, not_dir):
        assert data["ok"] is False
        assert data["error"]["code"] == "invalid_cwd"
    # ...and all three echo the caller's input, never a server-side path
    assert missing["error"]["message"] == "Not an accessible directory in the workspace: nope"
    assert not_dir["error"]["message"] == (
        f"Not an accessible directory in the workspace: {file_here}"
    )


def test_set_cwd_rejects_poison(client):
    data = signed_post(client, "/v1/cwd", {"path": "a\x00b"}).json()
    assert data["ok"] is False
    assert data["error"]["code"] == "invalid_input"


def test_set_cwd_requires_signature(client):
    resp = client.post("/v1/cwd", json={"path": "sub"})
    assert resp.status_code == 401


def test_no_route_serves_the_workspace_root(client):
    """The workspace root is server configuration; no endpoint hands it out."""
    assert "/v1/workspace" not in {route.path for route in client.app.routes}


# --- probing cannot map the filesystem -----------------------------------------

def test_existing_outside_reads_like_missing(client, workspace, tmp_path):
    """Same code, same message shape: only the model's own input differs."""
    existing = tmp_path / "there.txt"
    existing.write_bytes(b"x")
    outside = signed_post(client, "/v1/read", {"path": str(existing)}).json()
    missing = signed_post(
        client, "/v1/read", {"path": str(tmp_path / "never.txt")}
    ).json()
    assert outside["error"]["code"] == "unable_to_read"
    assert missing["error"]["code"] == "unable_to_read"
    assert outside["error"]["message"] == f"Unable to read {existing}"
    assert missing["error"]["message"] == f"Unable to read {tmp_path / 'never.txt'}"


def test_denied_reads_like_missing(client, workspace):
    """AF_READ_DENY default (fresh Config) blocks .env; the answer must not
    differ from a nonexistent file."""
    denied = signed_post(
        client, "/v1/read", {"path": ".env", "cwd": client.af_workspace}
    ).json()
    nonexistent = signed_post(
        client, "/v1/read", {"path": ".env.nothere", "cwd": client.af_workspace}
    ).json()
    assert denied["error"]["message"] == "Unable to read .env"
    assert nonexistent["error"]["message"] == "Unable to read .env.nothere"
    assert denied["error"]["code"] == nonexistent["error"]["code"]


def test_containment_rejection_is_logged_not_returned(client, workspace, tmp_path, caplog):
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"x")
    with caplog.at_level("WARNING", logger="agentfiles"):
        signed_post(client, "/v1/read", {"path": str(outside)})
    # the reason lives server-side...
    assert any("containment rejected" in r.message for r in caplog.records)
    # ...while the model got only the unified message (asserted in the test above)


# --- MCP side --------------------------------------------------------------------

def _wire(tmp_path, monkeypatch):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "sub").mkdir()
    (workspace / "sub" / "a.txt").write_bytes(b"hello cwd\n")

    app = create_app(ServerConfig(workspace=str(workspace), tokens={TOKEN: SECRET}))
    tool_client = ToolClient(
        ClientConfig(url="http://testserver", token=TOKEN, secret=SECRET)
    )
    tool_client._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )
    monkeypatch.setattr(mcp_server, "_client", tool_client)
    monkeypatch.setattr(mcp_server, "_receipts", ReceiptBook())
    cwd_state.clear()
    return workspace


async def test_mcp_workspace_reports_own_cwd(tmp_path, monkeypatch):
    """workspace reports this client's own cwd; the server's workspace root is
    never fetched and never appears in the output."""
    workspace = _wire(tmp_path, monkeypatch)
    try:
        assert "not set" in await mcp_server.workspace()

        assert await mcp_server.set_cwd("sub") == (
            f"Working directory set to {os.path.realpath(workspace / 'sub')}"
        )
        cwd = cwd_state.get()
        assert cwd is not None
        assert await mcp_server.workspace() == f"Working directory: {cwd}"
    finally:
        cwd_state.clear()


async def test_mcp_relative_path_needs_set_cwd(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    try:
        with pytest.raises(Exception) as exc:
            await mcp_server._call("read", {"path": "a.txt"})
        assert "cwd_not_set" in str(exc.value)
    finally:
        cwd_state.clear()


async def test_mcp_set_cwd_then_read_works(tmp_path, monkeypatch):
    workspace = _wire(tmp_path, monkeypatch)
    try:
        await mcp_server.set_cwd("sub")
        text = await mcp_server._call("read", {"path": "a.txt"})
        assert json.loads(text)["content"] == "hello cwd\n"
    finally:
        cwd_state.clear()


async def test_mcp_set_cwd_rejects_outside(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    try:
        with pytest.raises(Exception) as exc:
            await mcp_server.set_cwd(str(tmp_path))  # outside the workspace
        assert "invalid_cwd" in str(exc.value)
        assert cwd_state.get() is None  # nothing stored on failure
    finally:
        cwd_state.clear()


async def test_receipt_is_isolated_per_cwd(tmp_path, monkeypatch):
    """The same relative spelling means different files after set_cwd: the
    receipt must not follow the path across a cwd switch."""
    workspace = _wire(tmp_path, monkeypatch)
    try:
        other = workspace / "other"
        other.mkdir()
        (other / "a.txt").write_bytes(b"OTHER FILE\n")

        await mcp_server.set_cwd("sub")
        await mcp_server._call("read", {"path": "a.txt"})
        assert len(mcp_server._receipts) == 1

        # switching cwd must start with no receipt for that spelling:
        # without this, the sub/a.txt receipt could authorize over other/a.txt
        await mcp_server.set_cwd("other")
        assert mcp_server._receipts.lookup("a.txt", cwd_state.get()) is None

        with pytest.raises(Exception) as exc:
            await mcp_server._call(
                "edit", {"path": "a.txt", "oldString": "hello cwd", "newString": "x"}
            )
        # no receipt under the new cwd -> server demands a fresh read
        assert "version_missing" in str(exc.value)
    finally:
        cwd_state.clear()


async def test_receipt_still_works_after_re_read_in_new_cwd(tmp_path, monkeypatch):
    workspace = _wire(tmp_path, monkeypatch)
    try:
        other = workspace / "other"
        other.mkdir()
        (other / "a.txt").write_bytes(b"hello cwd\n")

        await mcp_server.set_cwd("sub")
        await mcp_server._call("read", {"path": "a.txt"})
        await mcp_server.set_cwd("other")
        # same spelling, same content: re-reading under the new cwd grants a
        # fresh receipt scoped to it
        await mcp_server._call("read", {"path": "a.txt"})
        text = await mcp_server._call(
            "edit", {"path": "a.txt", "oldString": "hello cwd", "newString": "edited"}
        )
        assert text.startswith("Edited file successfully")
        assert (workspace / "other" / "a.txt").read_bytes() == b"edited\n"
        # and the sub file was never touched
        assert (workspace / "sub" / "a.txt").read_bytes() == b"hello cwd\n"
    finally:
        cwd_state.clear()
