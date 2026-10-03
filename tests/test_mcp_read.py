"""MCP read: download descriptors become a local path for the model."""

from __future__ import annotations

import json
import os

import httpx
import pytest

import agentfiles_mcp.server as mcp_server
from agentfiles_mcp.client import ToolClient
from agentfiles_mcp.config import Config as ClientConfig
from agentfiles_server.app import create_app
from agentfiles_server.config import Config as ServerConfig

TOKEN = "tok-mcp"
SECRET = "sec-mcp"

PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000a49444154789c6360000002000100ffff03000006000557bfabd400"
    "00000049454e44ae426082"
)


@pytest.fixture()
def wired(tmp_path, monkeypatch):
    """Point the MCP server's shared client at an in-process server."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "pixel.png").write_bytes(PNG)
    (workspace / "hello.txt").write_text("hi", encoding="utf-8")

    app = create_app(ServerConfig(workspace=str(workspace), tokens={TOKEN: SECRET}))
    tool_client = ToolClient(
        ClientConfig(url="http://testserver", token=TOKEN, secret=SECRET)
    )
    tool_client._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )
    monkeypatch.setattr(mcp_server, "_client", tool_client)
    monkeypatch.setenv("AF_TEMP_DIR", str(tmp_path / "dl"))
    return workspace


async def test_read_text_returns_server_model_text(wired):
    text = await mcp_server._call("read", {"path": "hello.txt"})
    assert json.loads(text)["content"] == "hi"


async def test_read_image_downloads_and_returns_local_path(wired):
    text = await mcp_server._call("read", {"path": "pixel.png"})
    lines = text.splitlines()
    assert lines[0] == "Image read successfully"
    local = os.path.realpath(lines[1])
    assert os.path.isfile(local)
    with open(local, "rb") as handle:
        assert handle.read() == PNG


async def test_read_image_failure_keeps_error_code(wired):
    with pytest.raises(Exception) as exc:
        await mcp_server._call("read", {"path": ".env"})
    assert "unable_to_read" in str(exc.value)
