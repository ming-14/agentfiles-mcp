"""MCP client transport: signed fetch + local temp materialization."""

from __future__ import annotations

import os

import httpx
import pytest

from agentfiles_mcp.client import ToolClient
from agentfiles_mcp.config import Config as ClientConfig
from agentfiles_mcp.transport import fetch, temp_dir
from agentfiles_server.app import create_app
from agentfiles_server.config import Config as ServerConfig
from agentfiles_shared.errors import ToolError
from agentfiles_shared.transport import DownloadDescriptor

TOKEN = "tok-tp"
SECRET = "sec-tp"

PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000a49444154789c6360000002000100ffff03000006000557bfabd400"
    "00000049454e44ae426082"
)


@pytest.fixture()
def server(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "pixel.png").write_bytes(PNG)
    app = create_app(ServerConfig(workspace=str(workspace), tokens={TOKEN: SECRET}))
    return app


def client_for(server) -> ToolClient:
    tool_client = ToolClient(
        ClientConfig(url="http://testserver", token=TOKEN, secret=SECRET)
    )
    tool_client._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server), base_url="http://testserver"
    )
    return tool_client


async def test_download_round_trip(server, tmp_path, monkeypatch):
    monkeypatch.setenv("AF_TEMP_DIR", str(tmp_path / "dl"))
    tool_client = client_for(server)
    server_path = os.path.realpath(tmp_path / "ws" / "pixel.png")

    data = await tool_client.download(server_path)
    assert data == PNG
    await tool_client.aclose()


async def test_fetch_writes_to_temp_and_returns_path(server, tmp_path, monkeypatch):
    monkeypatch.setenv("AF_TEMP_DIR", str(tmp_path / "dl"))
    tool_client = client_for(server)
    descriptor = DownloadDescriptor(
        path=os.path.realpath(tmp_path / "ws" / "pixel.png"),
        name="pixel.png",
        mime="image/png",
        size=len(PNG),
    )
    local = await fetch(tool_client, descriptor)
    assert local.exists()
    assert local.read_bytes() == PNG
    assert local.parent == temp_dir()
    # deterministic name: same descriptor maps to the same local file
    again = await fetch(tool_client, descriptor)
    assert again == local
    assert not list(local.parent.glob("*.part"))
    await tool_client.aclose()


async def test_fetch_size_mismatch_is_tool_error(server, tmp_path, monkeypatch):
    monkeypatch.setenv("AF_TEMP_DIR", str(tmp_path / "dl"))
    tool_client = client_for(server)
    descriptor = DownloadDescriptor(
        path=os.path.realpath(tmp_path / "ws" / "pixel.png"),
        name="pixel.png",
        mime="image/png",
        size=len(PNG) + 5,  # wrong on purpose
    )
    with pytest.raises(ToolError) as exc:
        await fetch(tool_client, descriptor)
    assert exc.value.code == "transport_unavailable"
    await tool_client.aclose()


async def test_download_outside_workspace_is_denied(server, tmp_path, monkeypatch):
    monkeypatch.setenv("AF_TEMP_DIR", str(tmp_path / "dl"))
    tool_client = client_for(server)
    with pytest.raises(ToolError) as exc:
        await tool_client.download(str(tmp_path / "not-here.png"))
    assert exc.value.code == "path_escape"
    await tool_client.aclose()
