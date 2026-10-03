"""End-to-end: signed request through the FastAPI app (no network)."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from agentfiles_mcp.client import ToolClient
from agentfiles_mcp.config import Config as ClientConfig
from agentfiles_server.app import create_app
from agentfiles_server.config import Config as ServerConfig

TOKEN = "tok-e2e"
SECRET = "sec-e2e"


@pytest.fixture()
def client(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    app = create_app(
        ServerConfig(workspace=str(workspace), tokens={TOKEN: SECRET})
    )
    with TestClient(app) as test_client:
        yield test_client


def signed_post(client: TestClient, path: str, payload: dict, *, token=TOKEN, secret=SECRET):
    from agentfiles_shared.auth import build_headers

    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = build_headers(
        token=token, secret=secret, method="POST", path=path, body=body
    ).as_dict()
    headers["Content-Type"] = "application/json"
    return client.post(path, content=body, headers=headers)


def test_healthz_no_signature_needed(client):
    assert client.get("/healthz").json() == {"ok": True}


def test_unsigned_request_rejected(client):
    resp = client.post("/v1/read", json={"path": "x"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "missing_authorization"


def test_wrong_token_rejected(client):
    resp = signed_post(client, "/v1/read", {"path": "x"}, token="nope")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unknown_token"


def test_wrong_secret_rejected(client):
    resp = signed_post(client, "/v1/read", {"path": "x"}, secret="bad")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "bad_signature"


def test_tampered_body_rejected(client):
    from agentfiles_shared.auth import build_headers

    body = json.dumps({"path": "a"}).encode()
    headers = build_headers(
        token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=body
    ).as_dict()
    headers["Content-Type"] = "application/json"
    tampered = json.dumps({"path": "b"}).encode()
    resp = client.post("/v1/read", content=tampered, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "bad_signature"


def test_replay_rejected(client):
    from agentfiles_shared.auth import build_headers

    body = json.dumps({"path": "x"}).encode()
    headers = build_headers(
        token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=body
    ).as_dict()
    headers["Content-Type"] = "application/json"
    first = client.post("/v1/read", content=body, headers=headers)
    second = client.post("/v1/read", content=body, headers=headers)
    # first request authenticates and reaches the handler (200 + tool error)
    assert first.status_code == 200
    assert first.json()["error"]["code"] == "not_implemented"
    # the identical nonce may not be reused
    assert second.status_code == 401
    assert second.json()["error"]["code"] == "replayed_nonce"


def test_signed_call_reaches_handler(client, monkeypatch):
    """A valid signed request passes auth and reaches the tool handler."""
    resp = signed_post(client, "/v1/read", {"path": "x"})
    assert resp.status_code == 200  # auth ok, handler raises not_implemented
    data = resp.json()
    assert data["ok"] is False
    assert data["error"]["code"] == "not_implemented"


def test_httpx_client_round_trip(monkeypatch, tmp_path):
    """ToolClient signs correctly and unwraps the server envelope."""
    import httpx

    from agentfiles_mcp.client import ToolClient
    from agentfiles_mcp.config import Config as ClientConfig
    from agentfiles_server.fslayer import Resolver

    app = create_app(ServerConfig(workspace=str(tmp_path), tokens={TOKEN: SECRET}))
    # ASGITransport does not run lifespan; initialize state manually
    app.state.resolver = Resolver(str(tmp_path))

    tool_client = ToolClient(
        ClientConfig(url="http://testserver", token=TOKEN, secret=SECRET)
    )
    tool_client._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )

    from agentfiles_shared.errors import ToolError

    async def run():
        with pytest.raises(ToolError) as exc:
            await tool_client.call("read", {"path": "x"})
        assert exc.value.code == "not_implemented"
        await tool_client.aclose()

    import asyncio

    asyncio.run(run())
