"""End-to-end: signed request through the FastAPI app (no network)."""

from __future__ import annotations

import json
import threading

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from agentfiles_mcp.client import RemoteError, ToolClient
from agentfiles_mcp.config import Config as ClientConfig
from agentfiles_server.app import create_app
from agentfiles_server.config import Config as ServerConfig
from agentfiles_server.tools import glob as glob_tool
from agentfiles_shared.auth import build_headers
from agentfiles_shared.errors import ToolError

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
        test_client.af_workspace = str(workspace)
        yield test_client


def signed_post(client: TestClient, path: str, payload: dict, *, token=TOKEN, secret=SECRET):
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = build_headers(
        token=token, secret=secret, method="POST", path=path, body=body
    ).as_dict()
    headers["Content-Type"] = "application/json"
    return client.post(path, content=body, headers=headers)


def raw_post(client: TestClient, path: str, raw: bytes, *, signature=None):
    """Post a pre-serialized (possibly invalid) body with valid signature headers."""
    headers = build_headers(
        token=TOKEN, secret=SECRET, method="POST", path=path, body=raw
    ).as_dict()
    if signature is not None:
        headers["X-Signature"] = signature
    headers["Content-Type"] = "application/json"
    return client.post(path, content=raw, headers=headers)


def _asgi_client(app, *, secret: str = SECRET) -> ToolClient:
    """ToolClient wired to a FastAPI app without touching the network."""
    tool_client = ToolClient(
        ClientConfig(url="http://testserver", token=TOKEN, secret=secret)
    )
    tool_client._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )
    return tool_client


def _bare_client() -> ToolClient:
    """ToolClient pointed at a URL that only respx answers."""
    return ToolClient(ClientConfig(url="http://testserver", token=TOKEN, secret=SECRET))


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
    body = json.dumps({"path": "x", "cwd": client.af_workspace}).encode()
    headers = build_headers(
        token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=body
    ).as_dict()
    headers["Content-Type"] = "application/json"
    first = client.post("/v1/read", content=body, headers=headers)
    second = client.post("/v1/read", content=body, headers=headers)
    # first request authenticates and reaches the handler (200 + tool error)
    assert first.status_code == 200
    assert first.json()["error"]["code"] == "unable_to_read"
    # the identical nonce may not be reused
    assert second.status_code == 401
    assert second.json()["error"]["code"] == "replayed_nonce"


def test_signed_call_reaches_handler(client):
    """A valid signed request passes auth and reaches the tool handler."""
    resp = signed_post(client, "/v1/read", {"path": "x", "cwd": client.af_workspace})
    assert resp.status_code == 200  # auth ok, handler reports missing file
    data = resp.json()
    assert data["ok"] is False
    assert data["error"]["code"] == "unable_to_read"


def test_malformed_json_body_is_invalid_input(client):
    """A body that isn't JSON is a tool error, never a 500 with a traceback."""
    resp = raw_post(client, "/v1/read", b"not-json")
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == "invalid_input"


def test_non_object_body_is_invalid_input(client):
    resp = raw_post(client, "/v1/read", b"[1,2]")
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == "invalid_input"


def test_missing_required_field_is_invalid_input(client):
    resp = raw_post(client, "/v1/edit", b'{"path":"a"}')
    error = resp.json()["error"]
    assert error["code"] == "invalid_input"
    assert "oldString" in error["message"]


def test_out_of_range_field_is_invalid_input(client):
    resp = raw_post(client, "/v1/read", b'{"path":"a","offset":0}')
    assert resp.json()["error"]["code"] == "invalid_input"


def test_valid_input_reaches_handler(client):
    body = json.dumps(
        {"path": "a", "offset": 1, "limit": 10, "cwd": client.af_workspace},
        separators=(",", ":"),
    ).encode()
    resp = raw_post(client, "/v1/read", body)
    assert resp.json()["error"]["code"] == "unable_to_read"


def test_non_ascii_signature_is_unauthorized(client):
    """latin-1 decodes to 'ünvalid'; must be a 401, not a TypeError/500."""
    resp = raw_post(client, "/v1/read", b'{"path":"a"}', signature=b"\xfcnvalid")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "bad_signature"


def test_routes_do_not_depend_on_lifespan(tmp_path):
    """Routes capture the resolver, so a client that never runs the ASGI
    lifespan (TestClient without a context manager, ASGITransport) still works."""
    app = create_app(ServerConfig(workspace=str(tmp_path), tokens={TOKEN: SECRET}))
    client = TestClient(app)  # deliberately not used as a context manager
    resp = signed_post(client, "/v1/read", {"path": "x", "cwd": str(tmp_path)})
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == "unable_to_read"


async def test_httpx_client_keeps_server_error_code(tmp_path):
    """A 401 body carries a stable code (bad_signature, ...); the client must
    not flatten it into a generic RemoteError."""
    app = create_app(ServerConfig(workspace=str(tmp_path), tokens={TOKEN: SECRET}))
    tool_client = _asgi_client(app, secret="wrong-secret")

    with pytest.raises(ToolError) as exc:
        await tool_client.call("read", {"path": "x"})
    assert exc.value.code == "bad_signature"
    await tool_client.aclose()


async def test_handler_runs_off_the_event_loop(tmp_path, monkeypatch):
    """Handlers are sync; if they ran inline in the async route, their thread
    would be the event loop's own."""
    seen: dict[str, int] = {}

    def stub_execute(resolver, config, params):
        seen["thread"] = threading.get_ident()
        return ({"matches": []}, "")

    monkeypatch.setattr(glob_tool, "execute", stub_execute)
    app = create_app(ServerConfig(workspace=str(tmp_path), tokens={TOKEN: SECRET}))
    loop_thread = threading.get_ident()

    body = json.dumps({"pattern": "*"}, separators=(",", ":")).encode()
    headers = build_headers(
        token=TOKEN, secret=SECRET, method="POST", path="/v1/glob", body=body
    ).as_dict()
    headers["Content-Type"] = "application/json"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        resp = await client.post("/v1/glob", content=body, headers=headers)
        health = await client.get("/healthz")

    assert resp.status_code == 200
    assert health.json() == {"ok": True}
    assert seen["thread"] != loop_thread


async def test_httpx_client_round_trip(tmp_path):
    """ToolClient signs correctly and unwraps the server envelope."""
    app = create_app(ServerConfig(workspace=str(tmp_path), tokens={TOKEN: SECRET}))
    tool_client = _asgi_client(app)

    with pytest.raises(ToolError) as exc:
        await tool_client.call("read", {"path": "x", "cwd": str(tmp_path)})
    assert exc.value.code == "unable_to_read"
    await tool_client.aclose()


@respx.mock
async def test_non_envelope_error_response_is_remote_error():
    """A non-200 without the error envelope (e.g. proxy 502 HTML) is a transport
    failure, not something to dress up as a tool error."""
    respx.post("http://testserver/v1/read").mock(
        return_value=httpx.Response(502, text="<html>bad gateway</html>")
    )
    tool_client = _bare_client()
    with pytest.raises(RemoteError):
        await tool_client.call("read", {"path": "x"})
    await tool_client.aclose()


@respx.mock
async def test_transport_failure_is_remote_error():
    respx.post("http://testserver/v1/read").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    tool_client = _bare_client()
    with pytest.raises(RemoteError):
        await tool_client.call("read", {"path": "x"})
    await tool_client.aclose()


@respx.mock
async def test_malformed_error_envelope_uses_default_code():
    """`error` that isn't an object must not blow up on `.get()`."""
    respx.post("http://testserver/v1/read").mock(
        return_value=httpx.Response(200, json={"ok": False, "error": "boom"})
    )
    tool_client = _bare_client()
    with pytest.raises(ToolError) as exc:
        await tool_client.call("read", {"path": "x"})
    assert exc.value.code == "remote_error"
    assert exc.value.message == "Remote tool failed"
    await tool_client.aclose()


@respx.mock
async def test_non_object_body_is_remote_error():
    """A 200 whose body isn't an envelope object must not crash on `.get()`."""
    respx.post("http://testserver/v1/read").mock(
        return_value=httpx.Response(200, json=[1, 2])
    )
    tool_client = _bare_client()
    with pytest.raises(RemoteError):
        await tool_client.call("read", {"path": "x"})
    await tool_client.aclose()


# --- request body limit ------------------------------------------------------

def body_of_size(size: int) -> bytes:
    """A well-formed request whose serialized length is exactly ``size``."""
    pad = size - len('{"path":""}')
    assert pad > 0
    body = json.dumps({"path": "x" * pad}, separators=(",", ":")).encode()
    assert len(body) == size
    return body


def limited_client(tmp_path, limit: int) -> TestClient:
    app = create_app(
        ServerConfig(workspace=str(tmp_path), tokens={TOKEN: SECRET},
                     max_body_bytes=limit)
    )
    return TestClient(app)


def test_oversized_body_is_refused(tmp_path):
    client = limited_client(tmp_path, 1024)
    resp = raw_post(client, "/v1/write", body_of_size(4096))
    assert resp.status_code == 413
    assert resp.json() == {
        "ok": False,
        "error": {
            "code": "payload_too_large",
            "message": "Request body is 4096 bytes, exceeding the 1024 byte limit",
        },
    }


def test_body_at_the_limit_still_reaches_the_handler(tmp_path):
    client = limited_client(tmp_path, 1024)
    resp = raw_post(client, "/v1/read", body_of_size(1024))
    assert resp.status_code == 200
    # the exact-size body carries no cwd: reaching this error proves the
    # handler ran (the body limit check passed) without changing the length
    assert resp.json()["error"]["code"] == "cwd_not_set"


def test_oversized_body_is_refused_before_authentication(tmp_path):
    """The limit has to hold without credentials too -- that is what stops an
    unauthenticated client from buffering an unbounded body."""
    client = limited_client(tmp_path, 1024)
    resp = client.post("/v1/read", content=body_of_size(4096))
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "payload_too_large"


async def test_client_surfaces_payload_too_large(tmp_path):
    """A 413 envelope reaches the model as a tool error, not a transport one."""
    app = create_app(
        ServerConfig(workspace=str(tmp_path), tokens={TOKEN: SECRET},
                     max_body_bytes=1024)
    )
    tool_client = _asgi_client(app)
    with pytest.raises(ToolError) as exc:
        await tool_client.call("write", {"path": "big.txt", "content": "x" * 4096})
    assert exc.value.code == "payload_too_large"
    await tool_client.aclose()


async def test_body_without_a_length_is_cut_off_mid_stream():
    """Chunked requests carry no Content-Length: the running total has to stop
    the read at the limit -- and stop, instead of draining what follows."""
    from agentfiles_server.middleware import BodyTooLarge, read_body
    from starlette.requests import Request

    pulled = 0

    async def receive():
        nonlocal pulled
        pulled += 1
        if pulled > 2:
            raise AssertionError("body was read past the limit")
        return {"type": "http.request", "body": b"x" * 600, "more_body": True}

    request = Request(
        {"type": "http", "method": "POST", "path": "/v1/read", "headers": []},
        receive,
    )
    with pytest.raises(BodyTooLarge) as exc:
        await read_body(request, 1024)
    assert exc.value.size == 1200
    assert pulled == 2
