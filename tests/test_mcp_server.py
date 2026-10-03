"""MCP proxy: schema single-sourcing, wire aliases, error text, lifespan."""

from __future__ import annotations

import pytest

import agentfiles_mcp.server as server
from agentfiles_shared.errors import ToolError
from agentfiles_shared.schema import (
    EditInput,
    GlobInput,
    GrepInput,
    ReadInput,
    WriteInput,
)

MODELS = {
    "read": ReadInput,
    "write": WriteInput,
    "edit": EditInput,
    "glob": GlobInput,
    "grep": GrepInput,
}


class RecordingClient:
    """Stands in for ToolClient; records the payload that would go on the wire."""

    def __init__(self, error: ToolError | None = None) -> None:
        self.error = error
        self.tool: str | None = None
        self.payload: dict | None = None

    async def call(self, tool: str, payload: dict) -> tuple[dict, str]:
        self.tool, self.payload = tool, payload
        if self.error is not None:
            raise self.error
        return {}, "model text"

    async def aclose(self) -> None:
        pass


# Internal-only wire fields: the MCP layer manages these itself (version
# receipts are attached/recorded by the proxy, invisible to the model).
INTERNAL_FIELDS = {"expectedVersion"}


async def test_tool_schemas_are_single_sourced():
    """Every MCP input schema must equal the shared schema model's schema —
    the FieldInfo is borrowed, so drift is structurally impossible.
    Internal-only fields (version receipts) are hidden from the model."""
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    assert set(tools) == set(MODELS)
    for name, model in MODELS.items():
        want = model.model_json_schema()
        got = tools[name].inputSchema
        want_props = {
            key: value
            for key, value in want["properties"].items()
            if key not in INTERNAL_FIELDS
        }
        assert got["properties"] == want_props, name
        assert set(got["required"]) == set(want.get("required", [])), name


async def test_edit_payload_uses_wire_aliases(monkeypatch):
    client = RecordingClient()
    monkeypatch.setattr(server, "_client", client)
    await server.mcp.call_tool(
        "edit", {"path": "a", "oldString": "x", "newString": "y", "replaceAll": True}
    )
    assert client.tool == "edit"
    assert client.payload == {
        "path": "a",
        "oldString": "x",
        "newString": "y",
        "replaceAll": True,
    }


async def test_optional_nulls_are_omitted_from_payload(monkeypatch):
    client = RecordingClient()
    monkeypatch.setattr(server, "_client", client)
    await server.mcp.call_tool("glob", {"pattern": "*"})
    assert client.payload == {"pattern": "*"}


async def test_tool_error_code_survives_fastmcp(monkeypatch):
    """FastMCP stringifies exceptions, so the code is carried in the text."""
    monkeypatch.setattr(
        server, "_client", RecordingClient(error=ToolError("unauthorized", "nope"))
    )
    with pytest.raises(Exception) as exc:
        await server.mcp.call_tool("read", {"path": "x"})
    assert "[unauthorized] nope" in str(exc.value)


async def test_lifespan_owns_and_closes_the_http_client(monkeypatch):
    closed: list[bool] = []

    class FakeClient:
        async def aclose(self) -> None:
            closed.append(True)

    monkeypatch.setattr(server, "ToolClient", lambda config: FakeClient())
    monkeypatch.setattr(server, "load_config", lambda: object())
    monkeypatch.setattr(server, "_client", None)

    async with server._lifespan(None) as client:
        assert server._client is client
    assert closed == [True]
    assert server._client is None
