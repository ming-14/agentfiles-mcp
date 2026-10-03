"""FastMCP server exposing the five V2 file tools over stdio.

Parameter descriptions and constraints are not repeated here: every tool
parameter borrows the ``FieldInfo`` from ``agentfiles_shared.schema``, which is
the single source of truth for both the REST and the MCP input schemas.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from agentfiles_shared.errors import ToolError
from agentfiles_shared.schema import (
    EditInput,
    GlobInput,
    GrepInput,
    ReadInput,
    WriteInput,
)

from .client import RemoteError, ToolClient
from .config import load as load_config

_client: ToolClient | None = None


@asynccontextmanager
async def _lifespan(_server: FastMCP[Any]):
    """Own the shared httpx client: create it at startup, close it at exit."""
    global _client
    _client = ToolClient(load_config())
    try:
        yield _client
    finally:
        await _client.aclose()
        _client = None


mcp = FastMCP("agentfiles", lifespan=_lifespan)


def client() -> ToolClient:
    """Fall back to lazy creation when the lifespan hasn't run (tests)."""
    global _client
    if _client is None:
        _client = ToolClient(load_config())
    return _client


def _payload(model: BaseModel) -> dict[str, Any]:
    """Wire payload: the schema model under its field aliases, nulls omitted."""
    return model.model_dump(by_alias=True, exclude_none=True)


def _render(result: dict, model_text: str) -> str:
    """Prefer the server-rendered model text; fall back to the structured result."""
    if model_text:
        return model_text
    return json.dumps(result, ensure_ascii=False, indent=2)


async def _call(tool: str, payload: dict[str, Any]) -> str:
    try:
        result, model_text = await client().call(tool, payload)
    except RemoteError as exc:
        # surfaced to the model as a tool error rather than crashing the session
        raise ToolError("remote_unavailable", str(exc.detail)) from exc
    except ToolError as exc:
        # FastMCP flattens any exception into `Error executing tool <name>:
        # <str(e)>`, which would drop ``exc.code``; carry it in the text.
        raise ToolError(exc.code, f"[{exc.code}] {exc.message}") from exc
    return _render(result, model_text)


# Field definitions borrowed from the shared schema models (see module docstring).
_READ = ReadInput.model_fields
_WRITE = WriteInput.model_fields
_EDIT = EditInput.model_fields
_GLOB = GlobInput.model_fields
_GREP = GrepInput.model_fields


@mcp.tool()
async def read(
    path: Annotated[str, _READ["path"]],
    offset: Annotated[int | None, _READ["offset"]] = None,
    limit: Annotated[int | None, _READ["limit"]] = None,
) -> str:
    """Read a text file or supported image, page through a large UTF-8 text file
    by line offset, or list a directory page."""
    params = ReadInput(path=path, offset=offset, limit=limit)
    return await _call("read", _payload(params))


@mcp.tool()
async def write(
    path: Annotated[str, _WRITE["path"]],
    content: Annotated[str, _WRITE["content"]],
) -> str:
    """Write content to one file (overwrite; parent directories are created)."""
    return await _call("write", _payload(WriteInput(path=path, content=content)))


@mcp.tool()
async def edit(
    path: Annotated[str, _EDIT["path"]],
    oldString: Annotated[str, _EDIT["old_string"]],
    newString: Annotated[str, _EDIT["new_string"]],
    replaceAll: Annotated[bool | None, _EDIT["replace_all"]] = None,
) -> str:
    """Replace exact text in one file."""
    params = EditInput(
        path=path, oldString=oldString, newString=newString, replaceAll=replaceAll
    )
    return await _call("edit", _payload(params))


@mcp.tool()
async def glob(
    pattern: Annotated[str, _GLOB["pattern"]],
    path: Annotated[str | None, _GLOB["path"]] = None,
    limit: Annotated[int | None, _GLOB["limit"]] = None,
) -> str:
    """Find files by glob pattern within the active Location."""
    params = GlobInput(pattern=pattern, path=path, limit=limit)
    return await _call("glob", _payload(params))


@mcp.tool()
async def grep(
    pattern: Annotated[str, _GREP["pattern"]],
    path: Annotated[str | None, _GREP["path"]] = None,
    include: Annotated[str | None, _GREP["include"]] = None,
    limit: Annotated[int | None, _GREP["limit"]] = None,
) -> str:
    """Search file contents by regular expression within the active Location."""
    params = GrepInput(
        pattern=pattern, path=path, include=include, limit=limit
    )
    return await _call("grep", _payload(params))
