"""FastMCP server exposing the five V2 file tools over stdio."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from agentfiles_shared.errors import ToolError
from agentfiles_shared.schema import MAX_READ_LINES

from .client import RemoteError, ToolClient
from .config import load as load_config

mcp = FastMCP("agentfiles")

_client: ToolClient | None = None


def client() -> ToolClient:
    global _client
    if _client is None:
        _client = ToolClient(load_config())
    return _client


def _render(tool: str, payload: dict[str, Any], result: dict, model_text: str) -> str:
    """Prefer the server-rendered model text; fall back to the structured result."""
    if model_text:
        return model_text
    import json as _json

    return _json.dumps(result, ensure_ascii=False, indent=2)


async def _call(tool: str, payload: dict[str, Any]) -> str:
    try:
        result, model_text = await client().call(tool, payload)
    except ToolError:
        raise
    except RemoteError as exc:
        # surfaced to the model as a tool error rather than crashing the session
        raise ToolError("remote_unavailable", str(exc.detail)) from exc
    return _render(tool, payload, result, model_text)


@mcp.tool()
async def read(
    path: str = Field(description="Path of the file or directory to read"),
    offset: int | None = Field(
        default=None, ge=1,
        description="The 1-based directory entry or text line offset to start reading from",
    ),
    limit: int | None = Field(
        default=None, ge=1, le=MAX_READ_LINES,
        description="The maximum number of directory entries or text lines to read",
    ),
) -> str:
    """Read a text file or supported image, page through a large UTF-8 text file
    by line offset, or list a directory page."""
    payload: dict[str, Any] = {"path": path}
    if offset is not None:
        payload["offset"] = offset
    if limit is not None:
        payload["limit"] = limit
    return await _call("read", payload)


@mcp.tool()
async def write(
    path: str = Field(description="File path to write"),
    content: str = Field(description="Content to write to the file"),
) -> str:
    """Write content to one file (overwrite; parent directories are created)."""
    return await _call("write", {"path": path, "content": content})


@mcp.tool()
async def edit(
    path: str = Field(description="File path to edit"),
    oldString: str = Field(description="Exact text to replace"),
    newString: str = Field(description="Replacement text, which must differ from oldString"),
    replaceAll: bool | None = Field(
        default=None, description="Replace all exact occurrences of oldString (default false)"
    ),
) -> str:
    """Replace exact text in one file."""
    payload: dict[str, Any] = {"path": path, "oldString": oldString, "newString": newString}
    if replaceAll is not None:
        payload["replaceAll"] = replaceAll
    return await _call("edit", payload)


@mcp.tool()
async def glob(
    pattern: str = Field(description="Glob pattern to match files against"),
    path: str | None = Field(
        default=None, description="Relative directory to search. Defaults to the active Location."
    ),
    limit: int | None = Field(default=None, ge=1, description="Maximum results to return"),
) -> str:
    """Find files by glob pattern within the active Location."""
    payload: dict[str, Any] = {"pattern": pattern}
    if path is not None:
        payload["path"] = path
    if limit is not None:
        payload["limit"] = limit
    return await _call("glob", payload)


@mcp.tool()
async def grep(
    pattern: str = Field(description="Regex pattern to search for in file contents"),
    path: str | None = Field(
        default=None, description="Relative directory to search. Defaults to the active Location."
    ),
    include: str | None = Field(
        default=None, description='File glob to include (for example, "*.js" or "*.{ts,tsx}")'
    ),
    limit: int | None = Field(default=None, ge=1, description="Maximum matches to return"),
) -> str:
    """Search file contents by regular expression within the active Location."""
    payload: dict[str, Any] = {"pattern": pattern}
    if path is not None:
        payload["path"] = path
    if include is not None:
        payload["include"] = include
    if limit is not None:
        payload["limit"] = limit
    return await _call("grep", payload)
