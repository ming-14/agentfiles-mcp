"""FastMCP server exposing the five V2 file tools over stdio.

Exposed names carry a ``remote_`` prefix (``remote_read``, ...) so the file
tools do not collide with same-named local tools the host may already offer;
``workspace`` and ``set_cwd`` stay unprefixed, being this server's own
concepts. The ``tool`` string passed to :func:`_call` is the server route
(``/v1/read``, ...) and never carries the prefix.

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
from agentfiles_shared.transport import DownloadDescriptor

from . import cwd as cwd_state
from .client import RemoteError, ToolClient
from .config import load as load_config
from .receipts import ReceiptBook, record_result
from . import transport as file_transport

_client: ToolClient | None = None
_receipts = ReceiptBook()


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
    # the request cwd rides along: relative paths resolve against it,
    # server-side. The server re-verifies every resulting file itself, so
    # this is resolution context, not authority.
    cwd = cwd_state.get()
    if cwd is not None:
        payload = {**payload, "cwd": cwd}
    path = str(payload.get("path", ""))
    # write/edit carry the last observed version; the server verifies it
    # against fstat and answers version_missing when we have never read the file
    if tool in ("write", "edit"):
        receipt = _receipts.lookup(path, cwd)
        if receipt is not None:
            payload = {**payload, "expectedVersion": receipt}
    try:
        result, model_text = await client().call(tool, payload)
    except RemoteError as exc:
        # surfaced to the model as a tool error rather than crashing the session
        raise ToolError("remote_unavailable", str(exc.detail)) from exc
    except ToolError as exc:
        # a stale or missing receipt is the model's signal to read again;
        # drop it so the next attempt re-verifies from scratch
        if exc.code in ("version_missing", "version_mismatch"):
            _receipts.forget(path, cwd)
        # FastMCP flattens any exception into `Error executing tool <name>:
        # <str(e)>`, which would drop ``exc.code``; carry it in the text.
        raise ToolError(exc.code, f"[{exc.code}] {exc.message}") from exc
    # receipts are keyed by (cwd, path): the returned version.path is a
    # server-absolute path the MCP layer cannot re-derive for relative input,
    # and the same spelling means a different file after set_cwd
    record_result(_receipts, path, result, cwd)
    if result.get("type") == "download":
        return await _materialize(result, model_text)
    return _render(result, model_text)


async def _materialize(result: dict[str, Any], model_text: str) -> str:
    """Fetch a download descriptor into the local temp dir; return its path.

    The model needs a local path it can hand to other tools, so the success
    text and the path are returned together.
    """
    descriptor = DownloadDescriptor.model_validate(result)
    try:
        local = await file_transport.fetch(client(), descriptor)
    except ToolError as exc:
        raise ToolError(exc.code, f"[{exc.code}] {exc.message}") from exc
    prefix = model_text or "File downloaded"
    return f"{prefix}\n{local}"


# Field definitions borrowed from the shared schema models (see module docstring).
_READ = ReadInput.model_fields
_WRITE = WriteInput.model_fields
_EDIT = EditInput.model_fields
_GLOB = GlobInput.model_fields
_GREP = GrepInput.model_fields


@mcp.tool()
async def remote_read(
    path: Annotated[str, _READ["path"]],
    offset: Annotated[int | None, _READ["offset"]] = None,
    limit: Annotated[int | None, _READ["limit"]] = None,
) -> str:
    """Read a text file or supported image, page through a large UTF-8 text file
    by line offset, or list a directory page."""
    params = ReadInput(path=path, offset=offset, limit=limit)
    return await _call("read", _payload(params))


@mcp.tool()
async def remote_write(
    path: Annotated[str, _WRITE["path"]],
    content: Annotated[str, _WRITE["content"]],
) -> str:
    """Write content to one file (overwrite; parent directories are created)."""
    return await _call("write", _payload(WriteInput(path=path, content=content)))


@mcp.tool()
async def remote_edit(
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
async def remote_glob(
    pattern: Annotated[str, _GLOB["pattern"]],
    path: Annotated[str | None, _GLOB["path"]] = None,
    limit: Annotated[int | None, _GLOB["limit"]] = None,
) -> str:
    """Find files by glob pattern within the active Location."""
    params = GlobInput(pattern=pattern, path=path, limit=limit)
    return await _call("glob", _payload(params))


@mcp.tool()
async def remote_grep(
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


@mcp.tool()
async def workspace() -> str:
    """Show this client's working directory: the base relative paths resolve
    against, set by set_cwd.

    Paths here are the server's namespace, not directories on your local
    machine. set_cwd resolves relative input against the server's workspace
    root, so this can report that root.
    """
    return cwd_state.describe()


@mcp.tool()
async def set_cwd(path: str) -> str:
    """Set the working directory for subsequent relative paths.

    The server validates the directory through a handle (must exist, be a
    directory, sit inside its workspace, and not match its deny rules) and
    returns its resolved path; only then is it stored. Absolute paths never
    need this. Relative input resolves against the server's workspace root,
    the only base there is before a cwd exists -- so set_cwd(".") yields that
    root. Starting state is unset: a relative path sent before set_cwd fails
    with cwd_not_set rather than resolving against an arbitrary default.
    """
    try:
        resolved = await client().set_cwd(path)
    except RemoteError as exc:
        raise ToolError("remote_unavailable", str(exc.detail)) from exc
    except ToolError as exc:
        raise ToolError(exc.code, f"[{exc.code}] {exc.message}") from exc
    cwd_state.set(resolved)
    return f"Working directory set to {resolved}"
