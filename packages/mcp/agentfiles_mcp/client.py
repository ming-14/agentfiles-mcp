"""Signed HTTP client for agentfiles-server."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import httpx

from agentfiles_shared.auth import build_headers
from agentfiles_shared.errors import ToolError
from agentfiles_shared.transport import DOWNLOAD_PATH

from .config import Config


class RemoteError(Exception):
    """Transport-level failure (network, non-2xx, malformed body)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _error_payload(response: httpx.Response) -> dict[str, Any] | None:
    """The server's ``{"error": {"code", "message"}}`` body, when there is one."""
    try:
        data = response.json()
    except ValueError:
        return None
    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict) and error.get("code"):
        return error
    return None


def _tool_error(error: Any, fallback_message: str) -> ToolError:
    """ToolError from an error envelope; tolerates a malformed envelope."""
    if not isinstance(error, dict):
        error = {}
    return ToolError(
        str(error.get("code", "remote_error")),
        str(error.get("message") or fallback_message),
    )


class ToolClient:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._http = httpx.AsyncClient(base_url=config.url, timeout=config.timeout)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def download(self, server_path: str) -> bytes:
        """Signed GET /v1/transport/download?path=... returning raw bytes.

        The query string is part of the canonical signature, so the target
        path cannot be swapped after signing.
        """
        query = f"path={quote(server_path, safe='')}"
        headers = build_headers(
            token=self._config.token,
            secret=self._config.secret,
            method="GET",
            path=DOWNLOAD_PATH,
            body=b"",
            query=query,
        ).as_dict()

        try:
            response = await self._http.get(f"{DOWNLOAD_PATH}?{query}", headers=headers)
        except httpx.HTTPError as exc:
            raise RemoteError(f"download failed: {exc.__class__.__name__}") from exc

        if response.status_code != 200:
            error = _error_payload(response)
            if error is None:
                raise RemoteError(f"download returned HTTP {response.status_code}")
            raise _tool_error(error, f"download returned HTTP {response.status_code}")
        return response.content

    async def call(self, tool: str, payload: dict[str, Any]) -> tuple[dict, str]:
        """POST /v1/<tool> with signature headers; returns (result, modelText).

        Raises ToolError for tool-level failures the model should see,
        RemoteError for transport problems.
        """
        path = f"/v1/{tool}"
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = build_headers(
            token=self._config.token,
            secret=self._config.secret,
            method="POST",
            path=path,
            body=body,
        ).as_dict()
        headers["Content-Type"] = "application/json"

        try:
            response = await self._http.post(path, content=body, headers=headers)
        except httpx.HTTPError as exc:
            raise RemoteError(f"request to {path} failed: {exc.__class__.__name__}") from exc

        if response.status_code != 200:
            # 401 carries a stable code (unknown_token, bad_signature, ...);
            # flattening it to "HTTP 401" would lose it downstream.
            error = _error_payload(response)
            if error is None:
                raise RemoteError(f"{path} returned HTTP {response.status_code}")
            raise _tool_error(error, f"{path} returned HTTP {response.status_code}")

        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise RemoteError(f"{path} returned non-JSON body") from exc
        if not isinstance(data, dict):
            raise RemoteError(f"{path} returned an unexpected body")

        if not data.get("ok"):
            raise _tool_error(data.get("error"), "Remote tool failed")
        return data.get("result") or {}, data.get("modelText") or ""
