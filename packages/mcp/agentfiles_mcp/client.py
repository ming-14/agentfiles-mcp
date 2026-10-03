"""Signed HTTP client for agentfiles-server."""

from __future__ import annotations

import json
from typing import Any

import httpx

from agentfiles_shared.auth import build_headers
from agentfiles_shared.errors import ToolError

from .config import Config


class RemoteError(Exception):
    """Transport-level failure (network, non-2xx, malformed body)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class ToolClient:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._http = httpx.AsyncClient(base_url=config.url, timeout=config.timeout)

    async def aclose(self) -> None:
        await self._http.aclose()

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
            raise RemoteError(f"{path} returned HTTP {response.status_code}")

        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise RemoteError(f"{path} returned non-JSON body") from exc

        if not data.get("ok"):
            error = data.get("error") or {}
            raise ToolError(
                str(error.get("code", "remote_error")),
                str(error.get("message", "Remote tool failed")),
            )
        return data.get("result") or {}, data.get("modelText") or ""
