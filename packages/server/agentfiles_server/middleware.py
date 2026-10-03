"""Authentication middleware: Bearer token -> timestamp -> nonce -> HMAC."""

from __future__ import annotations

import json

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from agentfiles_shared.auth import (
    HEADER_AUTHORIZATION,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    AuthError,
    verify,
)
from agentfiles_shared.errors import invalid_input
from agentfiles_shared.nonce_cache import NonceCache, nonce_ttl

SIGNED_PREFIX = "/v1/"


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, tokens: dict[str, str], max_skew: int) -> None:
        super().__init__(app)
        self._tokens = tokens
        self._max_skew = max_skew
        self._nonces = NonceCache()

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if not path.startswith(SIGNED_PREFIX):
            return await call_next(request)

        body = await request.body()
        try:
            token = verify(
                secrets_for_token=self._tokens,
                method=request.method,
                path=path,
                query=request.url.query,
                body=body,
                authorization=request.headers.get(HEADER_AUTHORIZATION),
                timestamp=request.headers.get(HEADER_TIMESTAMP),
                nonce=request.headers.get(HEADER_NONCE),
                signature=request.headers.get(HEADER_SIGNATURE),
                max_skew=self._max_skew,
            )
            nonce = request.headers[HEADER_NONCE]
            self._nonces.check_and_store(nonce, ttl=nonce_ttl(self._max_skew))
        except AuthError as exc:
            return JSONResponse(
                status_code=401,
                content={"ok": False, "error": {"code": exc.code, "message": exc.message}},
            )

        request.state.token = token
        # body was consumed by dispatch; stash it so handlers can re-read it
        request.state.body = body
        return await call_next(request)


def parse_body(request: Request) -> dict:
    """Read the JSON object the auth middleware stashed on the request.

    Raises ``ToolError('invalid_input')`` -- never a bare ``JSONDecodeError`` --
    so a malformed body reaches the model as a tool error instead of a 500.
    """
    cached: bytes | None = getattr(request.state, "body", None)
    if not cached:
        return {}
    try:
        data = json.loads(cached)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise invalid_input(f"body is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise invalid_input("body must be a JSON object")
    return data
