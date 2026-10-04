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
from agentfiles_shared.errors import invalid_input, payload_too_large
from agentfiles_shared.nonce_cache import NonceCache, nonce_ttl

from .config import DEFAULT_BODY_MAX_BYTES

SIGNED_PREFIX = "/v1/"


class BodyTooLarge(Exception):
    """The body (or its declared length) exceeds the configured limit."""

    def __init__(self, size: int) -> None:
        super().__init__(size)
        self.size = size


async def read_body(request: Request, limit: int) -> bytes:
    """Buffer the request body, refusing as soon as it passes ``limit``.

    The declared Content-Length is checked first, so an oversized upload is
    turned down before a byte of it is buffered; bodies without a usable
    length (chunked) are caught by the running total. This runs ahead of
    authentication on purpose: otherwise an unauthenticated client could pin
    the process's memory with one request.
    """
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise BodyTooLarge(int(declared))

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise BodyTooLarge(total)
        chunks.append(chunk)
    return b"".join(chunks)


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, tokens: dict[str, str], max_skew: int,
                 max_body: int = DEFAULT_BODY_MAX_BYTES) -> None:
        super().__init__(app)
        self._tokens = tokens
        self._max_skew = max_skew
        self._max_body = max_body
        self._nonces = NonceCache()

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if not path.startswith(SIGNED_PREFIX):
            return await call_next(request)

        try:
            body = await read_body(request, self._max_body)
        except BodyTooLarge as exc:
            error = payload_too_large(exc.size, self._max_body)
            return JSONResponse(
                status_code=413,
                content={"ok": False, "error": error.to_payload()},
            )

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
