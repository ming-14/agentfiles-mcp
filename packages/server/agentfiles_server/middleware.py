"""Authentication middleware: Bearer token -> timestamp -> nonce -> HMAC."""

from __future__ import annotations

import json

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from agentfiles_shared.auth import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    AuthError,
    verify,
)
from agentfiles_shared.nonce_cache import NonceCache

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
                body=body,
                authorization=request.headers.get("authorization"),
                timestamp=request.headers.get(HEADER_TIMESTAMP),
                nonce=request.headers.get(HEADER_NONCE),
                signature=request.headers.get(HEADER_SIGNATURE),
                max_skew=self._max_skew,
            )
            nonce = request.headers[HEADER_NONCE]
            self._nonces.check_and_store(nonce, ttl=self._max_skew)
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
    """Read the JSON body stashed by the middleware (or parse it if absent)."""
    cached: bytes | None = getattr(request.state, "body", None)
    if cached:
        return json.loads(cached or b"{}")
    return {}
