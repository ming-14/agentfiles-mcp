"""HMAC-SHA256 request signing (shared by server middleware and MCP client).

Canonical string:

    v1\n{timestamp}\n{nonce}\n{METHOD}\n{path}\n{sha256_hex(body)}

Headers:
    Authorization: Bearer <token>
    X-Timestamp:   <unix seconds>
    X-Nonce:       <8-128 hex chars>   (clients send 32: secrets.token_hex(16))
    X-Signature:   <hex hmac-sha256>
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string
import time
from dataclasses import dataclass

SIGNATURE_VERSION = "v1"
DEFAULT_MAX_SKEW = 300  # seconds
NONCE_BYTES = 16
NONCE_MIN_LENGTH = 8
NONCE_MAX_LENGTH = 128

HEADER_AUTHORIZATION = "authorization"
HEADER_TIMESTAMP = "X-Timestamp"
HEADER_NONCE = "X-Nonce"
HEADER_SIGNATURE = "X-Signature"


class AuthError(Exception):
    """Raised on any authentication/signature failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


_HEX_DIGITS = frozenset(string.hexdigits)


def is_hex(value: str) -> bool:
    """True for a non-empty ASCII hex string.

    ``hmac.compare_digest`` raises ``TypeError`` when either operand is a
    non-ASCII ``str``, so every header that reaches it must be screened first.
    """
    return bool(value) and all(char in _HEX_DIGITS for char in value)


def new_nonce() -> str:
    return secrets.token_hex(NONCE_BYTES)


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_string(
    *, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> str:
    return "\n".join(
        [SIGNATURE_VERSION, timestamp, nonce, method.upper(), path, body_hash(body)]
    )


def sign(
    secret: str, *, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> str:
    message = canonical_string(
        method=method, path=path, timestamp=timestamp, nonce=nonce, body=body
    ).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class SignedHeaders:
    """The four headers a client must attach to every signed request."""

    authorization: str
    timestamp: str
    nonce: str
    signature: str

    def as_dict(self) -> dict[str, str]:
        return {
            "Authorization": self.authorization,
            HEADER_TIMESTAMP: self.timestamp,
            HEADER_NONCE: self.nonce,
            HEADER_SIGNATURE: self.signature,
        }


def build_headers(
    *, token: str, secret: str, method: str, path: str, body: bytes,
    timestamp: int | None = None, nonce: str | None = None,
) -> SignedHeaders:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    n = nonce or new_nonce()
    sig = sign(secret, method=method, path=path, timestamp=ts, nonce=n, body=body)
    return SignedHeaders(
        authorization=f"Bearer {token}",
        timestamp=ts,
        nonce=n,
        signature=sig,
    )


def _bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise AuthError("missing_authorization", "Missing Authorization header")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AuthError("invalid_authorization", "Authorization must be Bearer <token>")
    return parts[1].strip()


def verify(
    *,
    secrets_for_token: dict[str, str],
    method: str,
    path: str,
    body: bytes,
    authorization: str | None,
    timestamp: str | None,
    nonce: str | None,
    signature: str | None,
    now: int | None = None,
    max_skew: int = DEFAULT_MAX_SKEW,
) -> str:
    """Validate the four headers. Returns the authenticated token.

    Raises AuthError with a stable ``code`` on any failure.
    The caller is responsible for nonce replay caching (see ``nonce_cache.py``).
    """
    token = _bearer_token(authorization)
    secret = secrets_for_token.get(token)
    if secret is None:
        raise AuthError("unknown_token", "Unknown bearer token")

    if timestamp is None or nonce is None or signature is None:
        raise AuthError(
            "missing_signature_headers",
            "Missing X-Timestamp, X-Nonce or X-Signature header",
        )
    try:
        ts = int(timestamp)
    except ValueError:
        raise AuthError("invalid_timestamp", "X-Timestamp must be unix seconds") from None

    current = int(time.time()) if now is None else now
    if abs(current - ts) > max_skew:
        raise AuthError("stale_timestamp", "Request timestamp outside allowed window")
    if (
        len(nonce) < NONCE_MIN_LENGTH
        or len(nonce) > NONCE_MAX_LENGTH
        or not is_hex(nonce)
    ):
        raise AuthError(
            "invalid_nonce",
            f"X-Nonce must be {NONCE_MIN_LENGTH}-{NONCE_MAX_LENGTH} hex characters",
        )

    if not is_hex(signature):
        # screened before compare_digest, which rejects non-ASCII str operands
        raise AuthError("bad_signature", "Signature verification failed")

    expected = sign(
        secret, method=method, path=path, timestamp=timestamp, nonce=nonce, body=body
    )
    if not hmac.compare_digest(expected, signature.lower()):
        raise AuthError("bad_signature", "Signature verification failed")
    return token
