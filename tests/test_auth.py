"""Signature round-trip, skew, replay, and tamper tests."""

from __future__ import annotations

import pytest

from agentfiles_shared.auth import (
    AuthError,
    DEFAULT_MAX_SKEW,
    build_headers,
    verify,
)
from agentfiles_shared.nonce_cache import NonceCache, nonce_ttl

TOKEN = "test-token"
SECRET = "test-secret"
SECRETS = {TOKEN: SECRET}
BODY = b'{"path":"src/main.ts"}'


def do_verify(headers, **overrides):
    args = {
        "secrets_for_token": SECRETS,
        "method": "POST",
        "path": "/v1/read",
        "body": BODY,
        "authorization": headers.authorization,
        "timestamp": headers.timestamp,
        "nonce": headers.nonce,
        "signature": headers.signature,
    }
    args.update(overrides)
    return verify(**args)


def test_round_trip():
    headers = build_headers(token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY)
    assert do_verify(headers) == TOKEN


def test_unknown_token():
    headers = build_headers(token="nope", secret=SECRET, method="POST", path="/v1/read", body=BODY)
    with pytest.raises(AuthError) as exc:
        do_verify(headers)
    assert exc.value.code == "unknown_token"


def test_missing_authorization():
    headers = build_headers(token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY)
    with pytest.raises(AuthError) as exc:
        do_verify(headers, authorization=None)
    assert exc.value.code == "missing_authorization"


def test_malformed_authorization():
    headers = build_headers(token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY)
    with pytest.raises(AuthError) as exc:
        do_verify(headers, authorization=f"Basic {TOKEN}")
    assert exc.value.code == "invalid_authorization"


def test_stale_timestamp_rejected():
    now = 1_759_478_400
    headers = build_headers(
        token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY,
        timestamp=now - DEFAULT_MAX_SKEW - 1,
    )
    with pytest.raises(AuthError) as exc:
        do_verify(headers, now=now)
    assert exc.value.code == "stale_timestamp"


def test_timestamp_within_window_accepted():
    now = 1_759_478_400
    headers = build_headers(
        token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY, timestamp=now
    )
    assert do_verify(headers, now=now) == TOKEN


def test_tampered_body_rejected():
    headers = build_headers(token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY)
    with pytest.raises(AuthError) as exc:
        verify(
            secrets_for_token=SECRETS,
            method="POST",
            path="/v1/read",
            body=b'{"path":"src/evil.ts"}',
            authorization=headers.authorization,
            timestamp=headers.timestamp,
            nonce=headers.nonce,
            signature=headers.signature,
        )
    assert exc.value.code == "bad_signature"


def test_tampered_path_rejected():
    headers = build_headers(token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY)
    with pytest.raises(AuthError) as exc:
        verify(
            secrets_for_token=SECRETS,
            method="POST",
            path="/v1/write",
            body=BODY,
            authorization=headers.authorization,
            timestamp=headers.timestamp,
            nonce=headers.nonce,
            signature=headers.signature,
        )
    assert exc.value.code == "bad_signature"


def test_wrong_secret_rejected():
    headers = build_headers(token=TOKEN, secret="other", method="POST", path="/v1/read", body=BODY)
    with pytest.raises(AuthError) as exc:
        do_verify(headers)
    assert exc.value.code == "bad_signature"


def test_missing_signature_headers():
    headers = build_headers(token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY)
    with pytest.raises(AuthError) as exc:
        do_verify(headers, nonce=None, signature=None)
    assert exc.value.code == "missing_signature_headers"


def test_nonce_replay_rejected():
    headers = build_headers(token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY)
    cache = NonceCache()
    cache.check_and_store(headers.nonce, ttl=DEFAULT_MAX_SKEW)
    with pytest.raises(AuthError) as exc:
        cache.check_and_store(headers.nonce, ttl=DEFAULT_MAX_SKEW)
    assert exc.value.code == "replayed_nonce"


def test_nonce_expires_after_ttl():
    cache = NonceCache()
    cache.check_and_store("abc12345", ttl=300, now=1000.0)
    # after the ttl the nonce may be forgotten (a replay outside the window
    # is already rejected by the timestamp check)
    cache.check_and_store("abc12345", ttl=300, now=1000.0 + 301)


def test_nonce_outlives_signature_window():
    """A replay stays rejected for the whole ±max_skew window.

    With ttl == max_skew a nonce could expire while its timestamp is still
    accepted (client clock ahead of the server), reopening the replay window.
    """
    skew = DEFAULT_MAX_SKEW
    ttl = nonce_ttl(skew)
    assert ttl == 2 * skew
    cache = NonceCache()
    cache.check_and_store("abc12345", ttl=ttl, now=1_000_000.0)
    with pytest.raises(AuthError) as exc:
        cache.check_and_store("abc12345", ttl=ttl, now=1_000_000.0 + skew + 1)
    assert exc.value.code == "replayed_nonce"
    # ...and is forgotten once the full window has passed
    cache.check_and_store("abc12345", ttl=ttl, now=1_000_000.0 + ttl + 1)


def test_nonce_must_be_hex():
    headers = build_headers(token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY)
    with pytest.raises(AuthError) as exc:
        do_verify(headers, nonce="not a hex nonce")
    assert exc.value.code == "invalid_nonce"


def test_non_ascii_signature_is_rejected_not_crash():
    """Non-ASCII signature -> bad_signature, never TypeError.

    hmac.compare_digest() raises TypeError on non-ASCII str operands, which
    would otherwise escape verify() as a 500 in the auth middleware.
    """
    headers = build_headers(token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY)
    with pytest.raises(AuthError) as exc:
        do_verify(headers, signature="ünvalid")
    assert exc.value.code == "bad_signature"


def test_signature_must_be_hex():
    headers = build_headers(token=TOKEN, secret=SECRET, method="POST", path="/v1/read", body=BODY)
    with pytest.raises(AuthError) as exc:
        do_verify(headers, signature="0x" + "a" * 64)
    assert exc.value.code == "bad_signature"
