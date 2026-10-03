"""Bounded in-memory nonce cache (replay protection).

Single-instance by design: entries expire after ``max_skew`` seconds, so the
cache only needs to remember nonces inside the accepted timestamp window.
"""

from __future__ import annotations

import time
from collections import OrderedDict

from .auth import AuthError


class NonceCache:
    def __init__(self, max_entries: int = 8192) -> None:
        self._max = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()

    def _purge(self, now: float) -> None:
        while self._seen:
            nonce, expiry = next(iter(self._seen.items()))
            if expiry > now:
                break
            self._seen.popitem(last=False)

    def check_and_store(self, nonce: str, *, ttl: int, now: float | None = None) -> None:
        """Accept a nonce once; raise AuthError('replayed_nonce') on reuse."""
        ts = time.time() if now is None else now
        self._purge(ts)
        if nonce in self._seen:
            raise AuthError("replayed_nonce", "Nonce has already been used")
        self._seen[nonce] = ts + ttl
        self._seen.move_to_end(nonce)
        while len(self._seen) > self._max:
            self._seen.popitem(last=False)
