"""Bounded in-memory nonce cache (replay protection).

Single-instance by design: entries only need to live as long as the accepted
timestamp window (see ``nonce_ttl``), so the cache stays small.
"""

from __future__ import annotations

import time
from collections import OrderedDict

from .auth import AuthError


def nonce_ttl(max_skew: int) -> int:
    """How long a replay entry must be remembered for a ``±max_skew`` window.

    The window is around the *signed* timestamp, not around arrival time, so
    ``ttl=max_skew`` lets an entry expire while its timestamp is still accepted
    whenever the client clock runs ahead of the server. Doubling covers both
    ends of the window.
    """
    return max_skew * 2


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
