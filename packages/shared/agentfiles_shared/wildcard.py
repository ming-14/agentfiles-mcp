"""Wildcard matching compatible with V2 rules.

Rules (from packages/core/src/util/wildcard.ts):
  * both sides normalize ``\\`` to ``/``
  * ``*`` matches any characters (including ``/``)
  * ``?`` matches exactly one character
  * matching is anchored (full string)
  * on Windows the comparison is case-insensitive
"""

from __future__ import annotations

import os
import re

__all__ = ["match", "compile_pattern"]


def compile_pattern(pattern: str) -> re.Pattern[str]:
    normalized = pattern.replace("\\", "/")
    regex = "".join(
        ".*" if ch == "*" else "." if ch == "?" else re.escape(ch)
        for ch in normalized
    )
    flags = re.DOTALL
    if os.name == "nt":
        flags |= re.IGNORECASE
    return re.compile(f"^{regex}$", flags)


def match(pattern: str, value: str) -> bool:
    """True when ``value`` fully matches ``pattern``."""
    return compile_pattern(pattern).match(value.replace("\\", "/")) is not None
