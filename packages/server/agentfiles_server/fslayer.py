"""Path resolution and containment (mirrors packages/core/src/location-mutation.ts).

Rules kept identical to V2, plus a server-side external whitelist:
  * relative paths must not escape the workspace root (``relative_escape``)
  * symlinks must not resolve outside the root (``location_escape``)
  * absolute paths outside the root are allowed only when they are inside a
    directory listed in ``AF_EXTERNAL_WHITELIST`` (otherwise the resolve fails)
  * resources are always reported with forward slashes
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from agentfiles_shared.errors import path_escape

REASON_RELATIVE_ESCAPE = "relative_escape"
REASON_LOCATION_ESCAPE = "location_escape"
REASON_NON_DIRECTORY_ANCESTOR = "non_directory_ancestor"
REASON_EXTERNAL_DENIED = "external_directory"


def slash(path: str) -> str:
    """Normalize separators to ``/`` (V2 keeps resources posix-style on Windows)."""
    return path.replace("\\", "/")


def contains(parent: str, child: str) -> bool:
    """True when ``child`` is lexically inside ``parent`` (same rule as FSUtil.contains)."""
    try:
        rel = os.path.relpath(child, parent)
    except ValueError:
        # Windows: relpath raises across drives ("path is on mount 'D:' ...").
        # Another drive can never be inside this one, so containment simply
        # fails -- the caller reports path_escape, never an exception.
        return False
    return rel == "." or (not os.path.isabs(rel) and not rel.startswith(".."))


def in_whitelist(path: str, whitelist: list[str]) -> bool:
    """True when ``path`` is inside one of the whitelisted directories."""
    return any(contains(directory, path) for directory in whitelist)


@dataclass(frozen=True)
class Resolved:
    canonical: str      # absolute, symlink-resolved
    resource: str       # workspace-relative (posix) or absolute when external
    external: bool


class Resolver:
    def __init__(self, root: str, whitelist: list[str] | None = None) -> None:
        self.root = os.path.realpath(root)
        self.whitelist = [os.path.realpath(p) for p in (whitelist or [])]

    def resolve(self, path: str) -> Resolved:
        """Resolve ``path`` against the workspace root.

        Raises ToolError('path_escape') on relative escape, symlink escape, or
        an external path that is not covered by the whitelist.
        """
        if os.path.isabs(path):
            lexical = os.path.normpath(path)
            if not contains(self.root, lexical):
                # external absolute path: only whitelisted directories are readable
                canonical = self._realpath_or_anchor(lexical, path)
                if not in_whitelist(canonical, self.whitelist):
                    raise path_escape(path, REASON_EXTERNAL_DENIED)
                return Resolved(
                    canonical=canonical,
                    resource=slash(canonical),
                    external=True,
                )
        else:
            lexical = os.path.normpath(os.path.join(self.root, path))
            if not contains(self.root, lexical):
                raise path_escape(path, REASON_RELATIVE_ESCAPE)

        canonical = self._realpath_or_anchor(lexical, path)
        if not contains(self.root, canonical):
            raise path_escape(path, REASON_LOCATION_ESCAPE)

        rel = os.path.relpath(canonical, self.root)
        resource = "." if rel == "." else slash(rel)
        return Resolved(canonical=canonical, resource=resource, external=False)

    @staticmethod
    def _realpath_or_anchor(target: str, reported: str) -> str:
        """Resolve symlinks for the existing prefix; anchor on nearest existing dir.

        ``reported`` is how the caller spelled the path: errors echo it, so a
        server-side absolute path never reaches a model-visible message.
        """
        if os.path.exists(target):
            return os.path.realpath(target)
        anchor = Path(target)
        while not anchor.exists():
            parent = anchor.parent
            if parent == anchor:
                break
            anchor = parent
        if not anchor.is_dir():
            raise path_escape(reported, REASON_NON_DIRECTORY_ANCESTOR)
        resolved_anchor = os.path.realpath(str(anchor))
        remainder = os.path.relpath(target, str(anchor))
        return os.path.normpath(os.path.join(resolved_anchor, remainder))
