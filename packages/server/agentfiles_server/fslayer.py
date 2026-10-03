"""Path resolution and containment (mirrors packages/core/src/location-mutation.ts).

Rules to keep identical to V2:
  * relative paths must not escape the workspace root (``relative_escape``)
  * symlinks must not resolve outside the root (``location_escape``)
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


def slash(path: str) -> str:
    """Normalize separators to ``/`` (V2 keeps resources posix-style on Windows)."""
    return path.replace("\\", "/")


def contains(parent: str, child: str) -> bool:
    """True when ``child`` is lexically inside ``parent`` (same rule as FSUtil.contains)."""
    rel = os.path.relpath(child, parent)
    return rel == "." or (not os.path.isabs(rel) and not rel.startswith(".."))


@dataclass(frozen=True)
class Resolved:
    canonical: str      # absolute, symlink-resolved
    resource: str       # workspace-relative (posix) or absolute when external
    external: bool


class Resolver:
    def __init__(self, root: str) -> None:
        self.root = os.path.realpath(root)

    def resolve(self, path: str) -> Resolved:
        """Resolve ``path`` against the workspace root.

        Raises ToolError('path_escape') on relative escape / symlink escape.
        """
        if os.path.isabs(path):
            lexical = os.path.normpath(path)
            lexically_internal = contains(self.root, lexical)
            if not lexically_internal:
                # external absolute path: allowed, but caller must authorize it
                canonical = self._realpath_or_anchor(lexical)
                return Resolved(
                    canonical=canonical,
                    resource=slash(canonical),
                    external=True,
                )
        else:
            lexical = os.path.normpath(os.path.join(self.root, path))
            lexically_internal = contains(self.root, lexical)
            if not lexically_internal:
                raise path_escape(path, REASON_RELATIVE_ESCAPE)

        canonical = self._realpath_or_anchor(lexical)
        if lexically_internal and not contains(self.root, canonical):
            raise path_escape(path, REASON_LOCATION_ESCAPE)

        rel = os.path.relpath(canonical, self.root)
        resource = "." if rel == "." else slash(rel)
        return Resolved(canonical=canonical, resource=resource, external=False)

    @staticmethod
    def _realpath_or_anchor(target: str) -> str:
        """Resolve symlinks for the existing prefix; anchor on nearest existing dir."""
        if os.path.exists(target):
            return os.path.realpath(target)
        anchor = Path(target)
        while not anchor.exists():
            parent = anchor.parent
            if parent == anchor:
                break
            anchor = parent
        if not anchor.is_dir():
            raise path_escape(target, REASON_NON_DIRECTORY_ANCESTOR)
        resolved_anchor = os.path.realpath(str(anchor))
        remainder = os.path.relpath(target, str(anchor))
        joined = os.path.normpath(os.path.join(resolved_anchor, remainder))
        return joined
