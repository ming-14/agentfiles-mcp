"""glob tool — V2 semantics (packages/core/src/tool/glob.ts).

TODO(step 5): ripgrep `--no-config --files --glob=<p> --glob=!**/.git/** .`
(no --hidden), default limit = unlimited, model text = one absolute path per line.
"""

from __future__ import annotations

from agentfiles_shared.errors import ToolError

from ..fslayer import Resolver


def execute(resolver: Resolver, payload: dict) -> tuple[dict, str]:
    raise ToolError("not_implemented", "glob is not implemented yet")
