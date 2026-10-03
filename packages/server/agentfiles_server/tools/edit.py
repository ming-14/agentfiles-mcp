"""edit tool — V2 semantics (packages/core/src/tool/edit.ts).

TODO(step 4): exact match counting, replaceAll, CRLF/BOM preservation,
CAS write (writeIfUnchanged) with per-target lock, diff preview text.
"""

from __future__ import annotations

from agentfiles_shared.errors import ToolError

from ..fslayer import Resolver


def execute(resolver: Resolver, payload: dict) -> tuple[dict, str]:
    raise ToolError("not_implemented", "edit is not implemented yet")
