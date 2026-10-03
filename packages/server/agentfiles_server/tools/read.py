"""read tool — V2 semantics (packages/core/src/tool/read.ts + read-filesystem.ts).

TODO(step 3): paged reader, magic-byte sniffing, UTF-8 strict decoding,
directory listing with symlink escape rejection, model-text rendering.
"""

from __future__ import annotations

from agentfiles_shared.errors import ToolError

from ..fslayer import Resolver


def execute(resolver: Resolver, payload: dict) -> tuple[dict, str]:
    raise ToolError("not_implemented", "read is not implemented yet")
