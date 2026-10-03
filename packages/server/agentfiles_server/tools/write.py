"""write tool — V2 semantics (packages/core/src/tool/write.ts).

TODO(step 4): overwrite-or-create, auto parent dirs, exactly-one BOM,
model text `Wrote|Created file successfully: <resource>`.
"""

from __future__ import annotations

from agentfiles_shared.errors import ToolError
from agentfiles_shared.schema import WriteInput

from ..fslayer import Resolver


def execute(resolver: Resolver, params: WriteInput) -> tuple[dict, str]:
    raise ToolError("not_implemented", "write is not implemented yet")
