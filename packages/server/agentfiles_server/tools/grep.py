"""grep tool — V2 semantics (packages/core/src/tool/grep.ts).

TODO(step 5): ripgrep `--no-config --json --hidden --no-messages
[--glob=<include>] --glob=!**/.git/** -- <pattern> <file|.>`,
model text = `Found N matches` / `No files found` + grouped `  Line N: text`.
"""

from __future__ import annotations

from agentfiles_shared.errors import ToolError
from agentfiles_shared.schema import GrepInput

from ..fslayer import Resolver


def execute(resolver: Resolver, params: GrepInput) -> tuple[dict, str]:
    raise ToolError("not_implemented", "grep is not implemented yet")
