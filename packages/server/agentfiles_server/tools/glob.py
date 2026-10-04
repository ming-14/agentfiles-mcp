"""glob tool — V2 semantics with containment checks and deny exclusions.

Unlike V2 (whose ``path`` is a type-only brand with no runtime check), the
search root here goes through the resolver, so a relative escape or an
external path outside the whitelist is rejected before rg ever runs.
"""

from __future__ import annotations

import os

from agentfiles_shared.errors import (
    SEARCH_TRANSPARENT_CODES,
    ToolError,
    unable_to_find_files,
)
from agentfiles_shared.schema import GlobInput

from .. import rg
from ..config import Config
from ..fslayer import Resolver, contains, slash


def execute(
    resolver: Resolver, config: Config, params: GlobInput
) -> tuple[dict, str]:
    try:
        return _run(resolver, config, params)
    except rg.InvalidPattern:
        raise unable_to_find_files(params.pattern) from None
    except ToolError as exc:
        if exc.code in SEARCH_TRANSPARENT_CODES:
            raise
        raise unable_to_find_files(params.pattern) from None


def _run(
    resolver: Resolver, config: Config, params: GlobInput
) -> tuple[dict, str]:
    # resolve the search root: relative stays inside the workspace, absolute
    # needs the whitelist; both escape attempts fail here (V2 checks nothing)
    search = resolver.resolve(params.path) if params.path else None
    cwd = search.canonical if search else resolver.root
    if not os.path.isdir(cwd):
        raise unable_to_find_files(params.pattern)

    # V2 defaults to no bound; cap the subprocess so one call cannot spin
    limit = params.limit if params.limit is not None else 10_000
    binary = rg.find_binary(config.ripgrep_path)
    result = rg.run_glob(
        binary,
        cwd=cwd,
        pattern=params.pattern,
        limit=limit,
        deny=config.read_deny,
        timeout=config.rg_timeout,
    )

    entries = []
    model_lines = []
    for item in result.items:
        absolute = os.path.normpath(os.path.join(cwd, item))
        if contains(resolver.root, absolute):
            rel = os.path.relpath(absolute, resolver.root)
            resource = "." if rel == "." else slash(rel)
        else:
            resource = slash(absolute)
        entries.append({"path": resource, "type": "file"})
        # model text shows absolute paths (V2 resolves before rendering)
        model_lines.append(slash(absolute))

    model_text = "\n".join(model_lines) if entries else "No files found"
    # V2's glob output has no truncated flag; the bound is on the RPC payload
    return {"entries": entries, "truncated": result.truncated}, model_text
