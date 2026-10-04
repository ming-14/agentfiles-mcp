"""glob tool — verified search root, deny exclusions, V2 rendering.

The search root (explicit path, the request's cwd, or the workspace) is
opened and verified through its handle before ripgrep sees it; rg then walks
the verified real path. Deny patterns ride along as ``--glob=!`` exclusions.
path_escape collapses into the generic message (V2 behavior) and is only
logged server-side, so probing cannot map the server's filesystem.

Names rg reports go through ``Resolver.resolve_child``: hits landing outside
containment are dropped, not rendered.
"""

from __future__ import annotations

from agentfiles_shared.errors import (
    SEARCH_TRANSPARENT_CODES,
    ToolError,
    unable_to_find_files,
)
from agentfiles_shared.schema import GlobInput

from .. import rg
from ..config import Config
from ..fslayer import Resolver, slash
from ..handlepath import OPEN_RDONLY


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
    except OSError:
        raise unable_to_find_files(params.pattern) from None


def _run(
    resolver: Resolver, config: Config, params: GlobInput
) -> tuple[dict, str]:
    # root = explicit path > request cwd > workspace. locate() is the only way
    # in: it rejects poison and a relative cwd (which would otherwise resolve
    # against the *process* cwd, since there is no path to join here).
    full = resolver.locate(params.path or ".", params.cwd or resolver.root)

    try:
        opened = resolver.open_checked(
            full, flags=OPEN_RDONLY, expect="dir",
            deny=config.read_deny,
            on_deny=ToolError("glob_deny", ""),
        )
    except ToolError as exc:
        if exc.code == "glob_deny":
            # a denied root answers exactly like an empty one: an error would
            # tell the model the path exists but is protected
            return {"entries": [], "truncated": False}, "No files found"
        raise
    with opened:
        cwd = opened.real  # ripgrep walks the verified real path

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
            hit = resolver.resolve_child(cwd, item)
            if hit is None:
                continue
            resource, absolute = hit
            entries.append({"path": resource, "type": "file"})
            # model text shows absolute paths (V2 resolves before rendering)
            model_lines.append(slash(absolute))

    model_text = "\n".join(model_lines) if entries else "No files found"
    # V2's glob output has no truncated flag; the bound is on the RPC payload
    return {"entries": entries, "truncated": result.truncated}, model_text
