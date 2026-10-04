"""grep tool — verified search root, deny exclusions, V2 rendering.

The root (path / request cwd / workspace) and any single-file target are
opened and verified through their handles before ripgrep sees them: rg
follows command-line files even past its ignore rules, so the file it is
handed must already be containment-checked. Deny patterns also ride along as
``--glob=!`` exclusions for the walk itself. path_escape collapses into the
generic message (logged server-side only).

Names rg reports go through ``Resolver.resolve_child``: hits landing outside
containment are dropped, not rendered.
"""

from __future__ import annotations

import os

from agentfiles_shared.errors import (
    SEARCH_TRANSPARENT_CODES,
    ToolError,
    unable_to_grep,
)
from agentfiles_shared.schema import GrepInput

from .. import rg
from ..config import Config
from ..fslayer import Resolver, slash
from ..handlepath import OPEN_RDONLY


def execute(
    resolver: Resolver, config: Config, params: GrepInput
) -> tuple[dict, str]:
    try:
        return _run(resolver, config, params)
    except rg.InvalidPattern:
        # V2 collapses an invalid regex into the same generic failure
        raise unable_to_grep(params.pattern) from None
    except ToolError as exc:
        if exc.code in SEARCH_TRANSPARENT_CODES:
            raise
        raise unable_to_grep(params.pattern) from None
    except OSError:
        raise unable_to_grep(params.pattern) from None


def _run(
    resolver: Resolver, config: Config, params: GrepInput
) -> tuple[dict, str]:
    # root = explicit path > request cwd > workspace, always through locate():
    # a relative cwd with no path would otherwise resolve against the process
    # cwd instead of the workspace
    full = resolver.locate(params.path or ".", params.cwd or resolver.root)

    # verify the target through its handle first: deny is matched against the
    # real resource AND the lexical one (a .env symlinked as good.txt is
    # denied either way), before rg ever opens the file
    try:
        opened = resolver.open_checked(
            full, flags=OPEN_RDONLY, expect="any",
            deny=config.read_deny,
            on_deny=ToolError("grep_deny", ""),
        )
    except ToolError as exc:
        if exc.code == "grep_deny":
            # a denied target answers exactly like a missing one (no matches):
            # an error here would tell the model the path exists but is protected
            return {"matches": [], "truncated": False}, "No files found"
        raise
    with opened:
        if opened.is_dir:
            cwd, single_file = opened.real, None
        else:
            # ripgrep bypasses glob exclusions for files named on the command
            # line, so the verified real path is what rg receives
            cwd, single_file = os.path.dirname(opened.real), os.path.basename(opened.real)

        limit = params.limit if params.limit is not None else 10_000
        binary = rg.find_binary(config.ripgrep_path)
        result = rg.run_grep(
            binary,
            cwd=cwd,
            pattern=params.pattern,
            file=single_file,
            include=params.include,
            limit=limit,
            deny=config.read_deny,
            timeout=config.rg_timeout,
        )

        hits = []
        for raw in result.items:
            hit = _to_match(resolver, cwd, raw)
            if hit is None:
                continue
            hits.append(hit)
        matches = [match for match, _ in hits]

    if not matches:
        return {"matches": [], "truncated": result.truncated}, "No files found"

    # grouped rendering: header, then "  Line N: text". The header is the
    # resolved real path; joining it back onto the search root doubles the base.
    # rg's `lines.text` keeps its trailing newline (V2's Match.text does too);
    # it is stripped here so the rendered block has no stray blank lines.
    lines = [f"Found {len(matches)} matches"]
    current = None
    for match, absolute in hits:
        if current != match["entry"]["path"]:
            if current is not None:
                lines.append("")
            current = match["entry"]["path"]
            lines.append(f"{slash(absolute)}:")
        preview = match["text"].rstrip("\r\n")
        lines.append(f"  Line {match['line']}: {preview}")
    return {"matches": matches, "truncated": result.truncated}, "\n".join(lines)


def _to_match(
    resolver: Resolver, cwd: str, raw: rg.RawMatch
) -> tuple[dict, str] | None:
    """One rg hit as (match, real path); None when it resolves outside
    containment."""
    hit = resolver.resolve_child(cwd, raw.path)
    if hit is None:
        return None
    resource, absolute = hit
    return {
        "entry": {"path": resource, "type": "file"},
        "line": raw.line,
        "offset": raw.offset,
        "text": raw.text,
        "submatches": raw.submatches,
    }, absolute


__all__ = ["execute"]
