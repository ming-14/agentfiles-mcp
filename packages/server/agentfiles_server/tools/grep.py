"""grep tool — verified search root, deny exclusions, V2 rendering.

The root (path / request cwd / workspace) and any single-file target are
opened and verified through their handles before ripgrep sees them: rg
follows command-line files even past its ignore rules, so the file it is
handed must already be containment-checked. Deny patterns also ride along as
``--glob=!`` exclusions for the walk itself. path_escape collapses into the
generic message (logged server-side only).
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
from ..fslayer import Resolver, contains, slash
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
    if params.path:
        full = resolver.locate(params.path, params.cwd)
    else:
        full = params.cwd or resolver.root

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

        matches = [_to_match(resolver, cwd, m) for m in result.items]

    if not matches:
        return {"matches": [], "truncated": result.truncated}, "No files found"

    # grouped rendering: absolute path header, then "  Line N: text".
    # rg's `lines.text` keeps its trailing newline (V2's Match.text does too);
    # it is stripped here so the rendered block has no stray blank lines.
    lines = [f"Found {len(matches)} matches"]
    current = None
    for match in matches:
        if current != match["entry"]["path"]:
            if current is not None:
                lines.append("")
            current = match["entry"]["path"]
            lines.append(f"{_absolute(cwd, current)}:")
        preview = match["text"].rstrip("\r\n")
        lines.append(f"  Line {match['line']}: {preview}")
    return {"matches": matches, "truncated": result.truncated}, "\n".join(lines)


def _to_match(resolver: Resolver, cwd: str, raw: rg.RawMatch) -> dict:
    absolute = os.path.normpath(os.path.join(cwd, raw.path))
    if contains(resolver.root, absolute):
        rel = os.path.relpath(absolute, resolver.root)
        resource = "." if rel == "." else slash(rel)
    else:
        resource = slash(absolute)
    return {
        "entry": {"path": resource, "type": "file"},
        "line": raw.line,
        "offset": raw.offset,
        "text": raw.text,
        "submatches": raw.submatches,
    }


def _absolute(cwd: str, resource: str) -> str:
    if resource.startswith("/") or (len(resource) >= 3 and resource[1] == ":"):
        return resource
    return slash(os.path.join(cwd, resource))


__all__ = ["execute"]
