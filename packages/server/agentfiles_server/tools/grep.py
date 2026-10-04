"""grep tool — V2 semantics with containment checks and deny exclusions.

The search root goes through the resolver (V2 does not check it), a file
target narrows rg to that single file, and AF_READ_DENY patterns are passed
as ``--glob=!`` exclusions so denied files never surface in results.
"""

from __future__ import annotations

import os

from agentfiles_shared.errors import ToolError, unable_to_grep
from agentfiles_shared.schema import GrepInput
from agentfiles_shared.wildcard import match as wildcard_match

from .. import rg
from ..config import Config
from ..fslayer import Resolver, contains, slash

_TRANSPARENT_CODES = {"path_escape", "rg_unavailable", "rg_timeout", "rg_failed"}


def execute(
    resolver: Resolver, config: Config, params: GrepInput
) -> tuple[dict, str]:
    try:
        return _run(resolver, config, params)
    except rg.InvalidPattern:
        # V2 collapses an invalid regex into the same generic failure
        raise unable_to_grep(params.pattern) from None
    except ToolError as exc:
        if exc.code in _TRANSPARENT_CODES:
            raise
        raise unable_to_grep(params.pattern) from None


def _run(
    resolver: Resolver, config: Config, params: GrepInput
) -> tuple[dict, str]:
    target = resolver.resolve(params.path) if params.path else None
    base = target.canonical if target else resolver.root

    if os.path.isdir(base):
        cwd, single_file = base, None
    else:
        cwd, single_file = os.path.dirname(base), os.path.basename(base)
        # ripgrep bypasses glob exclusions for files named on the command
        # line, so the deny list must be enforced here, before spawning
        if any(
            wildcard_match(pattern, target.resource)
            for pattern in config.read_deny
        ):
            return {"matches": [], "truncated": False}, "No files found"

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
