"""edit tool — V2 semantics with strict-mode version verification.

Pure exact matching (V2 has no fuzzy chain either). Order:
  prechecks (no IO) -> resolve -> write-deny -> verified handle ->
  decode -> re-check the pre-read fstat -> count matches ->
  BOM/CRLF conversion -> CAS write.
"""

from __future__ import annotations

import difflib

from agentfiles_shared.errors import (
    ToolError,
    edit_empty_old,
    edit_identical,
    edit_multiple_matches,
    edit_not_found,
    edit_too_large,
    unable_to_edit,
)
from agentfiles_shared.schema import (
    MAX_EDIT_BYTES,
    MAX_LINE_LENGTH,
    MAX_LINE_SUFFIX,
    MAX_READ_BYTES,
    EditInput,
)
from agentfiles_shared.wildcard import match as wildcard_match

from .. import filemut
from ..config import Config
from ..fslayer import Resolver

_TRANSPARENT_CODES = {
    "version_missing",
    "version_mismatch",
    "path_escape",
    "write_deny",
    "edit_identical",
    "edit_empty_old",
    "edit_not_found",
    "edit_multiple_matches",
    "edit_too_large",
}

PREVIEW_LINES = 6
PREVIEW_LINE_CHARS = 240
# The `patch` field travels with every edit, so it gets the same byte budget a
# single read page has: one large file must not be echoed back through it.
PATCH_MAX_BYTES = MAX_READ_BYTES


def execute(
    resolver: Resolver, config: Config, params: EditInput
) -> tuple[dict, str]:
    # argument prechecks run before any path or file IO (V2 order)
    if params.old_string == params.new_string:
        raise edit_identical()
    if params.old_string == "":
        raise edit_empty_old()

    try:
        return _run(resolver, config, params)
    except ToolError as exc:
        if exc.code in _TRANSPARENT_CODES:
            raise
        raise unable_to_edit(params.path) from None
    except OSError:
        # read-only file, vanished file, disk full -- on Windows a directory
        # is PermissionError, not IsADirectoryError. Never an `internal` error.
        raise unable_to_edit(params.path) from None


def _run(resolver: Resolver, config: Config, params: EditInput) -> tuple[dict, str]:
    target = resolver.resolve(params.path)
    if any(wildcard_match(p, target.resource) for p in config.write_deny):
        raise ToolError("write_deny", f"Unable to edit {params.path}")

    expected = params.expected_version
    if expected is None:
        raise filemut.version_missing_edit()

    with filemut.target_lock(target.canonical):
        handle = filemut.open_verified(
            target.canonical,
            expected,
            on_missing=filemut.version_missing_edit(),
            on_mismatch=filemut.version_mismatch_edit(),
            create=False,
            # budget enforced on the verified handle: after the CAS (a file
            # that no longer matches the marker is version_mismatch, the more
            # actionable answer) and before the read that fills memory
            max_bytes=MAX_EDIT_BYTES,
            on_too_large=edit_too_large(params.path, expected.size,
                                        MAX_EDIT_BYTES),
        )
        if handle is None:
            # open_verified(create=False) never returns None; an explicit error
            # rather than an assert, which `python -O` would strip
            raise filemut.version_missing_edit()
        try:
            text = _decode(handle.content, params.path)
            # any change landing since the pre-read fstat (mid-read or while
            # we were decoding) invalidates the match set
            filemut.verify_unchanged(handle, filemut.version_mismatch_edit())

            ending = "\r\n" if "\r\n" in text else "\n"
            old = _to_ending(params.old_string, ending)
            new = _to_ending(params.new_string, ending)

            count = _count(text, old)
            if count == 0:
                raise edit_not_found()
            if count > 1 and not params.replace_all:
                raise edit_multiple_matches()

            replaced = text.replace(old, new) if params.replace_all else \
                text.replace(old, new, 1)
            replacements = count if params.replace_all else 1

            additions, deletions = _diff_counts(text, replaced)
            patch = _patch(target.resource, text, replaced)

            had_bom = handle.had_bom
            out = replaced.encode("utf-8")
            filemut.modify(handle, filemut.join_bom(out, had_bom))
        except BaseException:
            handle.close()
            raise
        # marker from the handle we wrote through, before it closes
        version = filemut.finish(handle)

    model_text = "\n".join(
        [
            f"Edited file successfully: {target.resource}",
            f"Replacements: {replacements}",
            "```diff",
            *_preview(params.old_string, "-"),
            *_preview(params.new_string, "+"),
            "```",
        ]
    )
    result = {
        "files": [
            {
                "file": target.resource,
                "patch": patch,
                "status": "modified",
                "additions": additions,
                "deletions": deletions,
            }
        ],
        "replacements": replacements,
        "version": version.model_dump(by_alias=True),
    }
    return result, model_text


# --- helpers -----------------------------------------------------------------

def _decode(content: bytes, path: str) -> str:
    _had_bom, body = filemut.split_bom(content)
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        raise unable_to_edit(path) from None


def _to_ending(value: str, ending: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.replace("\n", ending) if ending == "\r\n" else normalized


def _count(text: str, needle: str) -> int:
    if not needle:
        return 0
    total = 0
    start = 0
    while True:
        index = text.find(needle, start)
        if index == -1:
            return total
        total += 1
        start = index + len(needle)


def _diff_counts(before: str, after: str) -> tuple[int, int]:
    additions = deletions = 0
    matcher = difflib.SequenceMatcher(a=before.splitlines(), b=after.splitlines())
    for tag, _i1, _i2, _j1, _j2 in matcher.get_opcodes():
        if tag in ("replace", "delete"):
            deletions += _i2 - _i1
        if tag in ("replace", "insert"):
            additions += _j2 - _j1
    return additions, deletions


def _clip(line: str) -> str:
    """Truncate a diff line exactly like the read tool truncates a file line."""
    ending = "\n" if line.endswith("\n") else ""
    body = line[:-1] if ending else line
    if len(body) <= MAX_LINE_LENGTH:
        return line
    return body[:MAX_LINE_LENGTH] + MAX_LINE_SUFFIX + ending


def _patch(resource: str, before: str, after: str) -> str:
    """Unified diff for the model, bounded twice.

    Long lines are clipped to MAX_LINE_LENGTH (a one-line megabyte file would
    otherwise be echoed back in full), and the diff stops at PATCH_MAX_BYTES
    with an explicit marker rather than silently returning a partial patch.
    """
    raw = list(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=resource,
            tofile=resource,
        )
    )
    out: list[str] = []
    used = 0
    omitted = 0
    for line in raw:
        clipped = _clip(line)
        size = len(clipped.encode("utf-8"))
        if used + size > PATCH_MAX_BYTES and out:
            omitted += 1
            continue
        out.append(clipped)
        used += size
    if omitted:
        out.append(
            f"... ({omitted} diff lines omitted; patch exceeds "
            f"{PATCH_MAX_BYTES} bytes)\n"
        )
    return "".join(out)


def _preview(value: str, prefix: str) -> list[str]:
    lines = value.replace("\r\n", "\n").split("\n")
    shown = [
        f"{prefix}{line[:PREVIEW_LINE_CHARS]}..." if len(line) > PREVIEW_LINE_CHARS
        else f"{prefix}{line}"
        for line in lines[:PREVIEW_LINES]
    ]
    if len(lines) > len(shown):
        shown.append(f"{prefix}...")
    return shown
