"""write tool — V2 semantics with strict-mode version verification.

Order: (input validated centrally) resolve -> write-deny -> version-verified
handle write. No formatter/watcher/LSP hooks (V2 has none either).
"""

from __future__ import annotations

from agentfiles_shared.errors import (
    ToolError,
    unable_to_write,
)
from agentfiles_shared.schema import WriteInput
from agentfiles_shared.wildcard import match as wildcard_match

from .. import filemut
from ..config import Config
from ..fslayer import Resolver

# keep verbatim: version policy and path escapes are actionable for the model
_TRANSPARENT_CODES = {
    "version_missing",
    "version_mismatch",
    "path_escape",
    "write_deny",
}


def execute(
    resolver: Resolver, config: Config, params: WriteInput
) -> tuple[dict, str]:
    try:
        return _run(resolver, config, params)
    except ToolError as exc:
        if exc.code in _TRANSPARENT_CODES:
            raise
        raise unable_to_write(params.path) from None


def _deny(resource: str, config: Config, path: str) -> None:
    if any(wildcard_match(pattern, resource) for pattern in config.write_deny):
        raise ToolError("write_deny", f"Unable to write {path}")


def _run(
    resolver: Resolver, config: Config, params: WriteInput
) -> tuple[dict, str]:
    target = resolver.resolve(params.path)
    _deny(target.resource, config, params.path)

    data = params.content.encode("utf-8")
    expected = params.expected_version

    with filemut.target_lock(target.canonical):
        handle = filemut.open_verified(
            target.canonical,
            expected,
            on_missing=filemut.version_missing_write(),
            on_mismatch=filemut.version_mismatch_write(),
            create=True,
        )
        existed = handle is not None
        try:
            if handle is None:
                # absent + no marker: create (parent dirs included)
                handle = filemut.create_with_dirs(target.canonical, data)
            else:
                # exactly one BOM: old file had one, or the new content does
                had_bom = handle.had_bom or data.startswith(b"\xef\xbb\xbf")
                filemut.modify(handle, filemut.join_bom(data, had_bom))
        finally:
            handle.close()

        version = filemut.version_of_path(target.canonical)

    verb = "Wrote" if existed else "Created"
    model_text = f"{verb} file successfully: {target.resource}"
    result = {
        "operation": "write",
        "target": target.canonical,
        "resource": target.resource,
        "existed": existed,
        "version": version.model_dump(by_alias=True),
    }
    return result, model_text
