"""read tool — open-then-verify, unified error surface.

Flow: locate (poison/cwd) -> open handle -> verify THE HANDLE (containment,
type, deny) -> list or read through that fd. Everything except the actionable
codes below collapses to `Unable to read <path>`: containment failures
included, so a probed path cannot be distinguished from a missing one (the
reason is logged server-side).
"""

from __future__ import annotations

import json

from agentfiles_shared.errors import ToolError, unable_to_read
from agentfiles_shared.schema import ReadInput
from agentfiles_shared.transport import DownloadDescriptor

from .. import readfs
from ..config import Config
from ..fslayer import Resolver
from ..handlepath import OPEN_RDONLY

# verbatim to the model: content/policy facts the model can act on.
# path_escape / path_kind / invalid_cwd are deliberately NOT here (see
# docstring); cwd_not_set stays because it tells the model how to proceed,
# and invalid_input because the fix is in the model's own arguments.
# malformed_utf8 and offset_out_of_range are raised only once the handle is
# verified, so they leak nothing about the filesystem; they are facts about
# the file and about the arguments asked for, the way binary_file already is.
_TRANSPARENT_CODES = {
    "binary_file",
    "malformed_utf8",
    "offset_out_of_range",
    "media_ingest_limit",
    "image_decode",
    "image_size",
    "cwd_not_set",
    "invalid_input",
}


def execute(
    resolver: Resolver, config: Config, params: ReadInput
) -> tuple[dict, str]:
    try:
        return _run(resolver, config, params)
    except ToolError as exc:
        if exc.code in _TRANSPARENT_CODES:
            raise
        raise unable_to_read(params.path) from None
    except OSError:
        # permission, a file vanishing mid-open, I/O error: a tool error the
        # model can act on, never an `internal` one
        raise unable_to_read(params.path) from None


def _run(
    resolver: Resolver, config: Config, params: ReadInput
) -> tuple[dict, str]:
    full = resolver.locate(params.path, params.cwd)
    opened = resolver.open_checked(
        full,
        flags=OPEN_RDONLY,
        expect="any",          # file or directory; devices/FIFOs rejected
        deny=config.read_deny,
        on_deny=unable_to_read(params.path),
    )
    with opened:
        if opened.is_dir:
            page = readfs.list_dir(opened, offset=params.offset, limit=params.limit)
            result = page.to_result()
            return result, _model_text(result)

        content = readfs.read_opened(
            opened, offset=params.offset, limit=params.limit
        )

    if isinstance(content, DownloadDescriptor):
        result = content.model_dump()
    else:
        result = content.to_result()
        # text reads grant the write/edit receipt: the fstat of the handle
        # these bytes came from, never a stat of the path taken afterwards
        if content.version is not None:
            result["version"] = content.version.model_dump(by_alias=True)
    return result, _model_text(result)


def _model_text(result: dict) -> str:
    # Images return a download descriptor; the MCP client appends the local
    # path after fetching, so the server only provides the success prefix.
    if result.get("type") == "download":
        return "Image read successfully"
    return json.dumps(result, ensure_ascii=False)
