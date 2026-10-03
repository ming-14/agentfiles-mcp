"""read tool — V2 semantics with images moved to the transport channel.

Order (mirrors packages/core/src/tool/read.ts):
  resolve (workspace / whitelist) → read-deny → inspect → list | read
Input validation happens centrally in app.py (V2 does it in the tool schema).
"""

from __future__ import annotations

import json

from agentfiles_shared.errors import ToolError, unable_to_read
from agentfiles_shared.schema import ReadInput
from agentfiles_shared.transport import DownloadDescriptor
from agentfiles_shared.wildcard import match as wildcard_match

from .. import readfs
from ..config import Config
from ..fslayer import Resolver

# Codes whose verbatim message reaches the model:
#   V2 read.ts passes binary/media/image errors through, and path/whitelist
#   escapes keep their explicit reason so operators can debug policy rejections.
#   Everything else (missing file, malformed UTF-8, offset range, read-deny)
#   collapses to V2's generic `Unable to read <path>`.
_TRANSPARENT_CODES = {
    "binary_file",
    "media_ingest_limit",
    "image_decode",
    "image_size",
    "path_escape",
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
        # permission, a file vanishing between inspect and open, I/O error:
        # a tool error the model can act on, never an `internal` one
        raise unable_to_read(params.path) from None


def _run(
    resolver: Resolver, config: Config, params: ReadInput
) -> tuple[dict, str]:
    target = resolver.resolve(params.path)
    resource = target.resource

    # read-deny: match the same resource V2 would authorize (deny, no prompt)
    if any(wildcard_match(pattern, resource) for pattern in config.read_deny):
        raise unable_to_read(params.path)

    kind = readfs.inspect(target.canonical, resource=resource)

    if kind == "directory":
        page = readfs.list_dir(
            target.canonical,
            resource=resource,
            offset=params.offset,
            limit=params.limit,
        )
        result = page.to_result()
        return result, _model_text(result)

    content = readfs.read_file(
        target.canonical, resource, offset=params.offset, limit=params.limit
    )
    if isinstance(content, DownloadDescriptor):
        result = content.model_dump()
    else:
        result = content.to_result()
        # text reads grant the write/edit receipt (images and directories do
        # not): the fstat of the handle these bytes came from, never a stat of
        # the path taken afterwards
        if content.version is not None:
            result["version"] = content.version.model_dump(by_alias=True)
    return result, _model_text(result)


def _model_text(result: dict) -> str:
    # Images return a download descriptor; the MCP client appends the local
    # path after fetching, so the server only provides the success prefix.
    if result.get("type") == "download":
        return "Image read successfully"
    return json.dumps(result, ensure_ascii=False)
