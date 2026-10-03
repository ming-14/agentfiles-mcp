"""Server-side file transport: signed download endpoint.

GET /v1/transport/download?path=<absolute-server-path>

The path is covered by the HMAC signature (the canonical string includes the
query string), so a tampered target fails signature verification before the
handler runs. Note what the signature does *not* do: it is computed by the
client from the shared secret, so it proves who is asking, never what may be
served. The authorization boundary is entirely server-side -- containment
(workspace / whitelist) plus the ``AF_READ_DENY`` policy, both re-checked
here for every request. The handler then streams raw bytes.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi.responses import FileResponse, JSONResponse

from agentfiles_shared.errors import ToolError, invalid_input, transport_too_large, \
    transport_unavailable, unable_to_read
from agentfiles_shared.transport import DOWNLOAD_PATH
from agentfiles_shared.wildcard import match as wildcard_match

from .config import Config
from .fslayer import Resolver
from .readfs import mime_type


def _error(exc: ToolError, status: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status, content={"ok": False, "error": exc.to_payload()})


def download(resolver: Resolver, config: Config, raw_path: str):
    """Return a FileResponse for ``raw_path``, or a JSON error envelope.

    Signature verification (including the signed query string) already happened
    in the middleware; this enforces containment, read-deny policy and size.
    ``raw_path`` must be an absolute server path (descriptors always carry
    one), which keeps the endpoint independent of the server's cwd.
    """
    if not raw_path:
        return _error(transport_unavailable(""), status=400)
    if not os.path.isabs(raw_path):
        return _error(invalid_input("path must be an absolute path"), status=400)

    try:
        target = resolver.resolve(raw_path)
    except ToolError as exc:
        # containment failure (symlink/external escape) -> 403
        return _error(exc, status=403)

    # Same policy as the read tool, matched against the same resource string,
    # so a denied file cannot be fetched by going around the tool handler.
    if any(wildcard_match(pattern, target.resource) for pattern in config.read_deny):
        return _error(unable_to_read(raw_path), status=403)

    canonical = target.canonical
    if not os.path.isfile(canonical):
        return _error(transport_unavailable(raw_path), status=404)

    size = os.path.getsize(canonical)
    if size > config.transport_max:
        return _error(transport_too_large(raw_path, size, config.transport_max), status=413)

    media_type = mime_type(canonical)
    return FileResponse(
        canonical,
        media_type=media_type,
        filename=Path(canonical).name,
        content_disposition_type="attachment",
    )


__all__ = ["download", "DOWNLOAD_PATH"]
