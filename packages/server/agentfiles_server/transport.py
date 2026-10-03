"""Server-side file transport: signed download endpoint.

GET /v1/transport/download?path=<absolute-server-path>

The path is covered by the HMAC signature (the canonical string includes the
query string), so a tampered target fails signature verification before the
handler runs. The handler additionally confines the request to the workspace
or the external whitelist and streams raw bytes.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi.responses import FileResponse, JSONResponse

from agentfiles_shared.errors import ToolError, path_escape, transport_too_large, \
    transport_unavailable
from agentfiles_shared.transport import DOWNLOAD_PATH

from .fslayer import Resolver, contains
from .readfs import mime_type


def _error(exc: ToolError, status: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status, content={"ok": False, "error": exc.to_payload()})


def download(resolver: Resolver, config, raw_path: str):
    """Return a FileResponse for ``raw_path``, or a JSON error envelope.

    Signature verification (including the signed query string) already happened
    in the middleware; this only enforces containment and size policy.
    """
    whitelist = resolver.whitelist

    if not raw_path:
        return _error(transport_unavailable(""), status=400)

    try:
        canonical = os.path.realpath(raw_path)
    except (OSError, ValueError):
        return _error(path_escape(raw_path, "external_directory"), status=400)

    allowed = contains(resolver.root, canonical) or any(
        contains(directory, canonical) for directory in whitelist
    )
    if not allowed:
        return _error(path_escape(raw_path, "external_directory"), status=403)

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
