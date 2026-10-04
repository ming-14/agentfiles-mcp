"""Server-side file transport: signed download endpoint.

GET /v1/transport/download?path=<absolute-server-path>

The path is covered by the HMAC signature (the canonical string includes the
query string), so a tampered target fails signature verification before the
handler runs. Note what the signature does *not* do: it is computed by the
client from the shared secret, so it proves who is asking, never what may be
served. The authorization boundary is entirely server-side -- open-then-
verify like every other tool: the file is opened, containment + deny are
checked against THE HANDLE's real path, and the bytes are streamed from that
same fd, so what is verified is what is served.

Containment failures collapse into the same "no longer available" envelope a
missing file gets (logged server-side): the model must not learn, through
this channel, whether a probed path exists outside the workspace.
"""

from __future__ import annotations

import os
import re

from fastapi.responses import JSONResponse, StreamingResponse

from agentfiles_shared.errors import ToolError, invalid_input, transport_too_large, \
    transport_unavailable, unable_to_read
from agentfiles_shared.transport import DOWNLOAD_PATH

from .config import Config
from .fslayer import Resolver
from .handlepath import OPEN_RDONLY
from .readfs import mime_type

_CHUNK = 64 * 1024

# A filename may hold anything the filesystem allows -- a quote closes the
# header value early, CRLF starts a new one. Only printable ASCII survives.
_HEADER_UNSAFE = re.compile(r"[^\x20-\x7e]|[\\\"]")


def _content_disposition(name: str) -> str:
    return f'attachment; filename="{_HEADER_UNSAFE.sub("_", name).strip() or "file"}"'


def _error(exc: ToolError, status: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status, content={"ok": False, "error": exc.to_payload()})


def _stream(opened):
    """Yield the verified handle's bytes, closing it when done or on error."""
    try:
        while True:
            chunk = os.read(opened.fd, _CHUNK)
            if not chunk:
                return
            yield chunk
    finally:
        opened.close()


def download(resolver: Resolver, config: Config, raw_path: str):
    """Stream ``raw_path`` through a verified handle, or a JSON error envelope.

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
        opened = resolver.open_checked(
            raw_path,
            flags=OPEN_RDONLY,
            expect="file",
            deny=config.read_deny,
            on_deny=unable_to_read(raw_path),
        )
    except FileNotFoundError:
        return _error(transport_unavailable(raw_path), status=404)
    except IsADirectoryError:
        return _error(transport_unavailable(raw_path), status=404)
    except OSError:
        return _error(transport_unavailable(raw_path), status=404)
    except ToolError as exc:
        if exc.code in ("path_escape", "path_kind"):
            # logged inside; same envelope as "missing" so the channel cannot
            # be used to map what lies outside the workspace
            return _error(transport_unavailable(raw_path), status=404)
        return _error(exc, status=403)  # deny and other policy errors

    size = opened.stat.st_size
    if size > config.transport_max:
        opened.close()
        return _error(
            transport_too_large(raw_path, size, config.transport_max), status=413
        )

    return StreamingResponse(
        _stream(opened),
        media_type=mime_type(opened.real),
        headers={
            "Content-Length": str(size),
            "Content-Disposition": _content_disposition(os.path.basename(opened.real)),
        },
    )


__all__ = ["download", "DOWNLOAD_PATH"]
