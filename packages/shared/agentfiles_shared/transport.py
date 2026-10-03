"""File transport contract shared by server and MCP client.

Model: the server never inlines file bytes into tool responses. Instead it
returns a download descriptor; the MCP client fetches the bytes over a signed
``GET /v1/transport/download`` request and stores them in its local temp
directory, giving the model a plain local path.
"""

from __future__ import annotations

from pydantic import BaseModel

# Server-side size cap for a single transport (override: AF_TRANSPORT_MAX)
DEFAULT_TRANSPORT_MAX_BYTES = 100 * 1024 * 1024

# Endpoint path (must be covered by the signing middleware)
DOWNLOAD_PATH = "/v1/transport/download"


class DownloadDescriptor(BaseModel):
    """Returned by read for any image (V2's Content slot, without base64)."""

    type: str = "download"
    path: str        # absolute path on the server (for the signed GET)
    name: str        # basename, shown to the model
    mime: str
    size: int
