"""Client-side file transport: fetch a descriptor and store it locally.

The server never inlines file bytes. When ``read`` returns a download
descriptor this module fetches the bytes over the signed transport endpoint
and writes them into the local temp directory, so the model can work with a
plain local path.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

from agentfiles_shared.errors import ToolError, transport_unavailable
from agentfiles_shared.transport import DownloadDescriptor

from .client import ToolClient

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def temp_dir(config_temp: str | None = None) -> Path:
    """AF_TEMP_DIR, else <system temp>/agentfiles."""
    root = config_temp or os.environ.get("AF_TEMP_DIR", "").strip()
    base = Path(root) if root else Path(tempfile.gettempdir()) / "agentfiles"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _target_name(descriptor: DownloadDescriptor) -> str:
    """<8-hex content hash>-<sanitized original name>: stable, collision-safe."""
    digest = hashlib.sha256(descriptor.path.encode("utf-8")).hexdigest()[:8]
    name = _SAFE_NAME.sub("_", descriptor.name) or "file"
    return f"{digest}-{name}"


async def fetch(client: ToolClient, descriptor: DownloadDescriptor) -> Path:
    """Download the file and return its local path.

    Writes to ``.part`` first and renames atomically so a partial download is
    never visible under the final name.
    """
    try:
        data = await client.download(descriptor.path)
    except ToolError:
        raise
    except Exception as exc:  # noqa: BLE001 - network layer, keep it generic
        raise transport_unavailable(descriptor.path) from exc

    if descriptor.size and len(data) != descriptor.size:
        raise transport_unavailable(descriptor.path)

    target = temp_dir() / _target_name(descriptor)
    partial = target.with_suffix(target.suffix + ".part")
    try:
        partial.write_bytes(data)
        os.replace(partial, target)
    finally:
        if partial.exists():
            partial.unlink(missing_ok=True)
    return target
