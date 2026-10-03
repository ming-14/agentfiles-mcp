"""Read engine: mirrors packages/core/src/tool/read-filesystem.ts.

Differences from V2 (deliberate):
  * images are never inlined as base64; they yield a ``Download`` descriptor
    that the MCP client fetches through the transport endpoint
  * images are sent as-is (no resize / no re-encode), but still validated so a
    corrupt image fails with ``Image could not be decoded: <resource>``
"""

from __future__ import annotations

import codecs
import mimetypes
import os
from dataclasses import dataclass
from pathlib import Path

from agentfiles_shared.errors import binary_file, image_decode, \
    media_ingest_limit, malformed_utf8, offset_out_of_range, path_kind
from agentfiles_shared.schema import (
    MAX_LINE_LENGTH,
    MAX_LINE_SUFFIX,
    MAX_MEDIA_INGEST_BYTES,
    MAX_READ_BYTES,
    MAX_READ_LINES,
)
from agentfiles_shared.transport import DownloadDescriptor

# 31 binary extensions (V2 read-filesystem.ts)
BINARY_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".exe", ".dll", ".so", ".class", ".jar", ".war",
    ".7z", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
    ".odp", ".bin", ".dat", ".obj", ".o", ".a", ".lib", ".wasm", ".pyc", ".pyo",
}


@dataclass(frozen=True)
class Content:
    """FileSystem.Content equivalent; encoding is always utf8 here."""

    uri: str
    name: str
    content: str
    encoding: str  # "utf8"
    mime: str

    def to_result(self) -> dict:
        return {
            "uri": self.uri,
            "name": self.name,
            "content": self.content,
            "encoding": self.encoding,
            "mime": self.mime,
        }


@dataclass(frozen=True)
class TextPage:
    content: str
    mime: str
    offset: int
    truncated: bool
    next: int | None = None

    def to_result(self) -> dict:
        result = {
            "type": "text-page",
            "content": self.content,
            "mime": self.mime,
            "offset": self.offset,
            "truncated": self.truncated,
        }
        if self.next is not None:
            result["next"] = self.next
        return result


@dataclass(frozen=True)
class ListPage:
    entries: list[dict]  # [{path, type}]
    truncated: bool
    next: int | None = None

    def to_result(self) -> dict:
        result = {"entries": self.entries, "truncated": self.truncated}
        if self.next is not None:
            result["next"] = self.next
        return result


def inspect(path: str) -> str:
    """Return "file" | "directory"; raise path_kind for anything else."""
    if os.path.isfile(path):
        return "file"
    if os.path.isdir(path):
        return "directory"
    raise path_kind(path, "a file or directory")


def mime_type(path: str) -> str:
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


def _file_uri(path: str) -> str:
    return Path(path).resolve().as_uri()


# --- sniffing ---------------------------------------------------------------

_IMAGE_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
]


def image_mime(head: bytes) -> str | None:
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    for signature, mime in _IMAGE_SIGNATURES:
        if head.startswith(signature):
            return mime
    return None


def is_binary(resource: str, data: bytes) -> bool:
    """V2 binary(): extension blacklist, NUL byte, >30% non-printable."""
    if os.path.splitext(resource)[1].lower() in BINARY_EXTENSIONS:
        return True
    if not data:
        return False
    non_printable = 0
    for byte in data:
        if byte == 0:
            return True
        if byte < 9 or (13 < byte < 32):
            non_printable += 1
    return non_printable / len(data) > 0.3


# --- image validation (struct only, never modifies the file) -----------------

def _validate_image(mime: str, data: bytes) -> bool:
    if mime == "image/png":
        if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) < 8 + 25 + 12:
            return False
        # IHDR must be the first chunk, IEND must terminate the stream
        if data[12:16] != b"IHDR":
            return False
        return data.rfind(b"IEND") > 0 and data[-8:-4] == b"IEND"
    if mime == "image/jpeg":
        if not data.startswith(b"\xff\xd8\xff"):
            return False
        if len(data) < 4 or not data.rstrip(b"\x00").endswith(b"\xff\xd9"):
            return False
        return True
    if mime == "image/gif":
        if not data.startswith((b"GIF87a", b"GIF89a")):
            return False
        return len(data) >= 14 and data[-1:] == b";"
    if mime == "image/webp":
        if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
            return False
        riff_size = int.from_bytes(data[4:8], "little")
        # RIFF size counts bytes after the size field
        return riff_size <= len(data) - 8 + 1
    return False


# --- file reading -------------------------------------------------------------

def read_file(
    absolute: str, resource: str, *, offset: int | None, limit: int | None
) -> Content | TextPage | DownloadDescriptor:
    """V2 read(): image transport / full text / paged text."""
    real = os.path.realpath(absolute)
    if not os.path.isfile(real):
        raise path_kind(resource, "a file")

    size = os.path.getsize(real)
    with open(real, "rb") as handle:
        first = handle.read(min(64 * 1024, size or 4 * 1024))

        mime = image_mime(first)
        if mime:
            if size > MAX_MEDIA_INGEST_BYTES:
                raise media_ingest_limit(resource, MAX_MEDIA_INGEST_BYTES)
            data = first + handle.read(MAX_MEDIA_INGEST_BYTES - len(first))
            if len(data) > MAX_MEDIA_INGEST_BYTES:
                raise media_ingest_limit(resource, MAX_MEDIA_INGEST_BYTES)
            if not _validate_image(mime, data):
                raise image_decode(resource)
            return DownloadDescriptor(
                path=real,
                name=os.path.basename(real),
                mime=mime,
                size=len(data),
            )

        if first.startswith(b"%PDF") or os.path.splitext(resource)[1].lower() in BINARY_EXTENSIONS:
            raise binary_file(resource)

        paged = size > MAX_READ_BYTES or offset is not None or limit is not None
        if not paged:
            if is_binary(resource, first):
                raise binary_file(resource)
            chunks = [first]
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                if is_binary(resource, chunk):
                    raise binary_file(resource)
                chunks.append(chunk)
            try:
                text = b"".join(chunks).decode("utf-8")
            except UnicodeDecodeError:
                raise malformed_utf8(resource) from None
            return Content(
                uri=_file_uri(real),
                name=os.path.basename(real),
                content=text,
                encoding="utf8",
                mime=mime_type(real),
            )

        return _read_paged(handle, first, resource, real, offset=offset, limit=limit)


def _read_paged(handle, first: bytes, resource: str, real: str,
                *, offset: int | None, limit: int | None) -> TextPage:
    """V2's line pagination state machine (64KB chunks, strict UTF-8)."""
    start_offset = offset or 1
    page_limit = min(limit or MAX_READ_LINES, MAX_READ_LINES)

    lines: list[str] = []
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    pending = ""
    discard = False
    line = 1
    nbytes = 0
    next_line: int | None = None

    def append(text: str) -> bool:
        nonlocal line, nbytes, next_line
        if line < start_offset:
            line += 1
            return True
        if len(lines) >= page_limit or nbytes >= MAX_READ_BYTES:
            next_line = line
            return False
        out = text if len(text) <= MAX_LINE_LENGTH else text[:MAX_LINE_LENGTH] + MAX_LINE_SUFFIX
        size_of_line = len(out.encode("utf-8")) + (1 if lines else 0)
        if nbytes + size_of_line > MAX_READ_BYTES:
            next_line = line
            return False
        lines.append(out)
        nbytes += size_of_line
        line += 1
        return True

    def consume(text: str) -> bool:
        nonlocal pending, discard
        rest = text
        while True:
            index = rest.find("\n")
            if index == -1:
                if not discard:
                    pending += rest
                    if len(pending) > MAX_LINE_LENGTH:
                        pending = pending[:MAX_LINE_LENGTH + 1]
                        discard = True
                return True
            current = pending + ("" if discard else rest[:index])
            pending = ""
            discard = False
            rest = rest[index + 1:]
            if current.endswith("\r"):
                current = current[:-1]
            if not append(current):
                return False

    def consume_chunk(chunk: bytes) -> bool:
        nonlocal next_line
        start = 0
        while start < len(chunk):
            if len(lines) >= page_limit or nbytes >= MAX_READ_BYTES:
                next_line = line
                return False
            newline = chunk.find(b"\n", start)
            end = len(chunk) if newline == -1 else newline + 1
            segment = chunk[start:end]
            if is_binary(resource, segment):
                raise binary_file(resource)
            try:
                decoded = decoder.decode(segment, final=False)
            except UnicodeDecodeError:
                raise malformed_utf8(resource) from None
            if not consume(decoded):
                return False
            start = end
        return True

    done = not consume_chunk(first)
    while not done:
        chunk = handle.read(64 * 1024)
        if not chunk:
            break
        done = not consume_chunk(chunk)
    if not done:
        try:
            tail = decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            raise malformed_utf8(resource) from None
        if not discard:
            pending += tail
        if pending:
            append(pending[:-1] if pending.endswith("\r") else pending)

    if not lines and start_offset != 1:
        raise offset_out_of_range(start_offset)

    return TextPage(
        content="\n".join(lines),
        mime=mime_type(real),
        offset=start_offset,
        truncated=next_line is not None,
        next=next_line,
    )


# --- directory listing ---------------------------------------------------------

def list_dir(absolute: str, *, offset: int | None, limit: int | None) -> ListPage:
    """V2 list(): reject escaping symlinks, dirs first, locale-aware sort."""
    import locale

    real = os.path.realpath(absolute)
    if not os.path.isdir(real):
        raise path_kind(real, "a file or directory")

    entries: list[dict] = []
    for name in os.listdir(real):
        child = os.path.join(real, name)
        try:
            target = os.path.realpath(child)
        except OSError:
            continue
        # reject symlinks escaping the listed directory (V2 FSUtil.contains)
        if not contains(real, target):
            continue
        try:
            is_dir = os.path.isdir(target)
            is_file = os.path.isfile(target)
        except OSError:
            continue
        if not (is_dir or is_file):
            continue
        suffix = os.sep if is_dir else ""
        entries.append({"path": name + suffix, "type": "directory" if is_dir else "file"})

    try:
        locale.setlocale(locale.LC_COLLATE, "")
        entries.sort(key=lambda e: (0 if e["type"] == "directory" else 1,
                                    locale.strxfrm(e["path"])))
    except (locale.Error, TypeError):
        entries.sort(key=lambda e: (0 if e["type"] == "directory" else 1, e["path"]))

    start_offset = offset or 1
    page_limit = min(limit or MAX_READ_LINES, MAX_READ_LINES)
    selected = entries[start_offset - 1: start_offset - 1 + page_limit]
    truncated = start_offset - 1 + len(selected) < len(entries)
    next_offset = start_offset + len(selected) if truncated else None
    return ListPage(entries=selected, truncated=truncated, next=next_offset)


def contains(parent: str, child: str) -> bool:
    rel = os.path.relpath(child, parent)
    return rel == "." or (not os.path.isabs(rel) and not rel.startswith(".."))


__all__ = [
    "Content", "TextPage", "ListPage",
    "inspect", "read_file", "list_dir",
    "image_mime", "is_binary", "mime_type",
    "BINARY_EXTENSIONS",
]
