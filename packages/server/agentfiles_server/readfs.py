"""Read engine: mirrors packages/core/src/tool/read-filesystem.ts.

Differences from V2 (deliberate):
  * images are never inlined as base64; they yield a ``Download`` descriptor
    that the MCP client fetches through the transport endpoint
  * images are sent as-is (no resize / no re-encode), but still validated so a
    corrupt image fails with ``Image could not be decoded: <resource>``
"""

from __future__ import annotations

import codecs
import locale
import mimetypes
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from agentfiles_shared.errors import binary_file, image_decode, \
    media_ingest_limit, malformed_utf8, offset_out_of_range
from agentfiles_shared.schema import (
    MAX_LINE_LENGTH,
    MAX_LINE_SUFFIX,
    MAX_MEDIA_INGEST_BYTES,
    MAX_READ_BYTES,
    MAX_READ_LINES,
    Version,
)
from agentfiles_shared.transport import DownloadDescriptor

from .filemut import version_of
from .fslayer import contains

# Binary extensions (V2 read-filesystem.ts). 28 entries; V2's header claims 31.
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
    # write/edit receipt: fstat of the handle these bytes came from
    # (images and directories grant none)
    version: Version | None = None

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
    # see Content.version: same receipt, same provenance (the read handle)
    version: Version | None = None

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
        # every read result carries a `type` so callers can discriminate
        # without shape-sniffing (V2's list result has none; see schema.ListPage)
        result = {
            "type": "list-page",
            "entries": self.entries,
            "truncated": self.truncated,
        }
        if self.next is not None:
            result["next"] = self.next
        return result


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


# The 30% non-printable ratio is only meaningful over a decent sample: paged
# reads run is_binary() once per line segment, and a short segment of control
# characters is normal text (log markers, escape sequences), not a binary file.
# Below this size only the NUL byte disqualifies a sample.
MIN_BINARY_SAMPLE_BYTES = 512


def is_binary(resource: str, data: bytes) -> bool:
    """V2 binary(): extension blacklist, NUL byte, >30% non-printable.

    The ratio rule is skipped for samples shorter than
    ``MIN_BINARY_SAMPLE_BYTES`` (see the note above); everything else follows
    V2.
    """
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
    if len(data) < MIN_BINARY_SAMPLE_BYTES:
        return False
    return non_printable / len(data) > 0.3


# --- image validation (struct only, never modifies the file) -----------------

# Structural checks only look at the opening signature and the closing bytes
# (PNG IEND / JPEG EOI / GIF terminator / RIFF length), so the trailer read
# for them is this long -- a 20MB image never has to be read whole.
IMAGE_TAIL_BYTES = 64


def _validate_image(mime: str, head: bytes, tail: bytes, size: int) -> bool:
    """Check image structure from ``head`` + ``tail`` + the real ``size``.

    ``size`` carries the real file length; the slices are only ever inspected
    for signature/trailer bytes, so neither of them needs the file's middle.
    """
    if mime == "image/png":
        if not head.startswith(b"\x89PNG\r\n\x1a\n") or size < 8 + 25 + 12:
            return False
        # IHDR must be the first chunk, IEND must terminate the stream
        if head[12:16] != b"IHDR":
            return False
        return tail.rfind(b"IEND") > 0 and tail[-8:-4] == b"IEND"
    if mime == "image/jpeg":
        if not head.startswith(b"\xff\xd8\xff"):
            return False
        if size < 4 or not tail.rstrip(b"\x00").endswith(b"\xff\xd9"):
            return False
        return True
    if mime == "image/gif":
        if not head.startswith((b"GIF87a", b"GIF89a")):
            return False
        return size >= 14 and tail[-1:] == b";"
    if mime == "image/webp":
        if size < 12 or head[:4] != b"RIFF" or head[8:12] != b"WEBP":
            return False
        riff_size = int.from_bytes(head[4:8], "little")
        # RIFF size counts bytes after the size field
        return riff_size <= size - 8 + 1
    return False


# --- file reading -------------------------------------------------------------

def read_opened(
    opened, *, offset: int | None, limit: int | None
) -> Content | TextPage | DownloadDescriptor:
    """V2 read() over an already-opened, containment-verified handle.

    The caller owns ``opened``; this function only reads through its fd (the
    descriptor is left open -- the tool closes it). Text results carry the
    write/edit receipt: the fstat taken at open time, before any read. A path
    stat taken afterwards (or an fstat after the read) could describe a file
    swapped in during the read, and that marker would then verify as
    "unchanged" for content nobody ever saw.
    """
    resource = opened.resource
    real = opened.real
    handle = os.fdopen(os.dup(opened.fd), "rb")
    with handle:
        # one fstat at open, before any read: receipt source and authoritative
        # size. The size is deliberately the handle's, not a fresh
        # os.path.getsize: a file that grows after this point is under-read
        # rather than described by a size that never matched the bytes we
        # are about to return.
        marker = version_of(opened.fd, real)
        size = marker.size
        first = handle.read(min(64 * 1024, size or 4 * 1024))

        mime = image_mime(first)
        if mime:
            if size > MAX_MEDIA_INGEST_BYTES:
                raise media_ingest_limit(resource, MAX_MEDIA_INGEST_BYTES)
            # only the trailer is needed for the structural check
            handle.seek(max(0, size - IMAGE_TAIL_BYTES))
            tail = handle.read(IMAGE_TAIL_BYTES)
            if not _validate_image(mime, first, tail, size):
                raise image_decode(resource)
            return DownloadDescriptor(
                path=real,
                name=os.path.basename(real),
                mime=mime,
                size=size,
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
                version=marker,
            )

        return _read_paged(handle, first, resource, real, offset=offset,
                           limit=limit, version=marker)


def _read_paged(handle, first: bytes, resource: str, real: str,
                *, offset: int | None, limit: int | None,
                version: Version | None = None) -> TextPage:
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
        version=version,
    )


# --- directory listing ---------------------------------------------------------

# ``locale.setlocale`` flips a process-global setting. list_dir runs on the
# threadpool, so the switch, the sort and the restore are serialized here --
# otherwise two concurrent listings interleave their locale switches, and every
# other thread sharing the process sees the transient locale.
_COLLATE_LOCK = threading.Lock()


def _entry_key(entry: dict) -> tuple[int, str]:
    return (0 if entry["type"] == "directory" else 1, entry["path"])


def _sort_entries(entries: list[dict]) -> None:
    """Dirs first, then the environment's locale collation of the name."""
    with _COLLATE_LOCK:
        previous: str | None = None
        try:
            previous = locale.setlocale(locale.LC_COLLATE)
            locale.setlocale(locale.LC_COLLATE, "")
            entries.sort(
                key=lambda e: _entry_key(e) + (locale.strxfrm(e["path"]),)
            )
        except (locale.Error, TypeError):
            entries.sort(key=_entry_key)
        finally:
            if previous is not None:
                try:
                    locale.setlocale(locale.LC_COLLATE, previous)
                except locale.Error:
                    pass


def list_dir(opened, *, offset: int | None, limit: int | None) -> ListPage:
    """V2 list() over a containment-verified directory handle.

    Listing walks ``opened.real`` (the kernel-resolved path of the handle we
    already verified): POSIX could list the fd directly, but Windows cannot
    (os.listdir rejects int), so one code path uses the verified real path --
    the documented directory-only micro-race. Each child is re-checked with
    realpath + contains below, so entries escaping the verified directory are
    dropped regardless.
    """
    real = opened.real

    names = _list_names(opened)

    entries: list[dict] = []
    for name in names:
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

    _sort_entries(entries)

    start_offset = offset or 1
    page_limit = min(limit or MAX_READ_LINES, MAX_READ_LINES)
    selected = entries[start_offset - 1: start_offset - 1 + page_limit]
    truncated = start_offset - 1 + len(selected) < len(entries)
    next_offset = start_offset + len(selected) if truncated else None
    return ListPage(entries=selected, truncated=truncated, next=next_offset)


def _list_names(opened) -> list[str]:
    try:
        return os.listdir(opened.fd)  # POSIX: names straight off the handle
    except (TypeError, OSError):
        # Windows has no fd-based listdir; use the verified real path
        return os.listdir(opened.real)


__all__ = [
    "Content", "TextPage", "ListPage",
    "read_opened", "list_dir",
    "image_mime", "is_binary", "mime_type",
    "BINARY_EXTENSIONS", "MIN_BINARY_SAMPLE_BYTES",
]
