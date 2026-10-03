"""readfs unit level: binary sniffing (paged reads check one line segment at
a time) and directory listing (locale handling)."""

from __future__ import annotations

import locale
import os
import threading

import pytest

from agentfiles_server import readfs
from agentfiles_server.readfs import BINARY_EXTENSIONS, MIN_BINARY_SAMPLE_BYTES, is_binary


def test_nul_byte_is_binary_regardless_of_length():
    assert is_binary("a.txt", b"abc\x00def")
    assert is_binary("a.txt", b"\x00")


def test_short_control_char_sample_is_text():
    """Paged reads run is_binary() per line segment; three control characters
    in a short line must not turn a text file into binary_file."""
    assert is_binary("a.txt", b"\x01\x02\x03") is False
    assert is_binary("a.txt", b"\x01\x02\x03\n") is False
    assert is_binary("a.txt", b"\x07\x07\x07ok\n") is False


def test_long_control_char_sample_is_binary():
    sample = b"\x01" * MIN_BINARY_SAMPLE_BYTES
    assert is_binary("a.txt", sample) is True
    # just under the threshold: no ratio verdict
    assert is_binary("a.txt", sample[:-1]) is False


def test_printable_sample_is_text():
    assert is_binary("a.txt", b"hello world\n" * 60) is False


def test_binary_extension_wins_over_content():
    assert is_binary("thing.dat", b"plain text here") is True
    assert ".dat" in BINARY_EXTENSIONS


# --- image validation: head + tail only, never the whole file ----------------

PNG_SIG = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000")
PNG_TRAILER = bytes.fromhex("0000000049454e44ae426082")


def test_png_needs_only_head_and_tail():
    # no middle at all: signature + IHDR from the head, IEND from the tail
    assert readfs._validate_image("image/png", PNG_SIG, PNG_TRAILER, size=4096) is True
    # ...but a too-small file is rejected via the real size
    assert readfs._validate_image("image/png", PNG_SIG, PNG_TRAILER, size=10) is False


def test_png_without_iend_in_tail_is_rejected():
    assert readfs._validate_image("image/png", PNG_SIG, b"\x00" * 32, size=4096) is False


def test_webp_riff_length_uses_real_file_size():
    head = b"RIFF\x00\x10\x00\x00WEBP"  # declares 0x1000 payload bytes
    tail = b"VP8 " + b"\x00" * 32
    # a file that really holds the declared payload is fine
    assert readfs._validate_image("image/webp", head, tail, size=0x1000 + 8) is True
    # a truncated file (declared length larger than what's on disk) is not
    assert readfs._validate_image("image/webp", head, tail, size=2000) is False


@pytest.mark.parametrize("mime,head,tail,size", [
    ("image/png", b"\x89PNG\r\n\x1a\n" + b"x" * 40, PNG_TRAILER, 4096),  # no IHDR
    ("image/jpeg", b"\xff\xd8\xff\xe0" + b"JFIF" * 4, b"garbage", 64),
    ("image/gif", b"GIF89a" + b"\x00" * 8, b"nope", 64),
    ("application/pdf", b"%PDF", b"", 100),  # unknown mime
])
def test_broken_images_rejected(mime, head, tail, size):
    assert readfs._validate_image(mime, head, tail, size) is False


def test_large_image_reads_head_and_tail_only(tmp_path, monkeypatch):
    """A 200KB image must never be slurped whole for a structural check."""
    import builtins

    from agentfiles_shared.transport import DownloadDescriptor

    filler = b"\x00" * (200_000 - len(PNG_SIG) - len(PNG_TRAILER))
    image = tmp_path / "big.png"
    image.write_bytes(PNG_SIG + filler + PNG_TRAILER)

    reads = {"bytes": 0}
    genuine_open = builtins.open

    class CountingHandle:
        def __init__(self, handle):
            self._handle = handle

        def read(self, size=-1):
            chunk = self._handle.read(size)
            reads["bytes"] += len(chunk)
            return chunk

        def __enter__(self):
            self._handle.__enter__()
            return self

        def __exit__(self, *exc_info):
            return self._handle.__exit__(*exc_info)

        def __getattr__(self, name):
            return getattr(self._handle, name)

    def counting_open(*args, **kwargs):
        handle = genuine_open(*args, **kwargs)
        return CountingHandle(handle) if str(args[0]).endswith("big.png") else handle

    monkeypatch.setattr(readfs, "open", counting_open, raising=False)

    result = readfs.read_file(str(image), "big.png", offset=None, limit=None)

    assert isinstance(result, DownloadDescriptor)
    assert result.size == 200_000
    assert result.mime == "image/png"
    head = 64 * 1024
    assert head < reads["bytes"] <= head + readfs.IMAGE_TAIL_BYTES


# --- directory listing: locale is process-global -----------------------------

def test_list_dir_sorts_dirs_first(tmp_path):
    (tmp_path / "bdir").mkdir()
    (tmp_path / "adir").mkdir()
    (tmp_path / "zfile.txt").write_text("x")
    page = readfs.list_dir(str(tmp_path), offset=None, limit=None)
    paths = [entry["path"] for entry in page.entries]
    assert paths == ["adir" + os.sep, "bdir" + os.sep, "zfile.txt"]


def test_list_dir_restores_locale(tmp_path):
    """setlocale mutates process-global state: it must not leak past list_dir."""
    (tmp_path / "a").write_text("x")
    before = locale.setlocale(locale.LC_COLLATE)
    readfs.list_dir(str(tmp_path), offset=None, limit=None)
    assert locale.setlocale(locale.LC_COLLATE) == before


def test_concurrent_listings_do_not_interleave_locale(tmp_path):
    for i in range(5):
        (tmp_path / f"file{i}.txt").write_text("x")
    before = locale.setlocale(locale.LC_COLLATE)
    failures: list[BaseException] = []

    def worker():
        try:
            for _ in range(10):
                page = readfs.list_dir(str(tmp_path), offset=None, limit=None)
                assert len(page.entries) == 5
        except BaseException as exc:  # noqa: BLE001 - surfaced after the join
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not failures
    assert locale.setlocale(locale.LC_COLLATE) == before


# --- errors report the resource, not the server-side path --------------------

def test_list_dir_error_reports_resource(tmp_path):
    from agentfiles_shared.errors import ToolError

    target = tmp_path / "note.txt"
    target.write_text("x")
    with pytest.raises(ToolError) as exc:
        readfs.list_dir(str(target), offset=1, limit=1, resource="note.txt")
    assert "note.txt" in exc.value.message
    assert str(tmp_path) not in exc.value.message


def test_inspect_error_reports_resource(tmp_path):
    from agentfiles_shared.errors import ToolError

    with pytest.raises(ToolError) as exc:
        readfs.inspect(str(tmp_path / "missing"), resource="missing")
    assert exc.value.code == "path_kind"
    assert "missing" in exc.value.message
    assert str(tmp_path) not in exc.value.message

    (tmp_path / "note.txt").write_text("x")
    assert readfs.inspect(str(tmp_path / "note.txt")) == "file"
