"""filemut unit level: BOM sequences, receipt provenance, lock table lifecycle."""

from __future__ import annotations

import os

import pytest

from agentfiles_server.filemut import join_bom, split_bom

BOM = b"\xef\xbb\xbf"

# UTF-8 text that starts with a byte from {0xEF, 0xBB, 0xBF} but is NOT a BOM
CJK_LEADING = "！重点".encode()        # U+FF01 -> EF BC 81
KATAKANA_LEADING = "ｱｲ".encode()       # U+FF71 -> EF BD B1
PRIVATE_USE = "\uf000x".encode()      # U+F000 -> EF 80 80
MIXED_BOM_TEXT = BOM + CJK_LEADING


@pytest.mark.parametrize(
    "raw",
    [CJK_LEADING, KATAKANA_LEADING, PRIVATE_USE, BOM[:1], BOM[:2], BOM[:1] + b"x"],
)
def test_split_bom_leaves_non_bom_prefix_alone(raw: bytes):
    had, body = split_bom(raw)
    assert had is False
    assert body == raw


def test_split_bom_detects_a_real_bom():
    assert split_bom(BOM + b"hello") == (True, b"hello")


def test_split_bom_collapses_a_run_of_boms():
    assert split_bom(BOM * 3 + b"hello") == (True, b"hello")


def test_split_bom_stops_at_the_first_non_bom_byte():
    # the 0xEF of '！' follows the BOM and must survive
    had, body = split_bom(MIXED_BOM_TEXT)
    assert had is True
    assert body == CJK_LEADING
    assert body.decode("utf-8") == "！重点"


def test_join_bom_preserves_leading_cjk_byte():
    assert join_bom(CJK_LEADING, False) == CJK_LEADING


def test_join_bom_prepends_one_bom_without_eating_content():
    assert join_bom(CJK_LEADING, True) == BOM + CJK_LEADING
    assert (BOM + CJK_LEADING).decode("utf-8") == "\ufeff！重点"


def test_join_bom_collapses_incoming_boms():
    assert join_bom(BOM * 2 + b"hello", True) == BOM + b"hello"
    assert join_bom(BOM + b"hello", False) == b"hello"


# --- finish: the receipt comes from the handle, never from the path ----------

def test_finish_marks_from_the_handle_not_the_path(tmp_path, monkeypatch):
    """After the write, the path may already point somewhere else; the receipt
    must describe the handle that carried the bytes. A path stat would hand
    out a marker for a file the caller never wrote (fail-open on the next
    write)."""
    from agentfiles_server import filemut

    target = tmp_path / "f.txt"   # create_with_dirs needs the path to be free
    handle = filemut.create_with_dirs(str(target), b"written\n")

    def boom(*args, **kwargs):
        raise AssertionError("finish must not stat by path")

    with monkeypatch.context() as patch:
        patch.setattr(filemut.os, "stat", boom)
        marker = filemut.finish(handle)

    assert handle.fd == -1
    assert marker.size == len(b"written\n")
    with open(target, "rb") as saved:
        assert saved.read() == b"written\n"


# --- target_lock: the table must not grow forever ----------------------------

def _key(path: str) -> str:
    """Mirror of filemut's lock-table key normalization."""
    return path.replace("\\", "/").lower() if os.name == "nt" else path


def test_target_lock_entry_is_released_when_idle():
    from agentfiles_server import filemut

    key = "lock-table-test.txt"  # keys are paths; no filesystem is involved
    with filemut.target_lock(key):
        assert _key(key) in filemut._locks
    assert _key(key) not in filemut._locks


def test_target_lock_entry_lives_while_a_caller_holds_it():
    """Reference counting, not delete-on-release: evicting the entry while a
    holder or waiter still has the object would let the next caller take a
    fresh, unrelated lock."""
    import threading

    from agentfiles_server import filemut

    key = "lock-held-test.txt"
    entered = threading.Event()
    release = threading.Event()

    def holder():
        with filemut.target_lock(key):
            entered.set()
            release.wait(5)

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert entered.wait(5)
        assert _key(key) in filemut._locks  # still referenced by the holder
    finally:
        release.set()
        thread.join(5)
    assert _key(key) not in filemut._locks
