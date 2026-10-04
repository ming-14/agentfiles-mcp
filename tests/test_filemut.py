"""filemut unit level: BOM sequences, receipt provenance, lock table lifecycle."""

from __future__ import annotations

import os

import pytest

from agentfiles_server.filemut import _lock_key, join_bom, split_bom

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
    from agentfiles_server.fslayer import Resolver

    target = tmp_path / "f.txt"
    opened = Resolver(str(tmp_path)).create_file(str(target))
    handle = filemut.adopt_created(opened)
    filemut.modify(handle, b"written\n")

    def boom(*args, **kwargs):
        raise AssertionError("finish must not stat by path")

    with monkeypatch.context() as patch:
        patch.setattr(filemut.os, "stat", boom)
        marker = filemut.finish(handle)

    assert handle.fd == -1
    assert marker.size == len(b"written\n")
    with open(target, "rb") as saved:
        assert saved.read() == b"written\n"


# --- _matches: what a marker has to agree with -------------------------------

def _stat(mtime_ns: int, size: int, ino: int, dev: int):
    import types

    return types.SimpleNamespace(
        st_mtime_ns=mtime_ns, st_size=size, st_ino=ino, st_dev=dev
    )


def test_matches_identity_when_the_volume_has_one():
    from agentfiles_server import filemut

    stat = _stat(111, 8, 42, 7)
    assert filemut._matches(stat, 111, 8, 42, 7) is True
    # same size, same mtime, different file
    assert filemut._matches(stat, 111, 8, 43, 7) is False


def test_matches_treats_an_omitted_identity_as_a_mismatch():
    """The comparison is chosen by what the volume reports, not by what the
    caller bothered to carry -- otherwise ino/dev could be dropped to get the
    weaker mtime+size check."""
    from agentfiles_server import filemut

    assert filemut._matches(_stat(111, 8, 42, 7), 111, 8, 0, 0) is False


def test_matches_falls_back_to_mtime_and_size_without_inodes():
    """A file with no st_ino of its own has no identity to compare."""
    from agentfiles_server import filemut

    stat = _stat(111, 8, 0, 0)
    assert filemut._matches(stat, 111, 8, 0, 0) is True
    assert filemut._matches(stat, 111, 9, 0, 0) is False


def test_same_path_folds_separators_only_where_they_are_separators():
    """A backslash separates on Windows and is a legal name character on
    POSIX: folding it unconditionally would call two files the same there."""
    from agentfiles_server import filemut

    assert filemut._same_path("/ws/a\\b.txt", "/ws/a/b.txt") is (os.name == "nt")


# --- target_lock: the table must not grow forever ----------------------------

def test_target_lock_entry_is_released_when_idle():
    from agentfiles_server import filemut

    key = "lock-table-test.txt"  # keys are paths; no filesystem is involved
    with filemut.target_lock(key):
        assert _lock_key(key) in filemut._locks
    assert _lock_key(key) not in filemut._locks


def test_target_lock_yields_a_held_lock():
    """The manager hands out a Lock object -- it has to acquire it too. A
    context manager that merely yields the object makes every
    ``with target_lock(path)`` a critical section in appearance only."""
    from agentfiles_server import filemut

    key = "lock-acquired-test.txt"
    with filemut.target_lock(key) as lock:
        assert lock.locked()


def test_target_lock_excludes_a_second_caller():
    """Concurrency: two callers on one path must not be inside at once.

    Without mutual exclusion two edits both pass verify_unchanged (neither
    has written yet) and both report success -- one payload is silently lost.
    """
    import threading

    from agentfiles_server import filemut

    key = "lock-exclusive-test.txt"
    entered = threading.Event()
    release = threading.Event()
    second = {}

    def holder():
        with filemut.target_lock(key):
            entered.set()
            release.wait(5)

    def waiter():
        with filemut.target_lock(key):
            second["inside"] = True

    first = threading.Thread(target=holder)
    first.start()
    try:
        assert entered.wait(5)
        late = threading.Thread(target=waiter)
        late.start()
        late.join(0.5)
        assert "inside" not in second, "second caller entered a held section"
        release.set()
        late.join(5)
        assert second.get("inside") is True, "the waiter never got in"
    finally:
        release.set()
        first.join(5)


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
        assert _lock_key(key) in filemut._locks  # still referenced by the holder
    finally:
        release.set()
        thread.join(5)
    assert _lock_key(key) not in filemut._locks


def test_one_lock_per_target_whatever_spelling_located_it(link_dir, tmp_path):
    """locate() output can carry a link the kernel resolves away at open time;
    two spellings of one file that keyed apart would share no exclusion, and
    both callers would verify against a stat taken before either wrote."""
    from agentfiles_server import filemut

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link_dir(real, link)

    through_link = _lock_key(str(link / "a.txt"))
    assert through_link == _lock_key(str(real / "a.txt"))
    with filemut.target_lock(str(link / "a.txt")) as held:
        assert filemut._locks[through_link] is held
