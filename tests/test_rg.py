"""ripgrep adapter: exit codes, parsing bounds, normalization, discovery."""

from __future__ import annotations

import os
import shutil

import pytest

from agentfiles_server import rg
from agentfiles_shared.errors import ToolError

HAS_RG = shutil.which("rg") is not None
pytestmark = pytest.mark.skipif(not HAS_RG, reason="ripgrep (rg) not on PATH")


@pytest.fixture()
def binary() -> str:
    return rg.find_binary(None)


@pytest.fixture()
def tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.ts").write_text("const needle = 1\n", encoding="utf-8")
    (tmp_path / "src" / "b.js").write_text("let needle = 2\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("needle in md\n", encoding="utf-8")
    (tmp_path / ".hidden").write_text("needle hidden\n", encoding="utf-8")
    (tmp_path / ".env").write_text("needle secret\n", encoding="utf-8")
    (tmp_path / "ignored.log").write_text("needle\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("needle\n", encoding="utf-8")
    return tmp_path


def run_glob(binary, cwd, pattern, **kw):
    return rg.run_glob(
        binary, cwd=str(cwd), pattern=pattern, limit=kw.pop("limit", 100),
        deny=kw.pop("deny", []), timeout=kw.pop("timeout", 15), **kw
    )


def run_grep(binary, cwd, pattern, **kw):
    return rg.run_grep(
        binary, cwd=str(cwd), pattern=pattern, file=kw.pop("file", None),
        include=kw.pop("include", None), limit=kw.pop("limit", 100),
        deny=kw.pop("deny", []), timeout=kw.pop("timeout", 15), **kw
    )


# --- glob -------------------------------------------------------------------

def test_glob_matches_pattern(binary, tree):
    result = run_glob(binary, tree, "**/*.ts")
    assert [i for i in result.items] == ["src/a.ts"]


def test_glob_no_match_is_empty(binary, tree):
    result = run_glob(binary, tree, "**/*.rs")
    assert result.items == []
    assert result.truncated is False


def test_glob_positive_glob_overrides_gitignore(binary, tree):
    """V2 parity: the glob tool always passes a positive --glob, and ripgrep's
    positive globs override ignore logic (rg: 'This always overrides any
    other ignore logic'). gitignored files ARE listed."""
    result = run_glob(binary, tree, "**/*.log")
    assert "ignored.log" in result.items


def test_glob_excludes_git_dir(binary, tree):
    result = run_glob(binary, tree, "**/*")
    assert not any(item.startswith(".git/") for item in result.items)


def test_glob_positive_glob_overrides_hidden(binary, tree):
    """Same override applies to hidden files: a matching positive glob wins.
    The deny list is what keeps secrets invisible, not --hidden."""
    result = run_glob(binary, tree, "**/*")
    assert ".hidden" in result.items
    denied = run_glob(binary, tree, "**/*", deny=["*.env"])
    assert ".env" not in denied.items
    assert ".hidden" in denied.items


def test_glob_invalid_pattern_is_not_a_crash(binary, tree):
    """Glob syntax, not regex: rg accepts an unclosed bracket as a literal."""
    result = run_glob(binary, tree, "[unclosed")
    assert isinstance(result.items, list)


def test_glob_deny_excludes_patterns(binary, tree):
    result = run_glob(binary, tree, "**/*", deny=["*.env"])
    assert ".env" not in result.items


def test_glob_limit_truncates(binary, tree):
    result = run_glob(binary, tree, "**/*", limit=2)
    assert len(result.items) == 2
    assert result.truncated is True


def test_glob_path_normalization(binary, tree):
    """Windows separators and ./ prefixes come back as posix-relative."""
    result = run_glob(binary, tree, "**/*")
    for item in result.items:
        assert "\\" not in item
        assert not item.startswith("./")
        assert not item.startswith("/")


# --- grep -------------------------------------------------------------------

def test_grep_finds_matches(binary, tree):
    result = run_grep(binary, tree, "needle")
    paths = {m.path for m in result.items}
    assert "src/a.ts" in paths
    assert "notes.md" in paths
    # --hidden means .env and .hidden are searched...
    assert ".env" in paths


def test_grep_deny_blocks_denied_files(binary, tree):
    # ...but deny globs keep them out of the results entirely
    result = run_grep(binary, tree, "needle", deny=["*.env"])
    assert ".env" not in {m.path for m in result.items}


def test_grep_include_filter(binary, tree):
    result = run_grep(binary, tree, "needle", include="*.ts")
    assert {m.path for m in result.items} == {"src/a.ts"}


def test_grep_single_file_target(binary, tree):
    result = run_grep(binary, tree, "needle", file="src/a.ts")
    assert {m.path for m in result.items} == {"src/a.ts"}


def test_grep_no_match_empty(binary, tree):
    result = run_grep(binary, tree, "definitely-absent-xyz")
    assert result.items == []
    assert result.truncated is False


def test_grep_invalid_regex(binary, tree):
    with pytest.raises(rg.InvalidPattern):
        run_grep(binary, tree, "[unclosed")


def test_grep_limit_truncates(binary, tree):
    result = run_grep(binary, tree, "needle", limit=1)
    assert len(result.items) == 1
    assert result.truncated is True


def test_grep_match_fields(binary, tree):
    result = run_grep(binary, tree, "needle", file="src/a.ts")
    match = result.items[0]
    assert match.line == 1
    assert match.offset == 0
    assert match.submatches and match.submatches[0]["text"] == "needle"


def test_grep_long_line_is_bounded(binary, tree):
    long = "x" * 5000 + "needle"
    (tree / "long.txt").write_text(long + "\n", encoding="utf-8")
    result = run_grep(binary, tree, "needle", file="long.txt")
    match = result.items[0]
    assert len(match.text) <= rg.MAX_LINE_CHARS + len("...")
    assert match.text.endswith("...")


# --- process / discovery -----------------------------------------------------

def test_timeout_is_tool_error(binary, tree):
    with pytest.raises(ToolError) as exc:
        rg.run_glob(
            binary, cwd=str(tree), pattern="**/*", limit=1,
            deny=[], timeout=0.0,
        )
    assert exc.value.code == "rg_timeout"


def test_find_binary_prefers_config(tmp_path):
    fake = tmp_path / "rg.exe"
    fake.write_bytes(b"")
    assert rg.find_binary(str(fake)) == str(fake)


def test_find_binary_missing_raises(monkeypatch):
    monkeypatch.setattr(rg.shutil, "which", lambda _name: None)
    with pytest.raises(ToolError) as exc:
        rg.find_binary(None)
    assert exc.value.code == "rg_unavailable"


def test_missing_cwd_is_tool_error(binary, tmp_path):
    """A cwd rg cannot enter (missing dir) surfaces as ToolError, not OSError."""
    missing = tmp_path / "no-such-dir"
    with pytest.raises(ToolError) as exc:
        rg.run_glob(
            binary, cwd=str(missing), pattern="**/*", limit=10,
            deny=[], timeout=15,
        )
    assert exc.value.code == "rg_failed"
