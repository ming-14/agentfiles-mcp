"""ripgrep adapter: exit codes, parsing bounds, normalization, discovery."""

from __future__ import annotations

import os
import shutil
import subprocess
import time

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

def _fake_rg(
    directory, payload: bytes, sleep: float = 0, to_stderr: bool = False
) -> str:
    """A stand-in for rg: writes ``payload``, then idles ``sleep`` seconds.

    A real rg always finishes, so the cases the deadline has to survive - a run
    that neither writes nor exits, or one that floods stderr - can only be
    reproduced with a fake.
    """
    seconds = max(1, int(sleep))
    source = directory / "payload.bin"
    source.write_bytes(payload)
    if os.name == "nt":
        lines = ["@echo off", f'type "{source}"' + (" 1>&2" if to_stderr else "")]
        if sleep > 0:
            lines.append(f"ping -n {seconds + 1} 127.0.0.1 > nul")
        script = directory / "fake_rg.bat"
        script.write_text("\r\n".join(lines) + "\r\n", encoding="ascii")
    else:
        lines = ["#!/bin/sh", f'cat "{source}"' + (" >&2" if to_stderr else "")]
        if sleep > 0:
            lines.append(f"sleep {seconds}")
        script = directory / "fake_rg.sh"
        script.write_text("\n".join(lines) + "\n", encoding="ascii")
        script.chmod(0o755)
    return str(script)


def test_timeout_bounds_the_read_loop(tmp_path):
    """A silent, late-exiting rg must not outlive AF_RG_TIMEOUT: iterating
    stdout has no deadline of its own."""
    fake = _fake_rg(tmp_path, b"", sleep=5)
    start = time.monotonic()
    with pytest.raises(ToolError) as exc:
        rg.run_glob(
            fake, cwd=str(tmp_path), pattern="**/*", limit=10,
            deny=[], timeout=0.5,
        )
    assert exc.value.code == "rg_timeout"
    assert time.monotonic() - start < 4.0


def test_noisy_stderr_does_not_deadlock(tmp_path):
    """rg blocks once the stderr pipe fills: draining has to continue past the
    8KB cap, or a chatty run never closes stdout and never exits."""
    fake = _fake_rg(tmp_path, b"rg: warning\n" * 20_000, to_stderr=True)
    result = rg.run_glob(
        fake, cwd=str(tmp_path), pattern="**/*", limit=10, deny=[], timeout=10,
    )
    assert result.items == []


def test_parse_failure_kills_the_child(monkeypatch, tmp_path):
    """A record rg cannot parse used to leave the process running unreaped."""
    fake = _fake_rg(tmp_path, b"x" * (rg.MAX_RECORD_BYTES + 1) + b"\n", sleep=5)
    spawned = []
    real_popen = subprocess.Popen

    def spy(args, **kwargs):
        handle = real_popen(args, **kwargs)
        spawned.append(handle)
        return handle

    monkeypatch.setattr(rg.subprocess, "Popen", spy)
    with pytest.raises(ToolError) as exc:
        rg.run_grep(
            fake, cwd=str(tmp_path), pattern="needle", file=None, include=None,
            limit=10, deny=[], timeout=10,
        )
    assert exc.value.code == "rg_failed"
    assert spawned and spawned[0].poll() is not None


def test_truncated_ignores_a_signal_exit_code(binary, tree, monkeypatch):
    """Closing stdout early can end rg with a signal (-13 SIGPIPE on POSIX)
    instead of 0/1/2; the rows already collected are still good."""

    def wait_then_signal(self, timeout):
        self.handle.wait(timeout=timeout)
        return -13

    monkeypatch.setattr(rg._Process, "wait", wait_then_signal)
    result = run_glob(binary, tree, "**/*", limit=1)
    assert len(result.items) == 1
    assert result.truncated is True


def test_timeout_is_tool_error(binary, tree):
    with pytest.raises(ToolError) as exc:
        rg.run_glob(
            binary, cwd=str(tree), pattern="**/*", limit=1,
            deny=[], timeout=0.0,
        )
    assert exc.value.code == "rg_timeout"


def test_validate_deny_globs_accepts_a_normal_pattern(binary):
    assert rg.validate_deny_globs(binary, ["*.env", "*.env.*"]) is None


def test_validate_deny_globs_flags_a_broken_pattern(binary):
    """An unparsable deny glob makes rg exit 2: every search comes back empty
    with no other symptom, so startup needs to be able to spot it."""
    complaint = rg.validate_deny_globs(binary, ["**/{a"])
    assert complaint and "glob" in complaint


def test_startup_warns_about_a_broken_deny_glob(binary, tmp_path, capsys):
    from agentfiles_server.__main__ import _warn_on_broken_deny_globs
    from agentfiles_server.config import Config

    def warn(patterns):
        _warn_on_broken_deny_globs(
            Config(
                workspace=str(tmp_path), tokens={"t": "s"},
                read_deny=patterns, ripgrep_path=binary,
            )
        )
        return capsys.readouterr().err

    assert warn(["*.env"]) == ""
    assert "AF_READ_DENY" in warn(["**/{a"])


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
