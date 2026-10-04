"""ripgrep execution adapter (mirrors packages/core/src/ripgrep.ts).

Spawns the rg binary, streams stdout line by line, and maps exit codes the
same way V2 does:
    1                -> no matches
    2 + regex error  -> InvalidPattern (grep only)
    2                -> partial results
    anything else    -> failure with the captured stderr (8KB cap)

Deny patterns from AF_READ_DENY are translated into ``--glob=!pattern``
exclusions so a file that cannot be read also cannot be surfaced by search.

AF_RG_TIMEOUT bounds the whole run: reading stdout happens on a worker thread
that the caller joins against a deadline, because a rg that neither writes nor
exits would otherwise block for as long as it likes.

stderr is drained by a background thread from spawn time: a chatty rg would
otherwise fill the pipe while we are still reading stdout and deadlock.
"""

from __future__ import annotations

import contextlib
import json
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from agentfiles_shared.errors import ToolError

MAX_RECORD_BYTES = 64 * 1024
MAX_SUBMATCHES = 100
MAX_LINE_CHARS = 2_000
ERROR_BYTES = 8 * 1024
# a glob probe runs against an empty directory, where rg parses the globs
# before walking anything
PROBE_TIMEOUT = 10.0
# a process wedged in uninterruptible IO can outlive kill()
KILL_TIMEOUT = 5.0

_INVALID_PATTERN = re.compile(r"regex parse error|error parsing regex")


def find_binary(configured: str | None) -> str:
    """AF_RIPGREP_PATH first, then PATH lookup."""
    if configured:
        return configured
    found = shutil.which("rg")
    if not found:
        raise ToolError(
            "rg_unavailable", "ripgrep (rg) is not available on the server"
        )
    return found


@dataclass
class RunResult:
    items: list = field(default_factory=list)
    truncated: bool = False


class InvalidPattern(Exception):
    def __init__(self, pattern: str, message: str) -> None:
        super().__init__(message)
        self.pattern = pattern
        self.message = message


@dataclass
class _Process:
    handle: "subprocess.Popen[bytes]"
    stderr: bytearray

    def wait(self, timeout: float) -> int:
        try:
            return self.handle.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            raise ToolError("rg_timeout", "ripgrep exceeded the time limit") from None

    def kill(self) -> None:
        if self.handle.poll() is None:
            self.handle.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.handle.wait(timeout=KILL_TIMEOUT)

    @property
    def stderr_text(self) -> str:
        return bytes(self.stderr[:ERROR_BYTES]).decode("utf-8", "replace")


def _spawn(binary: str, args: list[str], cwd: str) -> _Process:
    try:
        handle = subprocess.Popen(
            [binary, *args],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        # missing rg, missing cwd, permission denied: same surface as a
        # non-zero exit, never a bare OSError out of the tool
        raise ToolError("rg_failed", f"ripgrep could not start: {exc}") from exc
    stderr = bytearray()

    def drain() -> None:
        assert handle.stderr is not None
        while True:
            # keep reading past the cap: rg blocks on a full stderr pipe, and
            # a blocked rg never closes stdout
            room = ERROR_BYTES - len(stderr)
            chunk = handle.stderr.read(4096 if room <= 0 else min(4096, room))
            if not chunk:
                return
            if room > 0:
                stderr.extend(chunk)

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    return _Process(handle=handle, stderr=stderr)


def _strip_prefix(line: str) -> str:
    r"""V2's three-step normalization: drop ./ runs, drop leading slashes, \ -> /."""
    line = re.sub(r"^(?:\.[\\/])+", "", line)
    line = re.sub(r"^[\\/]+", "", line)
    return line.replace("\\", "/")


def _deny_globs(deny: list[str]) -> list[str]:
    return [f"--glob=!{pattern}" for pattern in deny]


@dataclass
class _Deadline:
    """Absolute monotonic deadline shared by the read loop and the exit wait."""

    end: float

    @classmethod
    def from_timeout(cls, timeout: float) -> _Deadline:
        return cls(end=time.monotonic() + timeout)

    def remaining(self) -> float:
        return max(0.0, self.end - time.monotonic())


def _run_bounded(
    process: _Process, deadline: _Deadline, consume: Callable[[], None]
) -> None:
    """Run ``consume`` on a worker thread, bounded by ``deadline``.

    Iterating stdout has no deadline of its own, and handlers run off the
    server's thread pool, so an unbounded read would park one worker per
    stuck rg until the pool is exhausted.
    """
    failure: dict[str, BaseException] = {}

    def worker() -> None:
        try:
            consume()
        except BaseException as exc:  # noqa: BLE001 - replayed on the caller
            failure["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(deadline.remaining())
    if thread.is_alive():
        process.kill()
        raise ToolError("rg_timeout", "ripgrep exceeded the time limit")

    error = failure.get("error")
    if error is not None:
        process.kill()
        raise error


def _check_exit(process: _Process, deadline: _Deadline, pattern: str) -> int:
    remaining = deadline.remaining()
    if remaining == 0.0:
        process.kill()
        raise ToolError("rg_timeout", "ripgrep exceeded the time limit")
    code = process.wait(remaining)
    stderr = process.stderr_text
    if code == 2 and _INVALID_PATTERN.search(stderr):
        raise InvalidPattern(pattern, stderr.strip())
    if code not in (0, 1, 2):
        raise ToolError(
            "rg_failed", stderr.strip() or f"ripgrep failed with code {code}"
        )
    return code


def _collect(
    process: _Process,
    limit: int,
    timeout: float,
    pattern: str,
    parse: Callable[[bytes], object | None],
) -> RunResult:
    deadline = _Deadline.from_timeout(timeout)
    items: list = []
    truncated = False

    def consume() -> None:
        nonlocal truncated
        assert process.handle.stdout is not None
        try:
            for raw in process.handle.stdout:
                if len(items) >= limit:
                    truncated = True
                    break
                item = parse(raw)
                if item is not None:
                    items.append(item)
        finally:
            process.handle.stdout.close()

    _run_bounded(process, deadline, consume)

    if truncated:
        try:
            # we stopped reading on purpose; take the exit code without its rows
            _check_exit(process, deadline, pattern)
        except ToolError as exc:
            # a closed pipe can end rg with a signal (-13 SIGPIPE on POSIX)
            # rather than 0/1/2; that says nothing about the rows we already
            # collected
            if exc.code != "rg_failed":
                raise
        return RunResult(items=items, truncated=True)

    code = _check_exit(process, deadline, pattern)
    if code == 1:
        items = []
    return RunResult(items=items, truncated=False)


# --- glob -------------------------------------------------------------------

def run_glob(
    binary: str,
    *,
    cwd: str,
    pattern: str,
    limit: int,
    deny: list[str],
    timeout: float,
) -> RunResult:
    if limit <= 0:
        return RunResult()
    args = [
        "--no-config",
        "--files",
        f"--glob={pattern}",
        *_deny_globs(deny),
        "--glob=!**/.git/**",
        ".",
    ]
    return _collect(_spawn(binary, args, cwd), limit, timeout, pattern, _parse_line)


def _parse_line(raw: bytes) -> str | None:
    line = raw.decode("utf-8", "replace").rstrip("\r\n")
    return _strip_prefix(line) if line else None


# --- grep -------------------------------------------------------------------

@dataclass
class RawMatch:
    path: str
    line: int
    offset: int
    text: str
    submatches: list[dict]


def run_grep(
    binary: str,
    *,
    cwd: str,
    pattern: str,
    file: str | None,
    include: str | None,
    limit: int,
    deny: list[str],
    timeout: float,
) -> RunResult:
    if limit <= 0:
        return RunResult()
    args = [
        "--no-config",
        "--json",
        "--hidden",
        "--no-messages",
    ]
    if include:
        args.append(f"--glob={include}")
    args += _deny_globs(deny)
    args += [
        "--glob=!**/.git/**",
        "--",
        pattern,
        file if file is not None else ".",
    ]
    return _collect(_spawn(binary, args, cwd), limit, timeout, pattern, _parse_record)


def _parse_record(raw: bytes) -> RawMatch | None:
    if len(raw) > MAX_RECORD_BYTES:
        raise ToolError(
            "rg_failed",
            f"Ripgrep JSON record exceeded {MAX_RECORD_BYTES} bytes",
        )
    return _parse_match(raw.decode("utf-8", "replace"))


def validate_deny_globs(binary: str, patterns: list[str]) -> str | None:
    """Return rg's complaint about the first malformed deny glob, else None.

    A glob rg cannot parse makes it exit 2 without reading anything, which
    empties every search silently. The probe runs in an empty directory: rg
    parses the globs before it walks, so startup pays nothing for it.
    """
    if not patterns:
        return None
    with tempfile.TemporaryDirectory() as empty:
        process = _spawn(
            binary, ["--no-config", "--files", *_deny_globs(patterns), "."], empty
        )
        if _check_exit(process, _Deadline.from_timeout(PROBE_TIMEOUT), "") == 2:
            return process.stderr_text.strip() or "rejected by ripgrep"
    return None


def _parse_match(line: str) -> RawMatch | None:
    """Parse one --json record; non-match rows are dropped."""
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ToolError("rg_failed", "Invalid ripgrep JSON output") from exc
    if not isinstance(data, dict) or data.get("type") != "match":
        return None
    payload = data.get("data")
    if not isinstance(payload, dict):
        return None
    path = (payload.get("path") or {}).get("text", "")
    text = (payload.get("lines") or {}).get("text", "")
    line_number = payload.get("line_number")
    offset = payload.get("absolute_offset")
    if not isinstance(line_number, int) or not isinstance(offset, int):
        raise ToolError("rg_failed", "Invalid ripgrep match output")

    # V2 bounds a preview line at 2000 chars and drops a torn surrogate pair
    # (a slice can split a astral character; avoid re for the lone-surrogate check)
    if len(text) > MAX_LINE_CHARS:
        text = text[:MAX_LINE_CHARS]
        if text and 0xD800 <= ord(text[-1]) <= 0xDBFF:
            text = text[:-1]
        text += "..."

    submatches = []
    for item in (payload.get("submatches") or [])[:MAX_SUBMATCHES]:
        if not isinstance(item, dict):
            continue
        inner = item.get("match") or {}
        submatches.append(
            {
                "text": inner.get("text", ""),
                "start": item.get("start", 0),
                "end": item.get("end", 0),
            }
        )
    return RawMatch(
        path=_strip_prefix(path),
        line=line_number,
        offset=offset,
        text=text,
        submatches=submatches,
    )


__all__ = [
    "find_binary", "run_glob", "run_grep", "validate_deny_globs", "InvalidPattern",
    "RawMatch", "RunResult", "MAX_RECORD_BYTES", "MAX_SUBMATCHES",
    "MAX_LINE_CHARS", "ERROR_BYTES",
]
