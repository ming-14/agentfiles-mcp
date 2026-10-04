"""ripgrep execution adapter (mirrors packages/core/src/ripgrep.ts).

Spawns the rg binary, streams stdout line by line, and maps exit codes the
same way V2 does:
    1                -> no matches
    2 + regex error  -> InvalidPattern (grep only)
    2                -> partial results
    anything else    -> failure with the captured stderr (8KB cap)

Deny patterns from AF_READ_DENY are translated into ``--glob=!pattern``
exclusions so a file that cannot be read also cannot be surfaced by search.

stderr is drained by a background thread from spawn time: a chatty rg would
otherwise fill the pipe while we are still reading stdout and deadlock.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field

from agentfiles_shared.errors import ToolError

MAX_RECORD_BYTES = 64 * 1024
MAX_SUBMATCHES = 100
MAX_LINE_CHARS = 2_000
ERROR_BYTES = 8 * 1024

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
            self.handle.kill()
            self.handle.wait()
            raise ToolError("rg_timeout", "ripgrep exceeded the time limit") from None

    def kill(self) -> None:
        if self.handle.poll() is None:
            self.handle.kill()
        self.handle.wait()

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
        # read until EOF but keep only the first ERROR_BYTES
        while len(stderr) < ERROR_BYTES:
            chunk = handle.stderr.read(min(4096, ERROR_BYTES - len(stderr) + 1))
            if not chunk:
                return
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


def _check_exit(process: _Process, timeout: float, pattern: str) -> int:
    code = process.wait(timeout)
    stderr = process.stderr_text
    if code == 2 and _INVALID_PATTERN.search(stderr):
        raise InvalidPattern(pattern, stderr.strip())
    if code not in (0, 1, 2):
        raise ToolError(
            "rg_failed", stderr.strip() or f"ripgrep failed with code {code}"
        )
    return code


# --- glob -------------------------------------------------------------------

def run_glob(
    binary: str,
    *,
    cwd: str,
    pattern: str,
    limit: int,
    deny: list[str],
    timeout: float,
    hidden: bool = False,
) -> RunResult:
    if limit <= 0:
        return RunResult()
    args = ["--no-config", "--files"]
    if hidden:
        args.append("--hidden")
    args += [
        f"--glob={pattern}",
        *_deny_globs(deny),
        "--glob=!**/.git/**",
        ".",
    ]
    return _collect_lines(_spawn(binary, args, cwd), limit, timeout, pattern)


def _collect_lines(
    process: _Process, limit: int, timeout: float, pattern: str
) -> RunResult:
    items: list[str] = []
    truncated = False
    assert process.handle.stdout is not None
    try:
        for raw in process.handle.stdout:
            if len(items) >= limit:
                truncated = True
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line:
                items.append(_strip_prefix(line))
    finally:
        process.handle.stdout.close()

    if truncated:
        # we stopped reading on purpose; take the exit code without its rows
        _check_exit(process, timeout, pattern)
        return RunResult(items=items, truncated=True)

    code = _check_exit(process, timeout, pattern)
    if code == 1:
        items = []
    return RunResult(items=items, truncated=False)


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
    return _collect_matches(_spawn(binary, args, cwd), limit, timeout, pattern)


def _collect_matches(
    process: _Process, limit: int, timeout: float, pattern: str
) -> RunResult:
    matches: list[RawMatch] = []
    truncated = False
    assert process.handle.stdout is not None
    try:
        for raw in process.handle.stdout:
            if len(matches) >= limit:
                truncated = True
                break
            if len(raw) > MAX_RECORD_BYTES:
                raise ToolError(
                    "rg_failed",
                    f"Ripgrep JSON record exceeded {MAX_RECORD_BYTES} bytes",
                )
            match = _parse_match(raw.decode("utf-8", "replace"))
            if match is not None:
                matches.append(match)
    finally:
        process.handle.stdout.close()

    if truncated:
        _check_exit(process, timeout, pattern)
        return RunResult(items=matches, truncated=True)

    code = _check_exit(process, timeout, pattern)
    if code == 1:
        matches = []
    return RunResult(items=matches, truncated=False)


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
    "find_binary", "run_glob", "run_grep", "InvalidPattern", "RawMatch",
    "RunResult", "MAX_RECORD_BYTES", "MAX_SUBMATCHES", "MAX_LINE_CHARS",
    "ERROR_BYTES",
]
