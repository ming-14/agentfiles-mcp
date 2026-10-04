"""grep tool: grouped rendering, include, single file, deny exclusions."""

from __future__ import annotations

import json
import os
import shutil

import pytest
from fastapi.testclient import TestClient

from agentfiles_server.app import create_app
from agentfiles_server.config import Config
from agentfiles_server.fslayer import slash

pytestmark = pytest.mark.skipif(
    not shutil.which("rg"), reason="ripgrep (rg) not on PATH"
)

TOKEN = "tok-gr"
SECRET = "sec-gr"


def signed_post(client: TestClient, path: str, payload: dict):
    from agentfiles_shared.auth import build_headers

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = build_headers(
        token=TOKEN, secret=SECRET, method="POST", path=path, body=body
    ).as_dict()
    headers["Content-Type"] = "application/json"
    return client.post(path, content=body, headers=headers)


@pytest.fixture()
def workspace(tmp_path):
    ws = tmp_path / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "a.ts").write_text("const needle = 1;\nmore\n", encoding="utf-8")
    (ws / "src" / "b.js").write_text("let needle = 2;\n", encoding="utf-8")
    (ws / "notes.md").write_text("needle here\n", encoding="utf-8")
    (ws / "app.env.local").write_text("needle secret\n", encoding="utf-8")
    return ws


def make_client(workspace, **overrides) -> TestClient:
    config = Config(
        workspace=str(workspace), tokens={TOKEN: SECRET},
        read_deny=overrides.get("read_deny", ["*.env", "*.env.*"]),
        ripgrep_path=overrides.get("ripgrep_path"),
        rg_timeout=overrides.get("rg_timeout", 15.0),
    )
    client = TestClient(create_app(config))
    client.af_workspace = str(workspace)
    return client


def grep(client, **payload):
    payload.setdefault("cwd", getattr(client, "af_workspace", None))
    return signed_post(client, "/v1/grep", payload).json()


def test_grouped_model_text(workspace):
    with make_client(workspace) as client:
        data = grep(client, pattern="needle", path="src")
    assert data["ok"] is True
    text = data["modelText"]
    lines = text.splitlines()
    assert lines[0] == "Found 2 matches"
    # one header per file, blank line between groups, indented line entries
    assert any(line.endswith("src/a.ts:") or line.endswith("src\\a.ts:") for line in lines)
    assert "  Line 1: const needle = 1;" in lines
    assert "  Line 1: let needle = 2;" in lines
    # groups are separated by a blank line (rg walk order is not sorted,
    # so locate each header rather than assuming positions)
    a_at = next(i for i, line in enumerate(lines) if line.endswith("a.ts:"))
    b_at = next(i for i, line in enumerate(lines) if line.endswith("b.js:"))
    assert lines[a_at + 1].startswith("  Line ")
    assert lines[b_at + 1].startswith("  Line ")
    between = lines[min(a_at, b_at):max(a_at, b_at)]
    assert "" in between  # separator between file groups


def test_narrow_search_renders_the_real_path(workspace):
    """Searching a subdirectory must not render the workspace-relative name
    joined onto the search root (/ws/src + src/a.ts -> /ws/src/src/a.ts)."""
    with make_client(workspace) as client:
        data = grep(client, pattern="needle", path="src")
    assert data["ok"] is True
    header = next(
        line for line in data["modelText"].splitlines() if line.endswith("a.ts:")
    )
    expected = slash(os.path.realpath(workspace / "src" / "a.ts"))
    assert header == f"{expected}:"


def test_hit_outside_containment_is_dropped(workspace, tmp_path, fake_rg):
    """A hit that resolves outside the workspace is dropped, not rendered:
    search must not map what a read of the same path would refuse."""
    record = json.dumps({
        "type": "match",
        "data": {
            "path": {"text": "../outside/secret.txt"},
            "lines": {"text": "needle\n"},
            "line_number": 1,
            "absolute_offset": 0,
            "submatches": [],
        },
    }).encode("utf-8") + b"\n"
    fake = fake_rg(tmp_path, record)
    with make_client(workspace, ripgrep_path=fake) as client:
        data = grep(client, pattern="needle")
    assert data["ok"] is True
    assert data["result"]["matches"] == []
    assert data["modelText"] == "No files found"


def test_no_match_renders_no_files_found(workspace):
    with make_client(workspace) as client:
        data = grep(client, pattern="zzz-not-here")
    assert data["ok"] is True
    assert data["result"]["matches"] == []
    assert data["modelText"] == "No files found"


def test_matches_are_workspace_relative(workspace):
    with make_client(workspace) as client:
        data = grep(client, pattern="needle")
    paths = [m["entry"]["path"] for m in data["result"]["matches"]]
    assert "src/a.ts" in paths
    assert all("\\" not in p for p in paths)
    # model text renders absolute paths
    assert not data["modelText"].splitlines()[1].startswith("src/")


def test_include_filter(workspace):
    with make_client(workspace) as client:
        data = grep(client, pattern="needle", include="*.ts")
    paths = {m["entry"]["path"] for m in data["result"]["matches"]}
    assert paths == {"src/a.ts"}


def test_single_file_target(workspace):
    with make_client(workspace) as client:
        data = grep(client, pattern="needle", path="src/a.ts")
    paths = {m["entry"]["path"] for m in data["result"]["matches"]}
    assert paths == {"src/a.ts"}
    match = data["result"]["matches"][0]
    assert match["line"] == 1
    assert match["submatches"][0]["text"] == "needle"


def test_deny_hides_denied_file_content(workspace):
    """app.env.local is not hidden: grep would leak it without AF_READ_DENY."""
    with make_client(workspace) as client:
        data = grep(client, pattern="needle")
    paths = {m["entry"]["path"] for m in data["result"]["matches"]}
    assert not any(p.endswith("app.env.local") for p in paths)
    # and directly asking for it is equally fruitless
    direct = grep(client, pattern="secret", path="app.env.local")
    # the file is denied for reading; searching it must not leak either
    assert direct["result"]["matches"] == [] or direct["ok"] is False


def test_deny_configurable(workspace):
    with make_client(workspace, read_deny=[]) as client:
        data = grep(client, pattern="needle")
    paths = {m["entry"]["path"] for m in data["result"]["matches"]}
    assert any(p.endswith("app.env.local") for p in paths)


def test_invalid_regex_generic_error(workspace):
    with make_client(workspace) as client:
        data = grep(client, pattern="[unclosed")
    assert data["ok"] is False
    assert data["error"]["message"] == "Unable to grep for [unclosed"


def test_limit_truncates(workspace):
    with make_client(workspace) as client:
        data = grep(client, pattern="needle", limit=1)
    assert len(data["result"]["matches"]) == 1
    assert data["result"]["truncated"] is True
    # V2 renders exactly the matches it has (no "more" hint)
    assert data["modelText"].startswith("Found 1 matches")


def test_path_escape_rejected(workspace, tmp_path):
    (tmp_path / "out.txt").write_text("needle\n", encoding="utf-8")
    with make_client(workspace) as client:
        data = grep(client, pattern="needle", path="../out.txt")
    # V2 semantics: every grep failure collapses into the generic message
    assert data["error"]["code"] == "unable_to_grep"
    assert data["error"]["message"] == "Unable to grep for needle"


def test_search_narrows_with_path(workspace):
    with make_client(workspace) as client:
        data = grep(client, pattern="needle", path="src")
    paths = {m["entry"]["path"] for m in data["result"]["matches"]}
    assert "notes.md" not in paths
