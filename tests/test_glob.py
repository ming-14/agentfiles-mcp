"""glob tool: containment, rendering, deny exclusions."""

from __future__ import annotations

import json
import shutil

import pytest
from fastapi.testclient import TestClient

from agentfiles_server.app import create_app
from agentfiles_server.config import Config

pytestmark = pytest.mark.skipif(
    not shutil.which("rg"), reason="ripgrep (rg) not on PATH"
)

TOKEN = "tok-g"
SECRET = "sec-g"


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
    (ws / "src" / "a.ts").write_text("x\n", encoding="utf-8")
    (ws / "src" / "b.js").write_text("y\n", encoding="utf-8")
    (ws / "notes.md").write_text("z\n", encoding="utf-8")
    (ws / "cert.pem").write_text("p\n", encoding="utf-8")
    (ws / ".secret.env").write_text("K=1\n", encoding="utf-8")
    # not hidden: only the deny list can keep this one out of glob results
    (ws / "app.env.local").write_text("K=2\n", encoding="utf-8")
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


def glob(client, **payload):
    payload.setdefault("cwd", getattr(client, "af_workspace", None))
    return signed_post(client, "/v1/glob", payload).json()


def test_pattern_matching(workspace):
    with make_client(workspace) as client:
        data = glob(client, pattern="src/**/*.ts")
    assert data["ok"] is True
    assert [e["path"] for e in data["result"]["entries"]] == ["src/a.ts"]
    # model text uses absolute paths (V2 resolves before rendering)
    assert data["modelText"].endswith("/src/a.ts") or data["modelText"].endswith("\\src/a.ts")
    assert "\\" not in data["modelText"]


def test_no_files_found(workspace):
    with make_client(workspace) as client:
        data = glob(client, pattern="**/*.rs")
    assert data["ok"] is True
    assert data["result"]["entries"] == []
    assert data["modelText"] == "No files found"


def test_multiple_paths_each_on_a_line(workspace):
    with make_client(workspace) as client:
        data = glob(client, pattern="**/*.ts")
        multi = glob(client, pattern="**/*")
    assert len(data["modelText"].splitlines()) == len(data["result"]["entries"])
    assert len(multi["modelText"].splitlines()) == len(multi["result"]["entries"])


def test_limit_truncates(workspace):
    with make_client(workspace) as client:
        data = glob(client, pattern="**/*", limit=2)
    assert len(data["result"]["entries"]) == 2
    assert data["result"]["truncated"] is True


def test_git_excluded_but_dotfiles_visible(workspace):
    (workspace / ".git").mkdir()
    (workspace / ".git" / "config").write_text("x", encoding="utf-8")
    (workspace / ".npmrc").write_text("token=1", encoding="utf-8")
    with make_client(workspace) as client:
        data = glob(client, pattern="**/*")
    paths = [e["path"] for e in data["result"]["entries"]]
    # only --glob=!**/.git/** and AF_READ_DENY remove entries: the positive
    # --glob overrides rg's hidden filter, so dotfiles are listed
    assert not any(p.startswith(".git") for p in paths)
    assert not any(p.endswith(".env") for p in paths)
    # the default deny is *.env only, so this one is visible to the model
    assert any(p.endswith(".npmrc") for p in paths)


def test_deny_patterns_excluded(workspace):
    with make_client(workspace) as client:
        data = glob(client, pattern="**/*")
    paths = [e["path"] for e in data["result"]["entries"]]
    # app.env.local is not hidden: only AF_READ_DENY keeps it invisible
    assert not any(p.endswith("app.env.local") for p in paths)


def test_deny_configurable(workspace):
    with make_client(workspace, read_deny=["*.pem"]) as client:
        data = glob(client, pattern="**/*")
    paths = [e["path"] for e in data["result"]["entries"]]
    assert not any(p.endswith(".pem") for p in paths)
    # the *.env deny was replaced, so it shows up now
    assert any(p.endswith("app.env.local") for p in paths)


def test_relative_escape_rejected(workspace, tmp_path):
    (tmp_path / "outside.txt").write_text("x", encoding="utf-8")
    with make_client(workspace) as client:
        data = glob(client, pattern="*", path="../")
    assert data["ok"] is False
    # V2 semantics: every glob failure collapses into the generic message
    assert data["error"]["code"] == "unable_to_find"
    assert data["error"]["message"] == "Unable to find files matching *"


def test_path_must_be_directory(workspace):
    with make_client(workspace) as client:
        data = glob(client, pattern="*", path="notes.md")
    assert data["ok"] is False
    assert data["error"]["message"] == "Unable to find files matching *"


def test_search_narrows_with_path(workspace):
    with make_client(workspace) as client:
        data = glob(client, pattern="**/*", path="src")
    paths = {e["path"] for e in data["result"]["entries"]}
    # rg emits in walk order, not sorted: compare as a set
    assert paths == {"src/a.ts", "src/b.js"}


def test_whitelisted_external_search(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    shared = tmp_path / "shared"
    (shared / "docs").mkdir(parents=True)
    (shared / "docs" / "guide.md").write_text("x", encoding="utf-8")
    config = Config(
        workspace=str(ws), tokens={TOKEN: SECRET},
        external_whitelist=[str(shared)],
    )
    with TestClient(create_app(config)) as client:
        data = signed_post(
            client, "/v1/glob",
            {"pattern": "**/*.md", "path": str(shared)},
        ).json()
    assert data["ok"] is True
    entries = [e["path"] for e in data["result"]["entries"]]
    # external results are reported absolute (workspace-relative would escape)
    assert any(e.replace("\\", "/").endswith("docs/guide.md") for e in entries)


def test_hit_outside_containment_is_dropped(workspace, tmp_path, fake_rg):
    """A name rg reports that resolves outside the workspace is dropped rather
    than rendered under its absolute path -- search must not map the outside."""
    fake = fake_rg(tmp_path, b"../outside/leak.txt\n")
    with make_client(workspace, ripgrep_path=fake) as client:
        data = glob(client, pattern="**/*")
    assert data["ok"] is True
    assert data["result"]["entries"] == []
    assert data["modelText"] == "No files found"
