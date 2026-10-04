"""read tool behavior, aligned with V2 (packages/core/test/tool-read.test.ts)."""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from agentfiles_server.app import create_app
from agentfiles_server.config import Config

TOKEN = "tok-read"
SECRET = "sec-read"


def signed_post(client: TestClient, path: str, payload: dict) -> object:
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
    ws.mkdir()
    (ws / "src").mkdir()
    return ws


@pytest.fixture()
def client(workspace):
    config = Config(workspace=str(workspace), tokens={TOKEN: SECRET})
    with TestClient(create_app(config)) as test_client:
        # helpers attach this as the request cwd (set cwd=None explicitly to
        # exercise the cwd_not_set rejection)
        test_client.af_workspace = str(workspace)
        yield test_client


def read(client, path, **kwargs):
    payload = {"path": path}
    payload.update(kwargs)
    payload.setdefault("cwd", getattr(client, "af_workspace", None))
    return signed_post(client, "/v1/read", payload)


def make_text_file(workspace, name: str, text: str) -> str:
    target = workspace / name
    # newline="" keeps \n as-is on Windows (Path.write_text translates by default)
    target.write_bytes(text.encode("utf-8"))
    return name


# --- text files ------------------------------------------------------------

def test_small_text_file(client, workspace):
    make_text_file(workspace, "hello.txt", "hello\nworld\n")
    resp = read(client, "hello.txt")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    result = data["result"]
    assert result["encoding"] == "utf8"
    assert result["content"] == "hello\nworld\n"
    assert result["name"] == "hello.txt"
    assert result["uri"].startswith("file://")
    # V2 gives the model the structured JSON (toModelOutput returns [])
    assert json.loads(data["modelText"]) == result


def test_empty_file(client, workspace):
    make_text_file(workspace, "empty.txt", "")
    data = read(client, "empty.txt").json()
    assert data["ok"] is True
    assert data["result"]["content"] == ""


def test_missing_file_maps_to_generic_error(client):
    data = read(client, "nope.txt").json()
    assert data["ok"] is False
    assert data["error"]["message"] == "Unable to read nope.txt"


def test_invalid_utf8_maps_to_generic_error(client, workspace):
    (workspace / "bad.txt").write_bytes(b"ok\xff\xfe\xff")
    data = read(client, "bad.txt").json()
    assert data["error"]["message"] == "Unable to read bad.txt"


def test_binary_extension(client, workspace):
    (workspace / "archive.dat").write_bytes(b"stuff")
    data = read(client, "archive.dat").json()
    assert data["error"]["message"] == "Cannot read binary file: archive.dat"


def test_pdf_magic(client, workspace):
    (workspace / "doc.pdf").write_bytes(b"%PDF-1.4 rest")
    data = read(client, "doc.pdf").json()
    assert data["error"]["message"] == "Cannot read binary file: doc.pdf"


def test_nul_byte_is_binary(client, workspace):
    (workspace / "notes.txt").write_bytes(b"abc\x00def")
    data = read(client, "notes.txt").json()
    assert data["error"]["message"] == "Cannot read binary file: notes.txt"


# --- paging ----------------------------------------------------------------

def test_paged_text(client, workspace):
    lines = "\n".join(f"line {i}" for i in range(1, 201))
    make_text_file(workspace, "big.txt", lines + "\n")
    # 200 lines is under 50KB, but explicit offset forces paging
    data = read(client, "big.txt", offset=2, limit=3).json()
    assert data["ok"] is True
    result = data["result"]
    assert result["type"] == "text-page"
    assert result["content"] == "line 2\nline 3\nline 4"
    assert result["offset"] == 2
    assert result["truncated"] is True
    assert result["next"] == 5


def test_paged_read_keeps_control_char_lines(client, workspace):
    """Line segments are checked for binary content one at a time; a short
    segment of control characters must not fail the whole paged read."""
    make_text_file(workspace, "log.txt", "line one\n\x07\x07\x07ok\nline three\n")
    assert read(client, "log.txt").json()["ok"] is True
    data = read(client, "log.txt", offset=1, limit=10).json()
    assert data["ok"] is True, data
    assert data["result"]["content"] == "line one\n\x07\x07\x07ok\nline three"


def test_large_file_is_paged_without_offset(client, workspace):
    lines = "\n".join("x" * 99 for _ in range(1000))  # ~100KB
    make_text_file(workspace, "huge.txt", lines + "\n")
    data = read(client, "huge.txt").json()
    assert data["result"]["type"] == "text-page"
    assert data["result"]["truncated"] is True
    assert len(data["result"]["content"].encode()) <= 50 * 1024


def test_offset_out_of_range(client, workspace):
    make_text_file(workspace, "tiny.txt", "one\ntwo\n")
    data = read(client, "tiny.txt", offset=99).json()
    assert data["error"]["message"] == "Unable to read tiny.txt"


def test_long_line_is_truncated(client, workspace):
    make_text_file(workspace, "long.txt", "y" * 5000 + "\nnext\n")
    data = read(client, "long.txt", limit=1).json()
    content = data["result"]["content"]
    assert "... (line truncated to 2000 chars)" in content
    assert len(content) <= 2000 + len("... (line truncated to 2000 chars)")


def test_crlf_stripped_in_paged_mode(client, workspace):
    (workspace / "win.txt").write_bytes(b"a\r\nb\r\n")
    data = read(client, "win.txt", limit=1).json()
    assert data["result"]["content"] == "a"


def test_limit_over_2000_rejected(client, workspace):
    make_text_file(workspace, "a.txt", "x\n")
    data = read(client, "a.txt", limit=2001).json()
    assert data["ok"] is False
    assert data["error"]["code"] == "invalid_input"


def test_offset_zero_rejected(client, workspace):
    make_text_file(workspace, "a.txt", "x\n")
    data = read(client, "a.txt", offset=0).json()
    assert data["error"]["code"] == "invalid_input"


# --- directories -----------------------------------------------------------

def test_directory_listing_sorted_dirs_first(client, workspace):
    (workspace / "zdir").mkdir()
    (workspace / "adir").mkdir()
    make_text_file(workspace, "bfile.txt", "1")
    data = read(client, ".").json()
    # every read result is tagged so clients can discriminate by `type`
    assert data["result"]["type"] == "list-page"
    entries = data["result"]["entries"]
    # the workspace fixture also creates src/
    assert [e["type"] for e in entries[:3]] == ["directory", "directory", "directory"]
    assert entries[-1] == {"path": "bfile.txt", "type": "file"}
    assert sorted(e["path"] for e in entries if e["type"] == "directory") == [
        "adir" + os.sep, "src" + os.sep, "zdir" + os.sep
    ]
    # directories carry the OS separator suffix (V2 uses path.sep)
    assert entries[0]["path"].endswith(os.sep)


def test_directory_pagination(client, workspace):
    for i in range(5):
        make_text_file(workspace, f"f{i}.txt", "x")
    data = read(client, ".", offset=2, limit=2).json()
    result = data["result"]
    assert len(result["entries"]) == 2
    assert result["truncated"] is True
    assert result["next"] == 4


def test_directory_offset_beyond_end_is_empty_not_error(client, workspace):
    make_text_file(workspace, "only.txt", "x")
    data = read(client, ".", offset=50).json()
    assert data["ok"] is True
    assert data["result"]["entries"] == []


def test_symlink_escape_filtered_from_listing(client, workspace, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    link = workspace / "leak"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    data = read(client, ".").json()
    names = [e["path"] for e in data["result"]["entries"]]
    assert not any("leak" in n for n in names)


# --- policy: deny list & external whitelist --------------------------------

def test_env_file_denied(client, workspace):
    make_text_file(workspace, ".env", "SECRET=1")
    data = read(client, ".env").json()
    # deny must not reveal whether the file exists or matched
    assert data["error"]["message"] == "Unable to read .env"


def test_env_denied_even_nested(client, workspace):
    make_text_file(workspace, "app.env.local", "SECRET=1")
    data = read(client, "app.env.local").json()
    assert data["error"]["message"] == "Unable to read app.env.local"


def test_external_path_rejected_by_default(client, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("hi")
    data = read(client, str(outside)).json()
    assert data["ok"] is False
    # unified surface: a path outside containment reads exactly like a missing
    # one (the reason is logged server-side only)
    assert data["error"]["code"] == "unable_to_read"
    assert data["error"]["message"] == f"Unable to read {outside}"


def test_relative_escape_rejected(client, workspace, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("hi")
    data = read(client, "../outside.txt").json()
    assert data["error"]["code"] == "unable_to_read"
    assert data["error"]["message"] == "Unable to read ../outside.txt"


def test_file_as_directory_reports_input_not_server_path(client, workspace):
    """Errors echo what the caller sent; the workspace path stays server-side."""
    make_text_file(workspace, "sub.txt", "x")
    data = read(client, "sub.txt/inner").json()
    assert data["ok"] is False
    # sub.txt is a file: the kernel refuses to traverse it -> generic message
    assert data["error"]["message"] == "Unable to read sub.txt/inner"
    assert str(workspace) not in data["error"]["message"]


def test_whitelisted_external_path_allowed(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "doc.md").write_text("# doc")
    config = Config(
        workspace=str(ws),
        tokens={TOKEN: SECRET},
        external_whitelist=[str(shared)],
    )
    with TestClient(create_app(config)) as client:
        data = read(client, str(shared / "doc.md")).json()
    assert data["ok"] is True
    assert data["result"]["content"] == "# doc"


def test_cross_drive_path_is_path_escape_not_internal(client, workspace):
    """os.path.relpath raises across drives on Windows; the tool must report
    a generic read failure instead of leaking an `internal` error."""
    if os.name != "nt":
        pytest.skip("cross-drive paths only exist on Windows")
    home_drive = os.path.splitdrive(str(workspace))[0].upper()
    other = "D:" if home_drive != "D:" else "E:"
    data = read(client, f"{other}/data/x.txt").json()
    assert data["ok"] is False
    assert data["error"]["code"] == "unable_to_read"


def test_cross_drive_link_filtered_from_listing(client, workspace, monkeypatch):
    """A symlink resolving to another drive must be skipped by the listing,
    not blow up list_dir (contains() used to raise ValueError)."""
    if os.name != "nt":
        pytest.skip("cross-drive paths only exist on Windows")
    (workspace / "leak").mkdir()
    home_drive = os.path.splitdrive(str(workspace))[0].upper()
    other_drive = "D:" if home_drive != "D:" else "E:"
    genuine = os.path.realpath

    def realpath(path):
        if str(path).endswith("leak"):
            return other_drive + r"\leak-target"
        return genuine(path)

    monkeypatch.setattr("agentfiles_server.readfs.os.path.realpath", realpath)
    data = read(client, ".").json()
    assert data["ok"] is True, data
    assert not any("leak" in entry["path"] for entry in data["result"]["entries"])


# --- images: transport, never base64 ---------------------------------------

def tiny_png() -> bytes:
    # 1x1 transparent PNG
    import base64

    return base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4"
        "2mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    )


def signed_get(client: TestClient, path: str, query: str) -> object:
    from urllib.parse import quote

    from agentfiles_shared.auth import build_headers

    headers = build_headers(
        token=TOKEN, secret=SECRET, method="GET", path=path, body=b"", query=query
    ).as_dict()
    return client.get(f"{path}?{query}", headers=headers)


def test_image_returns_descriptor_not_base64(client, workspace):
    (workspace / "pixel.png").write_bytes(tiny_png())
    data = read(client, "pixel.png").json()
    assert data["ok"] is True
    result = data["result"]
    assert result["type"] == "download"
    assert result["mime"] == "image/png"
    assert result["name"] == "pixel.png"
    assert "content" not in result
    # no file bytes anywhere in the tool response
    assert "base64" not in json.dumps(data)
    assert data["modelText"] == "Image read successfully"


def test_transport_download_round_trip(client, workspace):
    png = tiny_png()
    (workspace / "pixel.png").write_bytes(png)
    read(client, "pixel.png")
    server_path = os.path.realpath(workspace / "pixel.png")
    from urllib.parse import quote

    resp = signed_get(
        client, "/v1/transport/download", f"path={quote(server_path, safe='')}"
    )
    assert resp.status_code == 200
    assert resp.content == png


def test_download_without_signature_rejected(client, workspace):
    (workspace / "pixel.png").write_bytes(tiny_png())
    resp = client.get("/v1/transport/download?path=x")
    assert resp.status_code == 401


def test_download_query_tamper_rejected(client, workspace):
    (workspace / "pixel.png").write_bytes(tiny_png())
    from urllib.parse import quote

    real = os.path.realpath(workspace / "pixel.png")
    other = os.path.realpath(workspace / "hello.txt")
    make_text_file(workspace, "hello.txt", "hi")

    from agentfiles_shared.auth import build_headers

    # sign for `real`, send `other` -> signature must fail
    headers = build_headers(
        token=TOKEN,
        secret=SECRET,
        method="GET",
        path="/v1/transport/download",
        body=b"",
        query=f"path={quote(real, safe='')}",
    ).as_dict()
    resp = client.get(
        f"/v1/transport/download?path={quote(other, safe='')}", headers=headers
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "bad_signature"


def test_download_outside_workspace_rejected(client, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("hi")
    from urllib.parse import quote

    resp = signed_get(
        client, "/v1/transport/download", f"path={quote(str(outside), safe='')}"
    )
    # same envelope as a missing file: the channel cannot be used to map
    # what exists outside the workspace (reason logged server-side only)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "transport_unavailable"


def test_download_read_deny_enforced(client, workspace):
    """The transport endpoint must honour AF_READ_DENY: the signature only
    proves who is asking, so a denied file can't be fetched around `read`."""
    make_text_file(workspace, ".env", "SECRET=1")
    from urllib.parse import quote

    resp = signed_get(
        client,
        "/v1/transport/download",
        f"path={quote(os.path.realpath(workspace / '.env'), safe='')}",
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "unable_to_read"


def test_download_requires_absolute_path(client, workspace):
    """Descriptors carry absolute server paths; a relative one is a contract
    violation (and would otherwise depend on the server's cwd)."""
    (workspace / "pixel.png").write_bytes(tiny_png())
    resp = signed_get(client, "/v1/transport/download", "path=pixel.png")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_input"


def test_download_whitelisted_external_allowed(tmp_path):
    """Containment goes through Resolver: whitelisted external files stay
    downloadable, everything else is not."""
    from urllib.parse import quote

    ws = tmp_path / "ws"
    ws.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "doc.md").write_text("# doc")
    config = Config(
        workspace=str(ws), tokens={TOKEN: SECRET}, external_whitelist=[str(shared)]
    )
    with TestClient(create_app(config)) as client:
        resp = signed_get(
            client,
            "/v1/transport/download",
            f"path={quote(str(shared / 'doc.md'), safe='')}",
        )
    assert resp.status_code == 200
    assert resp.content == b"# doc"


def test_download_cross_drive_is_rejected_not_500(client, workspace):
    """containment across drives must fail cleanly; contains() used to raise
    ValueError here, which escaped the handler as a 500."""
    if os.name != "nt":
        pytest.skip("cross-drive paths only exist on Windows")
    from urllib.parse import quote

    home_drive = os.path.splitdrive(str(workspace))[0].upper()
    other = "D:" if home_drive != "D:" else "E:"
    resp = signed_get(
        client, "/v1/transport/download", f"path={quote(other + '/data/x.txt', safe='')}"
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "transport_unavailable"


def test_corrupt_png_rejected(client, workspace):
    (workspace / "broken.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"garbage" * 4)
    data = read(client, "broken.png").json()
    assert data["error"]["message"] == "Image could not be decoded: broken.png"


def test_jpeg_structure_checked(client, workspace):
    # valid SOI but no EOI marker
    (workspace / "trunc.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"JFIF" * 8)
    data = read(client, "trunc.jpg").json()
    assert data["error"]["message"] == "Image could not be decoded: trunc.jpg"


def test_oversized_image_rejected(client, workspace, monkeypatch):
    import agentfiles_server.readfs as readfs

    # smaller than the png fixture: trips the size check before validation
    monkeypatch.setattr(readfs, "MAX_MEDIA_INGEST_BYTES", 10)
    (workspace / "big.png").write_bytes(tiny_png())
    data = read(client, "big.png").json()
    assert data["error"]["message"] == "Media exceeds 10 byte ingestion limit: big.png"


# --- receipt provenance (read -> write/edit optimistic concurrency) ----------

def test_receipt_comes_from_the_read_handle(client, workspace, monkeypatch):
    """A file swapped after the read must not be handed a receipt for its
    replacement. The marker is fstat() on the read handle, taken before the
    bytes are pulled, so the follow-up write fails verification (fail-closed)
    instead of overwriting content the model never saw."""
    import agentfiles_server.readfs as readfs

    (workspace / "a.txt").write_bytes(b"original\n")
    real_read_opened = readfs.read_opened

    def swapping(*args, **kwargs):
        payload = real_read_opened(*args, **kwargs)
        # external writer replaces the file at the same path right after our
        # read returns -- the window a path stat taken afterwards would cover
        (workspace / "a.txt").write_bytes(b"SECRET THE MODEL NEVER SAW\n")
        return payload

    monkeypatch.setattr(readfs, "read_opened", swapping)
    version = read(client, "a.txt").json()["result"]["version"]

    data = signed_post(client, "/v1/write", {
        "path": "a.txt",
        "content": "OVERWRITTEN\n",
        "expectedVersion": version,
        "cwd": str(workspace),
    }).json()
    assert data["ok"] is False
    assert data["error"]["code"] == "version_mismatch"
    assert (workspace / "a.txt").read_bytes() == b"SECRET THE MODEL NEVER SAW\n"


def test_receipt_matches_content_under_a_concurrent_writer(client, workspace):
    """Concurrency: a receipt may only ever authorize writing over content the
    model actually read.

    A writer thread keeps atomically replacing the file while we read and
    write in a loop. Whenever a write passes verification, its receipt must
    resolve to the very bytes the matching read returned -- the failure mode
    of a receipt taken from a stat of the path after the read, which could
    describe a file swapped in during that window (and would then verify as
    "unchanged")."""

    import threading

    target = workspace / "racy.txt"
    size = 4097  # constant length: only mtime/identity change between states
    initial = b"start".ljust(size, b"x")
    target.write_bytes(initial)
    known: dict[tuple[int, int, int], bytes] = {}
    with open(target, "rb") as handle:
        stat = os.fstat(handle.fileno())
    known[(stat.st_mtime_ns, stat.st_size, stat.st_ino)] = initial
    stop = threading.Event()

    def writer() -> None:
        # replacements are atomic (temp + replace), so a reader always sees a
        # whole generation; failures are just a lost race with an open handle
        generation = 0
        while not stop.is_set():
            payload = (f"gen{generation:06d}" + "x" * size)[:size].encode()
            generation += 1
            tmp = workspace / "racy.tmp"
            try:
                with open(tmp, "wb") as handle:
                    handle.write(payload)
                    # buffered writes must reach the OS before the fstat, or
                    # the recorded state (size/mtime) would not be the one the
                    # reader later observes on the replaced file
                    handle.flush()
                    stat = os.fstat(handle.fileno())
                known[(stat.st_mtime_ns, stat.st_size, stat.st_ino)] = payload
                os.replace(tmp, target)
            except OSError:
                pass
            # pace the generations: fast enough that a read/write round trip
            # usually straddles a replacement, slow enough that some writes
            # still land (otherwise the invariant below would never run)
            stop.wait(0.003)

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    reads = writes = 0
    try:
        for _ in range(60):
            read_back = read(client, "racy.txt").json()
            if not read_back["ok"]:
                # a replace landing on an open handle is a transient Windows
                # sharing violation; it must still be a clean tool error
                assert read_back["error"]["code"] == "unable_to_read", read_back
                continue
            reads += 1
            content = read_back["result"]["content"].encode("utf-8")
            receipt = read_back["result"]["version"]
            outcome = signed_post(client, "/v1/write", {
                "path": "racy.txt",
                "content": "D" * size,
                "expectedVersion": receipt,
                "cwd": str(workspace),
            }).json()
            # clean tool errors only -- never an internal one
            assert outcome["ok"] or outcome["error"]["code"] != "internal", outcome
            if not outcome["ok"]:
                # version_mismatch is the designed answer; a replace landing on
                # our handle is a transient Windows sharing violation, which
                # has to surface as a clean tool error all the same
                assert outcome["error"]["code"] in ("version_mismatch",
                                                    "unable_to_write"), outcome
                continue
            writes += 1
            key = (receipt["mtimeNs"], receipt["size"], receipt["ino"])
            assert known.get(key) == content, (
                "the receipt did not describe the bytes that were read"
            )
            # our own write produced another state; record it for the next read
            written = outcome["result"]["version"]
            known[(written["mtimeNs"], written["size"], written["ino"])] = \
                ("D" * size).encode()
        assert reads >= 10, "the race loop barely ran; the invariant was not exercised"
        assert writes >= 1, "no write ever passed verification; the invariant was not exercised"
    finally:
        stop.set()
        thread.join(5)


def test_filesystem_failure_reports_unable_to_read(client, workspace, monkeypatch):
    """An OSError on the read path (permission, vanished file, I/O error)
    becomes a tool error the model can act on -- never an `internal` one."""
    import agentfiles_server.readfs as readfs

    make_text_file(workspace, "a.txt", "content\n")

    def boom(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(readfs, "read_opened", boom)
    data = read(client, "a.txt").json()
    assert data["ok"] is False
    assert data["error"] == {
        "code": "unable_to_read",
        "message": "Unable to read a.txt",
    }
