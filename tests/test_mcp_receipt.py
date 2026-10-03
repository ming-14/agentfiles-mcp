"""MCP receipt book: read -> attach -> update -> fail closed."""

from __future__ import annotations

import json

import httpx
import pytest

import agentfiles_mcp.server as mcp_server
from agentfiles_mcp.client import ToolClient
from agentfiles_mcp.config import Config as ClientConfig
from agentfiles_mcp.receipts import ReceiptBook
from agentfiles_server.app import create_app
from agentfiles_server.config import Config as ServerConfig

TOKEN = "tok-r"
SECRET = "sec-r"


@pytest.fixture()
def wired(tmp_path, monkeypatch):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "a.txt").write_bytes(b"hello world\n")

    app = create_app(
        ServerConfig(
            workspace=str(workspace), tokens={TOKEN: SECRET},
            read_deny=[], write_deny=[],
        )
    )
    tool_client = ToolClient(
        ClientConfig(url="http://testserver", token=TOKEN, secret=SECRET)
    )
    tool_client._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )
    monkeypatch.setattr(mcp_server, "_client", tool_client)
    book = ReceiptBook()
    monkeypatch.setattr(mcp_server, "_receipts", book)
    return workspace, book


async def test_read_then_edit_round_trip(wired):
    workspace, book = wired
    await mcp_server._call("read", {"path": "a.txt"})
    assert len(book) == 1

    text = await mcp_server._call(
        "edit",
        {"path": "a.txt", "oldString": "hello", "newString": "bye"},
    )
    assert text.startswith("Edited file successfully: a.txt")
    assert (workspace / "a.txt").read_bytes() == b"bye world\n"
    # the edit's returned version replaced the read's receipt
    assert len(book) == 1


async def test_edit_without_read_is_rejected(wired):
    workspace, book = wired
    with pytest.raises(Exception) as exc:
        await mcp_server._call(
            "edit", {"path": "a.txt", "oldString": "hello", "newString": "bye"}
        )
    assert "version_missing" in str(exc.value)
    assert (workspace / "a.txt").read_bytes() == b"hello world\n"


async def test_stale_receipt_is_forgotten(wired):
    workspace, book = wired
    await mcp_server._call("read", {"path": "a.txt"})
    # external change invalidates the receipt
    with open(workspace / "a.txt", "ab") as handle:
        handle.write(b"extra\n")

    with pytest.raises(Exception) as exc:
        await mcp_server._call(
            "edit", {"path": "a.txt", "oldString": "hello", "newString": "bye"}
        )
    assert "version_mismatch" in str(exc.value)
    # the bad receipt was dropped so the next attempt cannot reuse it
    assert len(book) == 0


async def test_write_without_read_creates_but_not_overwrites(wired):
    workspace, book = wired
    # new file: no receipt needed
    text = await mcp_server._call("write", {"path": "b.txt", "content": "x"})
    assert text == "Created file successfully: b.txt"
    assert len(book) == 1

    # now b.txt exists and we hold a receipt from the write -> overwrite ok
    text = await mcp_server._call("write", {"path": "b.txt", "content": "y"})
    assert text == "Wrote file successfully: b.txt"
    assert (workspace / "b.txt").read_bytes() == b"y"


async def test_other_file_receipt_not_attached(wired):
    """A receipt for a.txt must not be sent along for c.txt."""
    workspace, book = wired
    (workspace / "c.txt").write_bytes(b"ccc\n")
    await mcp_server._call("read", {"path": "a.txt"})
    with pytest.raises(Exception) as exc:
        await mcp_server._call("write", {"path": "c.txt", "content": "hacked"})
    assert "version_missing" in str(exc.value)
    assert (workspace / "c.txt").read_bytes() == b"ccc\n"


def test_book_lru_eviction():
    book = ReceiptBook(max_entries=2)
    for i in range(3):
        book.remember({"path": f"/f{i}", "mtimeNs": i, "size": 1})
    assert len(book) == 2
    assert book.lookup("/f0") is None
    assert book.lookup("/f2") is not None


def test_book_case_insensitive_on_windows():
    import os

    book = ReceiptBook()
    book.remember({"path": r"C:\WS\A.txt", "mtimeNs": 1, "size": 1})
    if os.name == "nt":
        assert book.lookup("c:/ws/a.txt") is not None
    else:
        # POSIX: only the separator normalization applies
        assert book.lookup("C:/WS/A.txt") is not None
