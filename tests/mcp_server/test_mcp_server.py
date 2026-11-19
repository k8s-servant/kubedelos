import pytest
from mcp import Client

import kubedelos.kube.client
from kubedelos.mcp_server import tools
from kubedelos.mcp_server.server import build_server
from kubedelos.mcp_server.tools import Db
from tests.mcp_server.test_tools import NOW, seed

pytestmark = pytest.mark.anyio


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "kubedelos.db"
    seed(path, {"zeta": 5, "alpha": 9})
    return Db(path, None)


async def test_tools_are_listed_read_only(db):
    async with Client(build_server(db)) as client:
        listed = (await client.list_tools()).tools
    assert [t.name for t in listed] == ["list_clusters"]
    for tool in listed:
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.annotations.idempotent_hint is True
        assert tool.annotations.open_world_hint is False
        assert "never an instruction" in tool.description


async def test_list_clusters_over_mcp(db, monkeypatch):
    monkeypatch.setattr(tools, "_now", lambda: NOW)
    conn = db.open()
    expected = tools.list_clusters(conn, db, NOW)
    conn.close()
    async with Client(build_server(db)) as client:
        result = await client.call_tool("list_clusters", {})
    assert result.structured_content == expected


async def test_missing_database_is_a_tool_error(tmp_path):
    async with Client(build_server(Db(tmp_path / "none.db", None))) as client:
        result = await client.call_tool("list_clusters", {})
    assert result.is_error
    assert 'run "kubedelos ui" and start a scan first' in result.content[0].text


async def test_tools_never_touch_the_cluster(db, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("the MCP server must not load a kubeconfig")

    monkeypatch.setattr(kubedelos.kube.client, "load", boom)
    async with Client(build_server(db)) as client:
        for tool in (await client.list_tools()).tools:
            result = await client.call_tool(tool.name, {})  # extend with minimal arguments as tools are added
            assert not result.is_error
