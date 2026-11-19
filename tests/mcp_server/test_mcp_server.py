import os
import sys

import pytest
from mcp import Client, StdioServerParameters

import kubedelos.kube.client
from kubedelos.mcp_server import tools
from kubedelos.mcp_server.server import build_server
from kubedelos.mcp_server.tools import Db
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo
from tests.mcp_server.conftest import NOW, add_image, finding, new_run, seed

pytestmark = pytest.mark.anyio

MINIMAL_ARGS = {
    "find_vulnerability": {"vuln_id": "CVE-1"},
    "workload": {"namespace": "ns", "name": "a"},
    "list_findings": {},
    "attack_surface": {"min_severity": "HIGH", "rights": ["pod_exec"]},
}


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "kubedelos.db"
    seed(path, {"zeta": 5, "alpha": 9})
    conn = connect(path)
    run_id = new_run(Repo(conn), "alpha")
    add_image(Repo(conn), run_id, "img-a", [finding("CVE-1", "HIGH")])
    conn.close()
    return Db(path, None)


async def test_tools_are_listed_read_only(db):
    async with Client(build_server(db)) as client:
        listed = (await client.list_tools()).tools
    assert [t.name for t in listed] == [
        "list_clusters",
        "run_summary",
        "fix_first",
        "find_vulnerability",
        "workload",
        "list_findings",
        "attack_surface",
        "compare_runs",
        "accepted_risks",
    ]
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
            result = await client.call_tool(tool.name, MINIMAL_ARGS.get(tool.name, {}))
            assert not result.is_error, tool.name


async def test_run_summary_over_mcp(db, monkeypatch):
    monkeypatch.setattr(tools, "_now", lambda: NOW)
    conn = db.open()
    expected = tools.run_summary(conn, db, NOW, cluster="zeta")
    conn.close()
    async with Client(build_server(db)) as client:
        result = await client.call_tool("run_summary", {"cluster": "zeta"})
        missing = await client.call_tool("run_summary", {"cluster": "zeta", "run": 7})
        fixes = await client.call_tool("fix_first", {"cluster": "zeta", "view": "image", "limit": 500})
    assert result.structured_content == expected
    assert missing.is_error and "no run 7 for zeta" in missing.content[0].text
    assert fixes.structured_content["view"] == "image" and fixes.structured_content["items"] == []


async def test_find_vulnerability_over_mcp(db, monkeypatch):
    monkeypatch.setattr(tools, "_now", lambda: NOW)
    conn = db.open()
    expected = tools.find_vulnerability(conn, db, NOW, "CVE-1", cluster="alpha")
    conn.close()
    async with Client(build_server(db)) as client:
        result = await client.call_tool("find_vulnerability", {"vuln_id": "CVE-1", "cluster": "alpha"})
        missing = await client.call_tool("workload", {"namespace": "ns", "name": "nope", "cluster": "alpha"})
        bad = await client.call_tool("list_findings", {"cluster": "alpha", "severity": ["URGENT"]})
        found = await client.call_tool("list_findings", {"cluster": "alpha", "severity": ["high"]})
    assert result.structured_content == expected and expected["images"] == ["img-a"]
    assert missing.is_error and "no workload ns/nope in run 2" in missing.content[0].text
    assert bad.is_error and "unknown severity URGENT" in bad.content[0].text
    assert [i["vuln_id"] for i in found.structured_content["items"]] == ["CVE-1"]


async def test_attack_surface_over_mcp(db, monkeypatch):
    monkeypatch.setattr(tools, "_now", lambda: NOW)
    conn = db.open()
    expected = tools.attack_surface(conn, db, NOW, cluster="alpha", min_severity="HIGH")
    conn.close()
    async with Client(build_server(db)) as client:
        result = await client.call_tool("attack_surface", {"cluster": "alpha", "min_severity": "HIGH", "limit": 500})
        bad = await client.call_tool("attack_surface", {"cluster": "alpha", "exposure": ["sideways"]})
        compare = await client.call_tool("compare_runs", {"cluster": "zeta"})
        risks = await client.call_tool("accepted_risks", {"cluster": "alpha", "state": "all"})
    assert result.structured_content == expected and expected["total"] == 1
    assert expected["items"][0]["image"] == "img-a" and expected["items"][0]["facts"] is None
    assert bad.is_error
    assert compare.is_error and "no earlier comparable run" in compare.content[0].text
    assert risks.structured_content["entries"] == []


async def test_stdio_round_trip(tmp_path):
    """The real command, as a client config would launch it: nine tools, one cluster, and the database untouched."""
    path = tmp_path / "kubedelos.db"
    seed(path, {"my-cluster": 5})
    before = path.read_bytes()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "KUBEDELOS_DATA_DIR": str(tmp_path),
        "KUBEDELOS_CACHE_DIR": str(tmp_path / "cache"),
    }
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "kubedelos", "mcp", "--data-dir", str(tmp_path)], env=env
    )
    async with Client(params) as client:
        names = [tool.name for tool in (await client.list_tools()).tools]
        result = await client.call_tool("list_clusters", {})
    assert len(names) == 9
    assert "list_clusters" in names
    assert [c["name"] for c in result.structured_content["clusters"]] == ["my-cluster"]
    assert path.read_bytes() == before
