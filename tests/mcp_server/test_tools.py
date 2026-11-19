import dataclasses
import json
import sqlite3
from datetime import UTC, date, datetime

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from kubedelos.config import Settings
from kubedelos.mcp_server import tools
from kubedelos.mcp_server.tools import Db
from kubedelos.models import Workload
from kubedelos.store import accepted, queries
from kubedelos.store.db import MIGRATIONS, connect
from kubedelos.store.repo import Repo
from tests.mcp_server.conftest import (
    NOW,
    Clock,
    add_gap,
    add_image,
    add_workloads,
    finding,
    make_facts,
    new_run,
    seed,
)


def test_open_missing_database_says_how_to_create_it(tmp_path):
    path = tmp_path / "kubedelos.db"
    with pytest.raises(ToolError) as exc:
        Db(path, None).open()
    assert str(exc.value) == f'no kubedelos database at {path}; run "kubedelos ui" and start a scan first'
    assert not path.exists()


def test_open_older_schema_is_refused_without_writing(tmp_path):
    path = tmp_path / "kubedelos.db"
    connect(path).close()
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {len(MIGRATIONS) - 1}")
    raw.commit()
    raw.close()
    before = path.read_bytes()
    with pytest.raises(ToolError) as exc:
        Db(path, None).open()
    assert str(exc.value) == (
        f'the database at {path} was written by an older kubedelos; open "kubedelos ui" once to update it'
    )
    assert path.read_bytes() == before


def test_open_newer_schema_is_refused(tmp_path):
    path = tmp_path / "kubedelos.db"
    connect(path).close()
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {len(MIGRATIONS) + 1}")
    raw.commit()
    raw.close()
    with pytest.raises(ToolError) as exc:
        Db(path, None).open()
    assert str(exc.value) == f"the database at {path} was written by a newer kubedelos; upgrade kubedelos"


def test_clamp():
    assert tools.clamp(0) == 25
    assert tools.clamp(-3) == 25
    assert tools.clamp(500) == 100
    assert tools.clamp(7) == 7


def test_list_clusters_sorted_with_default(tmp_path):
    path = tmp_path / "kubedelos.db"
    seed(path, {"zeta": 5, "alpha": 9})
    db = Db(path, None)
    conn = db.open()
    result = tools.list_clusters(conn, db, NOW)
    assert [c["name"] for c in result["clusters"]] == ["alpha", "zeta"]
    assert result["default"] == "alpha"  # the newest finished run
    alpha = result["clusters"][0]
    assert alpha["newest_run"] == 1 and alpha["status"] == "ok" and alpha["last_scan"].startswith("2026-01-09")
    assert alpha["stale"] is True
    conn.close()
    pinned = Db(path, "zeta")
    conn = pinned.open()
    assert tools.list_clusters(conn, pinned, NOW)["default"] == "zeta"
    conn.close()


def test_unknown_cluster_lists_known_ones(tmp_path):
    path = tmp_path / "kubedelos.db"
    seed(path, {"zeta": 5, "alpha": 9})
    db = Db(path, None)
    conn = db.open()
    with pytest.raises(ToolError) as exc:
        tools.resolve_cluster(conn, db, "nope")
    assert str(exc.value) == "unknown cluster nope; known: alpha, zeta"
    assert tools.resolve_cluster(conn, db, "zeta") == "zeta"
    assert tools.resolve_cluster(conn, db, None) == "alpha"
    conn.close()


def test_open_file_that_is_not_a_database(tmp_path):
    path = tmp_path / "kubedelos.db"
    path.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(ToolError) as exc:
        Db(path, None).open()
    assert str(exc.value).startswith(f"cannot read the database at {path}: ")


@pytest.fixture
def world(tmp_path):
    """A database with one cluster, ``my-cluster``, and a repo that seeds more runs into it."""
    conn = connect(tmp_path / "kubedelos.db")
    repo = Repo(conn, clock=Clock(datetime(2026, 1, 10, tzinfo=UTC)))
    yield conn, repo, Db(tmp_path / "kubedelos.db", "my-cluster")
    conn.close()


def test_select_run_skips_a_running_run(world):
    conn, repo, _ = world
    done = new_run(repo, "my-cluster")
    new_run(repo, "my-cluster", "running")
    assert tools.select_run(conn, "my-cluster", None).id == done


def test_select_run_prefers_whole_cluster_then_any(world):
    conn, repo, _ = world
    whole = new_run(repo, "my-cluster")
    narrow = new_run(repo, "my-cluster", scope=Settings(namespaces=["web"]).scope)
    assert tools.select_run(conn, "my-cluster", None).id == whole
    assert tools.select_run(conn, "my-cluster", 2).id == narrow
    only_narrow = new_run(repo, "other", scope=Settings(namespaces=["web"]).scope)
    assert tools.select_run(conn, "other", None).id == only_narrow


def test_select_run_by_number(world):
    conn, repo, _ = world
    new_run(repo, "my-cluster")
    new_run(repo, "my-cluster", "partial")
    new_run(repo, "other")
    assert tools.select_run(conn, "my-cluster", 2).status == "partial"
    with pytest.raises(ToolError) as exc:
        tools.select_run(conn, "my-cluster", 9)
    assert str(exc.value) == "no run 9 for my-cluster"
    new_run(repo, "my-cluster", "failed")
    with pytest.raises(ToolError) as exc:
        tools.select_run(conn, "my-cluster", 3)  # a failed run has no results to show
    assert str(exc.value) == "no run 3 for my-cluster"


def test_select_run_without_a_finished_run(world):
    conn, repo, _ = world
    new_run(repo, "my-cluster", "running")
    with pytest.raises(ToolError) as exc:
        tools.select_run(conn, "my-cluster", None)
    assert str(exc.value) == "my-cluster has no finished scan yet"


def test_run_summary_fields(world):
    conn, repo, db = world
    previous = new_run(repo, "my-cluster")
    add_image(repo, previous, "img-a", [finding("CVE-1", "HIGH")])
    run_id = new_run(repo, "my-cluster")
    add_image(repo, run_id, "img-a", [finding("CVE-1", "CRITICAL"), finding("CVE-2", "HIGH", pkg="zlib")])
    add_image(repo, run_id, "img-b", error_kind="timeout", status="error")
    add_gap(repo, run_id, "namespace secret-ns was skipped")
    result = tools.run_summary(conn, db, NOW)
    assert result["cluster"] == "my-cluster"
    assert result["run"]["number"] == 2 and result["run"]["fact_sources"] is None
    assert result["kpis"] == dataclasses.asdict(queries.kpis(conn, run_id))
    assert result["kpis"]["critical"] == 1 and result["kpis"]["images_failed"] == 1
    assert result["coverage_gaps"] == ["namespace secret-ns was skipped"]
    assert result["failed"] == [{"kind": "timeout", "count": 1}]
    assert result["previous_run"] == 1


def test_run_summary_without_previous_run(world):
    conn, repo, db = world
    new_run(repo, "my-cluster")
    result = tools.run_summary(conn, db, NOW, cluster="my-cluster", run=1)
    assert result["previous_run"] is None and result["failed"] == [] and result["coverage_gaps"] == []


def _many_fixes(repo, run_id, n):
    for i in range(n):
        add_image(repo, run_id, f"img{i:03d}", [finding(f"CVE-{i:03d}", "HIGH")])


def test_fix_first_matches_dashboard_order(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    add_image(repo, run_id, "h1", [finding("CVE-H", "HIGH", pkg="a")])
    add_image(repo, run_id, "h2", [finding("CVE-H", "HIGH", pkg="a")])
    add_image(repo, run_id, "c1", [finding("CVE-C", "CRITICAL", pkg="b")])
    add_image(repo, run_id, "nf", [finding("CVE-N", "CRITICAL", pkg="n", fixed="")])
    result = tools.fix_first(conn, db, NOW)
    expected = queries.fix_by_fix(conn, run_id, limit=25)
    assert result["view"] == "fix" and result["cluster"] == "my-cluster" and result["run"]["number"] == 1
    assert result["items"] == [json.loads(json.dumps(dataclasses.asdict(r))) for r in expected.rows]
    assert [i["vuln_id"] for i in result["items"]] == ["CVE-C", "CVE-H"]
    assert result["total"] == 2 and result["truncated"] is False
    assert (result["no_fix"], result["no_fix_images"], result["accepted"]) == (1, 1, 0)


def test_fix_first_image_view(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    add_image(repo, run_id, "worse", [finding("CVE-1", "CRITICAL"), finding("CVE-2", "HIGH", pkg="z")])
    add_image(repo, run_id, "mild", [finding("CVE-3", "HIGH")])
    result = tools.fix_first(conn, db, NOW, view="image")
    expected = queries.fix_by_image(conn, run_id, limit=25)
    assert result["view"] == "image"
    assert result["items"] == [json.loads(json.dumps(dataclasses.asdict(r))) for r in expected.rows]
    assert [i["ref"] for i in result["items"]] == ["worse", "mild"]


def test_limit_clamped(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    _many_fixes(repo, run_id, 120)
    result = tools.fix_first(conn, db, NOW, limit=10_000)
    assert len(result["items"]) == 100 and result["total"] == 120 and result["truncated"] is True
    assert len(tools.fix_first(conn, db, NOW)["items"]) == 25
    assert len(tools.fix_first(conn, db, NOW, limit=3)["items"]) == 3


def test_fix_first_items_are_json_ready(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    add_image(repo, run_id, "img", [finding("CVE-1", "HIGH")])
    json.dumps(tools.fix_first(conn, db, NOW))
    json.dumps(tools.run_summary(conn, db, NOW))


def _wl(ns, name, kind="Deployment", container="c"):
    return Workload(namespace=ns, kind=kind, name=name, container=container)


def _cve_world(repo):
    run_id = new_run(repo, "my-cluster")
    site, api = _wl("web", "site"), _wl("api", "gateway")
    add_workloads(repo, run_id, "img-a", [site, api], [finding("CVE-1", "CRITICAL"), finding("CVE-2", "HIGH", pkg="z")],
                  facts={site: make_facts(root=True)})  # fmt: skip
    add_workloads(repo, run_id, "img-b", [_wl("web", "worker")], [finding("CVE-1", "CRITICAL")])
    return run_id


def test_find_vulnerability_includes_facts_and_acceptance(world):
    conn, repo, db = world
    _cve_world(repo)
    soon = date(2026, 2, 10)
    live = accepted.add(conn, vuln_id="CVE-1", reason="risk", owner="me", expires=soon, context="my-cluster",
                        now=NOW, namespace="web")  # fmt: skip
    gone = accepted.add(conn, vuln_id="CVE-1", reason="old", owner="me", expires=date(2026, 2, 1), context="my-cluster",
                        now=NOW)  # fmt: skip
    accepted.revoke(conn, gone, NOW)
    result = tools.find_vulnerability(conn, db, NOW, " CVE-1 ")
    assert (result["cluster"], result["run"]["number"], result["vuln_id"]) == ("my-cluster", 1, "CVE-1")
    assert [p["pkg_name"] for p in result["packages"]] == ["openssl"]
    assert result["images"] == ["img-a", "img-b"]
    assert [(w["namespace"], w["name"], w["image"]) for w in result["workloads"]] == [
        ("api", "gateway", "img-a"),
        ("web", "site", "img-a"),
        ("web", "worker", "img-b"),
    ]
    assert result["workloads"][0]["facts"] is None
    assert result["workloads"][1]["facts"] == make_facts(root=True).model_dump(mode="json")
    assert set(result["workloads"][0]) == {"namespace", "kind", "name", "container", "image", "facts"}
    assert result["total"] == 3 and result["truncated"] is False
    assert result["acceptance"] == [
        {"id": live, "namespace": "web", "repo": None, "pkg_name": None, "reason": "risk", "owner": "me",
         "expires_at": "2026-02-10"},
    ]  # fmt: skip
    json.dumps(result)


def test_find_vulnerability_limit_truncates(world):
    conn, repo, db = world
    _cve_world(repo)
    result = tools.find_vulnerability(conn, db, NOW, "CVE-1", limit=2)
    assert len(result["workloads"]) == 2 and result["total"] == 3 and result["truncated"] is True


def test_find_vulnerability_unknown_cve_is_empty(world):
    conn, repo, db = world
    _cve_world(repo)
    result = tools.find_vulnerability(conn, db, NOW, "CVE-404")
    assert result["packages"] == [] and result["images"] == [] and result["workloads"] == []
    assert result["acceptance"] == [] and result["total"] == 0 and result["truncated"] is False


def test_workload_lists_containers_with_top_findings(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    many = [finding(f"CVE-{i:02d}", "HIGH", pkg=f"p{i}") for i in range(12)] + [finding("CVE-X", "CRITICAL")]
    site = _wl("web", "site")
    add_workloads(repo, run_id, "img-a", [site, _wl("web", "site", "StatefulSet", "side")], many,
                  facts={site: make_facts()})  # fmt: skip
    add_workloads(repo, run_id, "img-b", [_wl("web", "site", container="init")])
    result = tools.workload(conn, db, NOW, "web", "site")
    assert result["cluster"] == "my-cluster" and result["run"]["number"] == 1
    containers = result["containers"]
    assert [(c["kind"], c["container"], c["image"]) for c in containers] == [
        ("Deployment", "c", "img-a"),
        ("Deployment", "init", "img-b"),
        ("StatefulSet", "side", "img-a"),
    ]
    first = containers[0]
    assert first["counts"] == {"CRITICAL": 1, "HIGH": 12, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    assert first["facts"] == make_facts().model_dump(mode="json") and containers[1]["facts"] is None
    top = first["top_findings"]
    assert len(top) == 10 and top[0]["vuln_id"] == "CVE-X"
    assert set(top[0]) == {"vuln_id", "pkg_name", "severity", "fixed_version"}
    assert containers[1]["top_findings"] == []
    only = tools.workload(conn, db, NOW, "web", "site", kind="StatefulSet")
    assert [c["kind"] for c in only["containers"]] == ["StatefulSet"]
    json.dumps(result)


def test_workload_missing_is_an_error(world):
    conn, repo, db = world
    new_run(repo, "my-cluster")
    with pytest.raises(ToolError) as exc:
        tools.workload(conn, db, NOW, "web", "nope")
    assert str(exc.value) == "no workload web/nope in run 1"


def _findings_world(repo):
    run_id = new_run(repo, "my-cluster")
    add_image(repo, run_id, "img-a", [finding("CVE-1", "CRITICAL"), finding("CVE-2", "HIGH", pkg="zlib", fixed="")],
              namespaces=("web",))  # fmt: skip
    add_image(repo, run_id, "img-b", [finding("CVE-3", "LOW", pkg="curl").model_copy(update={"pkg_class": "library"})],
              namespaces=("api",))  # fmt: skip
    return run_id


def test_list_findings_filters_and_paging(world):
    conn, repo, db = world
    _findings_world(repo)
    everything = tools.list_findings(conn, db, NOW)
    assert [i["vuln_id"] for i in everything["items"]] == ["CVE-1", "CVE-2", "CVE-3"]
    assert everything["total"] == 3 and everything["page"] == 1 and everything["per_page"] == 25
    assert everything["truncated"] is False and everything["accepted_left_out"] == 0
    first = everything["items"][0]
    assert first["ref"] == "img-a" and first["severity"] == "CRITICAL" and first["namespaces"] == ["web"]
    assert first["accepted"] is False and "total" not in first and "sev_rank" not in first
    assert [i["vuln_id"] for i in tools.list_findings(conn, db, NOW, severity=["high", "Low"])["items"]] == [
        "CVE-2",
        "CVE-3",
    ]
    assert [i["vuln_id"] for i in tools.list_findings(conn, db, NOW, namespace="api")["items"]] == ["CVE-3"]
    assert [i["vuln_id"] for i in tools.list_findings(conn, db, NOW, fixable="no")["items"]] == ["CVE-2"]
    assert [i["vuln_id"] for i in tools.list_findings(conn, db, NOW, q="curl")["items"]] == ["CVE-3"]
    assert [i["vuln_id"] for i in tools.list_findings(conn, db, NOW, pkg_class="library")["items"]] == ["CVE-3"]
    paged = tools.list_findings(conn, db, NOW, page=2, per_page=2)
    assert [i["vuln_id"] for i in paged["items"]] == ["CVE-3"] and paged["total"] == 3 and paged["truncated"] is False
    assert tools.list_findings(conn, db, NOW, per_page=2)["truncated"] is True
    assert tools.list_findings(conn, db, NOW, per_page=5000)["per_page"] == 100
    assert tools.list_findings(conn, db, NOW, page=9)["items"] == []
    json.dumps(everything)


def test_list_findings_accepted_modes(world):
    conn, repo, db = world
    _findings_world(repo)
    accepted.add(conn, vuln_id="CVE-1", reason="r", owner="o", expires=date(2026, 3, 1), context="my-cluster", now=NOW)
    hidden = tools.list_findings(conn, db, NOW)
    assert [i["vuln_id"] for i in hidden["items"]] == ["CVE-2", "CVE-3"] and hidden["accepted_left_out"] == 1
    only = tools.list_findings(conn, db, NOW, accepted="only")
    assert [i["vuln_id"] for i in only["items"]] == ["CVE-1"] and only["items"][0]["accepted"] is True
    assert tools.list_findings(conn, db, NOW, accepted="all")["total"] == 3


def test_list_findings_bad_severity(world):
    conn, repo, db = world
    new_run(repo, "my-cluster")
    with pytest.raises(ToolError) as exc:
        tools.list_findings(conn, db, NOW, severity=["URGENT"])
    assert str(exc.value) == "unknown severity URGENT; use CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN"


def test_page_zero_is_page_one(world):
    conn, repo, db = world
    _findings_world(repo)
    zero = tools.list_findings(conn, db, NOW, page=0)
    assert zero["page"] == 1 and zero["items"] == tools.list_findings(conn, db, NOW, page=1)["items"]
    assert tools.list_findings(conn, db, NOW, page=-4)["page"] == 1
