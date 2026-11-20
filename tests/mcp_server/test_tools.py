import dataclasses
import json
import sqlite3
from datetime import UTC, date, datetime

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from kubedelos.config import Settings
from kubedelos.mcp_server import tools
from kubedelos.mcp_server.tools import Db
from kubedelos.models import HostPath, Rights, Workload
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
    assert str(exc.value) == (
        f"the database at {path} was written by a newer kubedelos; upgrade kubedelos or restart the MCP server"
    )


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


def test_list_clusters_default_is_none_for_an_unknown_context(tmp_path):
    path = tmp_path / "kubedelos.db"
    seed(path, {"zeta": 5, "alpha": 9})
    db = Db(path, "nope")
    conn = db.open()
    assert tools.list_clusters(conn, db, NOW)["default"] is None
    conn.close()


EMPTY_DB_CALLS = {
    "run_summary": lambda conn, db: tools.run_summary(conn, db, NOW),
    "fix_first": lambda conn, db: tools.fix_first(conn, db, NOW),
    "find_vulnerability": lambda conn, db: tools.find_vulnerability(conn, db, NOW, "CVE-1"),
    "workload": lambda conn, db: tools.workload(conn, db, NOW, "ns", "a"),
    "list_findings": lambda conn, db: tools.list_findings(conn, db, NOW),
    "attack_surface": lambda conn, db: tools.attack_surface(conn, db, NOW),
    "compare_runs": lambda conn, db: tools.compare_runs(conn, db, NOW),
    "accepted_risks": lambda conn, db: tools.accepted_risks(conn, db, NOW),
}


@pytest.mark.parametrize("context", [None, "my-cluster"])
@pytest.mark.parametrize("tool", sorted(EMPTY_DB_CALLS))
def test_empty_database_says_to_scan_first(tmp_path, tool, context):
    path = tmp_path / "kubedelos.db"
    connect(path).close()
    db = Db(path, context)
    conn = db.open()
    with pytest.raises(ToolError) as exc:
        EMPTY_DB_CALLS[tool](conn, db)
    assert str(exc.value) == f'no scans yet in {path}; run "kubedelos ui" and start a scan first'
    assert tools.list_clusters(conn, db, NOW) == {"clusters": [], "default": None}
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
    assert result["run"]["images_failed"] == 1 and result["run"]["coverage_gaps"] == 1
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
    assert result["run"]["images_failed"] == 0 and result["run"]["coverage_gaps"] == 0


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
        ("api", "gateway", "img-a"),  # no facts ranks with unknown exposure: 1 Critical, 1 High
        ("web", "worker", "img-b"),  # no facts: 1 Critical
        ("web", "site", "img-a"),  # exposure none ranks last
    ]
    assert result["workloads"][0]["facts"] is None
    assert result["workloads"][2]["facts"] == make_facts(root=True).model_dump(mode="json")
    assert (result["images_total"], result["packages_total"]) == (2, 1)
    assert set(result["workloads"][0]) == {
        "namespace", "kind", "name", "container", "image", "facts", "score", "factors"
    }  # fmt: skip
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
    rest = tools.find_vulnerability(conn, db, NOW, "CVE-1", limit=2, offset=2)
    assert [w["name"] for w in rest["workloads"]] == ["site"] and rest["total"] == 3 and rest["truncated"] is False
    clamped = tools.find_vulnerability(conn, db, NOW, "CVE-1", limit=2, offset=-5)
    assert clamped["workloads"] == result["workloads"]


def test_find_vulnerability_orders_by_exposure_like_attack_surface(world):
    """30 workloads of one image: the external ones sort last by name, and still come first."""
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    many = [_wl("n", f"w{i:02d}") for i in range(30)]
    facts = {wl: _facts(level="external" if i >= 27 else "none") for i, wl in enumerate(many) if i % 5}
    add_workloads(repo, run_id, "img-a", many, [finding("CVE-1", "HIGH")], facts=facts)
    result = tools.find_vulnerability(conn, db, NOW, "CVE-1", limit=5)
    assert [w["name"] for w in result["workloads"]] == ["w27", "w28", "w29", "w00", "w05"]  # then no facts
    assert result["total"] == 30 and result["truncated"] is True
    surface = tools.attack_surface(conn, db, NOW, limit=100)
    everything = [w["name"] for w in tools.find_vulnerability(conn, db, NOW, "CVE-1", limit=100)["workloads"]]
    assert everything == [i["name"] for i in surface["items"]]


def test_find_vulnerability_caps_images_and_packages(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    for i in range(120):
        add_image(repo, run_id, f"img{i:03d}", [finding("CVE-1", "HIGH", pkg=f"p{i:03d}")])
    result = tools.find_vulnerability(conn, db, NOW, "CVE-1")
    assert len(result["images"]) == tools.MAX_LIMIT and result["images_total"] == 120
    assert len(result["packages"]) == tools.MAX_LIMIT and result["packages_total"] == 120
    assert result["images"][0] == "img000" and result["packages"][0]["pkg_name"] == "p000"


def test_find_vulnerability_normalises_the_id(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    add_image(repo, run_id, "img-a", [finding("CVE-2024-1", "HIGH"), finding("GHSA-abcd-efgh", "HIGH", pkg="z")])
    for given in (" cve-2024-1 ", "Cve-2024-1", "CVE-2024-1\n"):
        result = tools.find_vulnerability(conn, db, NOW, given)
        assert result["vuln_id"] == "CVE-2024-1" and result["images"] == ["img-a"], given
    assert tools.find_vulnerability(conn, db, NOW, " GHSA-abcd-efgh ")["images"] == ["img-a"]
    other = tools.find_vulnerability(conn, db, NOW, "ghsa-abcd-efgh")
    assert other["vuln_id"] == "ghsa-abcd-efgh" and other["images"] == []  # only a CVE- id is upper-cased


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
    # A page too large for SQLite's offset is clamped like the UI's, not an internal error.
    huge = tools.list_findings(conn, db, NOW, page=10**30)
    assert huge["items"] == [] and huge["page"] == tools.MAX_PAGE == 10**9 and huge["total"] == 3
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


def _facts(*, level="none", privileged=False, host_pid=False, hostpath=None, caps=(), rights=None, rights_status="ok"):
    base = make_facts(level=level)
    pod = base.pod.model_copy(
        update={
            "privileged": privileged,
            "host_pid": host_pid,
            "added_capabilities": tuple(caps),
            "host_path_volumes": (HostPath(path="/data", read_only=hostpath),) if hostpath is not None else (),
        }
    )
    return base.model_copy(update={"pod": pod, "rights": Rights(status=rights_status, **(rights or {}))})


def test_host_access_rules():
    assert not tools.host_access(_facts())
    assert tools.host_access(_facts(privileged=True))
    assert tools.host_access(_facts(host_pid=True))
    assert tools.host_access(_facts(hostpath=False))
    assert not tools.host_access(_facts(hostpath=True))
    assert tools.host_access(_facts(caps=["CHOWN", "SYS_ADMIN"]))
    assert tools.host_access(_facts(caps=["ALL"]))
    assert not tools.host_access(_facts(caps=["CHOWN"]))
    for cap in ("cap_sys_admin", "CAP_SYS_MODULE", "bpf"):
        assert tools.host_access(_facts(caps=[cap])), cap
    assert not tools.host_access(_facts(caps=["NET_BIND_SERVICE"]))


def _surface_world(repo):
    run_id = new_run(repo, "my-cluster")
    ext, unk, clu, nof = _wl("web", "ext"), _wl("web", "unk"), _wl("api", "clu"), _wl("api", "nof")
    add_workloads(repo, run_id, "img-a", [ext, unk], [finding("CVE-1", "CRITICAL")], facts={
        ext: _facts(level="external", privileged=True, rights={"reads_secrets": True}),
        unk: _facts(level="unknown", rights={"wildcard": True}),
    })  # fmt: skip
    add_workloads(repo, run_id, "img-b", [clu], [finding("CVE-2", "HIGH"), finding("CVE-3", "HIGH", pkg="z")],
                  facts={clu: _facts(level="cluster", hostpath=False)})  # fmt: skip
    add_workloads(repo, run_id, "img-c", [nof], [finding("CVE-4", "CRITICAL"), finding("CVE-5", "CRITICAL", pkg="y")])
    return run_id


def _names(result):
    return [(i["namespace"], i["name"]) for i in result["items"]]


def test_attack_surface_filters_and_order(world):
    conn, repo, db = world
    _surface_world(repo)
    result = tools.attack_surface(conn, db, NOW)
    # No facts ranks with unknown exposure; nof has two Criticals to unk's one, so it comes first.
    assert _names(result) == [("web", "ext"), ("api", "nof"), ("web", "unk"), ("api", "clu")]
    assert result["facts_collected"] is True and result["total"] == 4 and result["truncated"] is False
    assert result["cluster"] == "my-cluster" and result["run"]["number"] == 1
    first = result["items"][0]
    assert set(first) == {
        "namespace",
        "kind",
        "name",
        "container",
        "image",
        "critical",
        "high",
        "host_access",
        "rights_status",
        "facts",
    }
    assert (first["critical"], first["high"], first["host_access"], first["image"]) == (1, 0, True, "img-a")
    assert result["items"][3]["host_access"] is True and result["items"][3]["high"] == 2
    assert result["items"][1]["facts"] is None and result["items"][1]["host_access"] is None
    json.dumps(result)
    assert _names(tools.attack_surface(conn, db, NOW, exposure=["external", "cluster"])) == [
        ("web", "ext"),
        ("api", "clu"),
    ]
    assert _names(tools.attack_surface(conn, db, NOW, privileged=True)) == [("web", "ext")]
    assert _names(tools.attack_surface(conn, db, NOW, privileged=False)) == [
        ("web", "unk"),
        ("api", "clu"),
    ]
    assert _names(tools.attack_surface(conn, db, NOW, host=True)) == [("web", "ext"), ("api", "clu")]
    assert _names(tools.attack_surface(conn, db, NOW, rights=["reads_secrets", "wildcard"])) == [
        ("web", "ext"),
        ("web", "unk"),
    ]
    assert _names(tools.attack_surface(conn, db, NOW, rights=["pod_exec"])) == []
    only_crit = tools.attack_surface(conn, db, NOW, min_severity="CRITICAL")
    assert _names(only_crit) == [("web", "ext"), ("api", "nof"), ("web", "unk")]
    assert _names(tools.attack_surface(conn, db, NOW, min_severity="HIGH", exposure=["cluster"])) == [("api", "clu")]
    page = tools.attack_surface(conn, db, NOW, limit=2, offset=1)
    assert _names(page) == [("api", "nof"), ("web", "unk")] and page["total"] == 4 and page["truncated"] is True
    assert _names(tools.attack_surface(conn, db, NOW, limit=2, offset=-5))[0] == ("web", "ext")


def test_attack_surface_orders_by_severity_within_exposure(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    a, b, c = _wl("n", "a"), _wl("n", "b"), _wl("n", "c")
    add_workloads(repo, run_id, "img-a", [a], [finding("CVE-1", "HIGH")], facts={a: _facts(level="none")})
    add_workloads(repo, run_id, "img-b", [b], [finding("CVE-2", "CRITICAL")], facts={b: _facts(level="none")})
    add_workloads(repo, run_id, "img-c", [c], [], facts={c: _facts(level="none")})
    assert _names(tools.attack_surface(conn, db, NOW)) == [("n", "b"), ("n", "a"), ("n", "c")]


def test_no_facts_ranks_with_unknown_exposure(world):
    """A workload without facts is as exposed as an unknown one: ahead of cluster and none, whatever its counts."""
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    unk, nof, clu, non = _wl("n", "unk"), _wl("n", "nof"), _wl("n", "clu"), _wl("n", "non")
    add_workloads(repo, run_id, "img-a", [unk], [finding("CVE-1", "HIGH")], facts={unk: _facts(level="unknown")})
    add_workloads(repo, run_id, "img-b", [nof], [finding("CVE-1", "CRITICAL")])
    add_workloads(repo, run_id, "img-c", [clu, non], [finding("CVE-1", "CRITICAL"), finding("CVE-2", "CRITICAL")],
                  facts={clu: _facts(level="cluster"), non: _facts(level="none")})  # fmt: skip
    assert _names(tools.attack_surface(conn, db, NOW)) == [("n", "nof"), ("n", "unk"), ("n", "clu"), ("n", "non")]


def test_attack_surface_without_facts(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    add_workloads(repo, run_id, "img-a", [_wl("web", "old")], [finding("CVE-1", "HIGH")])
    for kwargs in ({"exposure": ["external"]}, {"privileged": False}, {"host": False}, {"rights": ["escalates"]}):
        result = tools.attack_surface(conn, db, NOW, **kwargs)
        assert result["items"] == [] and result["facts_collected"] is False, kwargs
    result = tools.attack_surface(conn, db, NOW, min_severity="HIGH")
    assert _names(result) == [("web", "old")] and result["items"][0]["facts"] is None
    assert result["facts_collected"] is False


def test_attack_surface_unknown_host_access_is_null(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    add_workloads(repo, run_id, "img-a", [_wl("web", "old")], [finding("CVE-1", "HIGH")])
    result = tools.attack_surface(conn, db, NOW)
    assert result["items"][0]["facts"] is None and result["items"][0]["host_access"] is None


def test_attack_surface_exposure_filters_never_match_rows_without_facts(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    add_workloads(repo, run_id, "img-a", [_wl("web", "old")], [finding("CVE-1", "HIGH")])
    for level in ("none", "unknown"):
        assert tools.attack_surface(conn, db, NOW, exposure=[level])["items"] == [], level


def test_attack_surface_unknown_exposure_is_not_none(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    unk = _wl("web", "unk")
    add_workloads(repo, run_id, "img-a", [unk], [finding("CVE-1", "HIGH")], facts={unk: _facts(level="unknown")})
    assert tools.attack_surface(conn, db, NOW, exposure=["none"])["items"] == []
    assert _names(tools.attack_surface(conn, db, NOW, exposure=["unknown"])) == [("web", "unk")]


def test_attack_surface_undetermined_rights_match_the_rights_filter(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    unk, ok, nof = _wl("n", "unk"), _wl("n", "ok"), _wl("n", "nof")
    add_workloads(repo, run_id, "img-a", [unk, ok, nof], [finding("CVE-1", "HIGH")], facts={
        unk: _facts(rights_status="unknown"),
        ok: _facts(rights_status="ok"),
    })  # fmt: skip
    result = tools.attack_surface(conn, db, NOW, rights=["reads_secrets"])
    assert _names(result) == [("n", "unk")]
    assert result["items"][0]["rights_status"] == "unknown"
    by_name = {i["name"]: i["rights_status"] for i in tools.attack_surface(conn, db, NOW)["items"]}
    assert by_name == {"unk": "unknown", "ok": "ok", "nof": None}


def _two_runs(repo):
    first = new_run(repo, "my-cluster")
    add_image(repo, first, "img-a", [finding("CVE-1", "HIGH")])
    second = new_run(repo, "my-cluster")
    add_image(repo, second, "img-a", [finding("CVE-2", "CRITICAL")])
    return first, second


def test_compare_runs_defaults_to_previous_comparable(world):
    conn, repo, db = world
    _two_runs(repo)
    result = tools.compare_runs(conn, db, NOW)
    assert (result["from"]["number"], result["to"]["number"]) == (1, 2)
    assert (result["new_total"], result["gone_total"]) == (1, 1)
    assert [f["vuln_id"] for f in result["new"]] == ["CVE-2"]
    assert [f["vuln_id"] for f in result["gone"]] == ["CVE-1"]
    json.dumps(result)
    explicit = tools.compare_runs(conn, db, NOW, from_run=2, to_run=1)
    assert (explicit["from"]["number"], explicit["to"]["number"]) == (2, 1)
    assert [f["vuln_id"] for f in explicit["new"]] == ["CVE-1"]
    assert tools.compare_runs(conn, db, NOW, to_run=2)["from"]["number"] == 1
    assert len(tools.compare_runs(conn, db, NOW, limit=1)["new"]) == 1


def test_compare_runs_without_previous_is_an_error(world):
    conn, repo, db = world
    new_run(repo, "my-cluster")
    with pytest.raises(ToolError) as exc:
        tools.compare_runs(conn, db, NOW)
    assert str(exc.value) == "no earlier comparable run to compare with; pass from_run"
    with pytest.raises(ToolError) as exc:
        tools.compare_runs(conn, db, NOW, from_run=9)
    assert str(exc.value) == "no run 9 for my-cluster"


def test_accepted_risks_active_and_all(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    add_image(repo, run_id, "img-a", [finding("CVE-1", "HIGH")])
    live = accepted.add(conn, vuln_id="CVE-1", reason="risk", owner="me", expires=date(2026, 3, 1),
                        context="my-cluster", now=NOW)  # fmt: skip
    old = accepted.add(conn, vuln_id="CVE-2", reason="old", owner="me", expires=date(2026, 2, 1), context=None,
                       now=NOW)  # fmt: skip
    gone = accepted.add(conn, vuln_id="CVE-3", reason="x", owner="me", expires=date(2026, 3, 1), context="my-cluster",
                        now=NOW)  # fmt: skip
    accepted.revoke(conn, gone, NOW)
    later = NOW.replace(day=5)
    active = tools.accepted_risks(conn, db, later)
    assert active["cluster"] == "my-cluster" and active["state"] == "active"
    assert [e["id"] for e in active["entries"]] == [live]
    entry = active["entries"][0]
    assert entry["expires"] == "2026-03-01" and entry["created_at"] == NOW.isoformat()
    assert entry["state"] == "active" and entry["covers"] == 1 and entry["revoked_at"] is None
    everything = tools.accepted_risks(conn, db, later, state="all")
    assert {e["id"]: e["state"] for e in everything["entries"]} == {live: "active", old: "expired", gone: "revoked"}
    json.dumps(everything)


def test_accepted_risks_without_a_run(world):
    conn, repo, db = world
    new_run(repo, "my-cluster", "running")
    accepted.add(conn, vuln_id="CVE-1", reason="r", owner="me", expires=date(2026, 3, 1), context=None, now=NOW)
    result = tools.accepted_risks(conn, db, NOW)
    assert [e["covers"] for e in result["entries"]] == [None]


def _store_intel(conn, *, kev=True):
    with conn:
        conn.execute("INSERT INTO threat_intel VALUES ('CVE-1', ?, '2025-03-04', 0.97, 0.99)", (int(kev),))
        conn.execute(
            "INSERT INTO threat_feed VALUES ('kev', '2026-01-31T08:00:00+00:00', 'v1', 1),"
            " ('epss', '2026-01-31T09:00:00+00:00', 'v1', 1)"
        )


def test_fix_first_scores_and_orders_by_risk_when_shown(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    site = _wl("web", "site")
    add_workloads(repo, run_id, "img-h", [site], [finding("CVE-H", "HIGH", pkg="a")],
                  facts={site: make_facts(level="none")})  # fmt: skip
    add_workloads(repo, run_id, "img-c", [_wl("web", "other")], [finding("CVE-C", "CRITICAL", pkg="b")])
    _store_intel(conn, kev=True)
    conn.execute("UPDATE threat_intel SET vuln_id = 'CVE-H'")
    conn.commit()
    result = tools.fix_first(conn, db, NOW)
    assert result["risk"] == {
        "shown": True,
        "facts": True,
        "feeds": {"kev": "2026-01-31T08:00:00+00:00", "epss": "2026-01-31T09:00:00+00:00"},
    }
    scores = [i["score"] for i in result["items"]]
    assert scores == sorted(scores, reverse=True) and all(isinstance(s, int) for s in scores)
    top = result["items"][0]
    assert [f["factor"] for f in top["factors"]] == ["severity", "exploited", "exposure", "host", "rights"]
    assert set(top["factors"][0]) == {"factor", "points", "detail"}
    assert sum(f["points"] for f in top["factors"]) >= top["score"]
    json.dumps(result)
    by_image = tools.fix_first(conn, db, NOW, view="image")
    assert by_image["risk"]["shown"] is True and by_image["items"][0]["score"] is not None
    assert len(by_image["items"][0]["factors"]) == 5


def test_fix_first_without_facts_or_feeds_hides_the_score(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    add_image(repo, run_id, "img", [finding("CVE-1", "HIGH")])
    result = tools.fix_first(conn, db, NOW)
    assert result["risk"] == {"shown": False, "facts": False, "feeds": {"kev": None, "epss": None}}
    assert [(i["score"], i["factors"]) for i in result["items"]] == [(None, [])]


def test_find_vulnerability_carries_intel_and_scores_the_workloads(world):
    conn, repo, db = world
    _cve_world(repo)
    _store_intel(conn)
    result = tools.find_vulnerability(conn, db, NOW, "CVE-1")
    assert (result["kev"], result["kev_added"], result["epss"], result["epss_percentile"]) == (
        True, "2025-03-04", 0.97, 0.99)  # fmt: skip
    assert result["risk"]["shown"] is True and result["risk"]["facts"] is True
    items = result["workloads"]
    assert [i["score"] for i in items] == sorted((i["score"] for i in items), reverse=True)
    assert items[-1]["name"] == "site"  # exposure none, so the lowest
    assert [f["factor"] for f in items[0]["factors"]] == ["severity", "exploited", "exposure", "host", "rights"]
    assert items[0]["factors"][1] == {"factor": "exploited", "points": 25, "detail": "in KEV since 2025-03-04"}
    assert items[0]["factors"][0]["detail"] == "critical"


def test_find_vulnerability_ranks_the_external_workload_of_a_kev_cve_first(world):
    conn, repo, db = world
    run_id = new_run(repo, "my-cluster")
    quiet, loud = _wl("a", "quiet"), _wl("z", "loud")
    add_workloads(repo, run_id, "img", [quiet, loud], [finding("CVE-1", "HIGH")],
                  facts={quiet: make_facts(level="none"), loud: make_facts(level="external")})  # fmt: skip
    _store_intel(conn)
    result = tools.find_vulnerability(conn, db, NOW, "CVE-1")
    assert [w["name"] for w in result["workloads"]] == ["loud", "quiet"]
    assert result["workloads"][0]["score"] > result["workloads"][1]["score"]


def test_find_vulnerability_without_intel_or_facts_keeps_exposure_order(world):
    conn, repo, db = world
    _cve_world(repo)
    with conn:
        conn.execute("UPDATE workload SET facts = NULL")
    result = tools.find_vulnerability(conn, db, NOW, "CVE-1")
    assert result["risk"]["shown"] is False
    assert (result["kev"], result["kev_added"], result["epss"], result["epss_percentile"]) == (False, None, None, None)
    assert [(w["score"], w["factors"]) for w in result["workloads"]] == [(None, [])] * 3
    assert [w["name"] for w in result["workloads"]] == ["gateway", "site", "worker"]
