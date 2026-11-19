import pytest

from kubedelos.models import Workload
from kubedelos.store import workloads
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo
from tests.mcp_server.conftest import add_workloads, finding, make_facts, new_run


def _wl(ns, name, kind="Deployment", container="c"):
    return Workload(namespace=ns, kind=kind, name=name, container=container)


@pytest.fixture
def seeded(tmp_path):
    conn = connect(tmp_path / "kubedelos.db")
    repo = Repo(conn)
    run_id = new_run(repo, "my-cluster")
    web, api, job = _wl("web", "site"), _wl("api", "gateway"), _wl("api", "gateway", "StatefulSet")
    add_workloads(
        repo, run_id, "img-a",
        [web, api, job],
        [finding("CVE-1", "CRITICAL"), finding("CVE-2", "HIGH", pkg="zlib"), finding("CVE-3", "LOW", pkg="curl")],
        facts={web: make_facts(root=True)},
    )  # fmt: skip
    add_workloads(repo, run_id, "img-b", [_wl("web", "worker")], [finding("CVE-2", "HIGH", pkg="zlib")])
    add_workloads(repo, run_id, "img-c", [_wl("web", "clean")])
    other = new_run(repo, "my-cluster")
    add_workloads(repo, other, "img-a", [_wl("web", "site")], [finding("CVE-1", "CRITICAL")])
    yield conn, run_id
    conn.close()


def test_parse_facts_tolerates_null_invalid_and_other_versions():
    good = make_facts(root=False)
    assert workloads.parse_facts(good.model_dump_json()) == good
    assert workloads.parse_facts(None) is None
    assert workloads.parse_facts("") is None
    assert workloads.parse_facts("not json") is None
    assert workloads.parse_facts("{}") is None
    assert workloads.parse_facts('{"v": 2, "pod": {}}') is None
    assert workloads.parse_facts(good.model_dump_json().replace('"v":1', '"v":2')) is None


def test_workloads_for_a_cve(seeded):
    conn, run_id = seeded
    rows = workloads.workloads(conn, run_id, vuln_id="CVE-2")
    assert [(r.namespace, r.kind, r.name, r.ref) for r in rows] == [
        ("api", "Deployment", "gateway", "img-a"),
        ("api", "StatefulSet", "gateway", "img-a"),
        ("web", "Deployment", "site", "img-a"),
        ("web", "Deployment", "worker", "img-b"),
    ]
    assert workloads.workloads(conn, run_id, vuln_id="CVE-404") == []
    assert workloads.workloads(conn, run_id, vuln_id="cve-2") == []  # an exact match, no case folding
    site = rows[2]
    assert site.status == "ok" and site.facts == make_facts(root=True)
    assert rows[0].facts is None


def test_workloads_filters(seeded):
    conn, run_id = seeded
    assert len(workloads.workloads(conn, run_id)) == 5
    assert [r.name for r in workloads.workloads(conn, run_id, namespace="web")] == ["clean", "site", "worker"]
    both = workloads.workloads(conn, run_id, namespace="api", name="gateway")
    assert [r.kind for r in both] == ["Deployment", "StatefulSet"]
    only = workloads.workloads(conn, run_id, namespace="api", name="gateway", kind="StatefulSet")
    assert [r.kind for r in only] == ["StatefulSet"]
    assert workloads.workloads(conn, run_id, namespace="api", name="gate") == []


def test_counts_by_severity(seeded):
    conn, run_id = seeded
    site = workloads.workloads(conn, run_id, namespace="web", name="site")[0]
    assert site.counts == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "UNKNOWN": 0}
    clean = workloads.workloads(conn, run_id, namespace="web", name="clean")[0]
    assert clean.counts == dict.fromkeys(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"), 0)


def test_cve_packages(seeded):
    conn, run_id = seeded
    packages = workloads.cve_packages(conn, run_id, "CVE-2")
    assert packages == [
        {"pkg_name": "zlib", "installed_version": "1.1", "fixed_version": "1.2", "severity": "HIGH", "title": None,
         "primary_url": None},
    ]  # fmt: skip
    assert workloads.cve_packages(conn, run_id, "CVE-404") == []
    assert workloads.cve_images(conn, run_id, "CVE-2") == ["img-a", "img-b"]


def test_top_findings_are_ordered_and_bounded(seeded):
    conn, run_id = seeded
    top = workloads.top_findings(conn, run_id, "img-a")
    assert [(t["vuln_id"], t["severity"]) for t in top] == [("CVE-1", "CRITICAL"), ("CVE-2", "HIGH"), ("CVE-3", "LOW")]
    assert set(top[0]) == {"vuln_id", "pkg_name", "severity", "fixed_version"}
    assert len(workloads.top_findings(conn, run_id, "img-a", limit=2)) == 2
    assert workloads.top_findings(conn, run_id, "img-c") == []
