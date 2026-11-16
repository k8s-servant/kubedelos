from datetime import UTC, date, datetime, timedelta

import pytest

from kubedelos.config import Settings
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.store import accepted
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo

TODAY = date(2026, 3, 1)
NOW = datetime(2026, 3, 1, 9, tzinfo=UTC)
CLUSTER = Settings().scope


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "k.db")
    yield conn, Repo(conn)
    conn.close()


def _run(repo, context="ctx"):
    run_id = repo.start_run(context, "ui", "0.76.1", scan_level="library,os", scope=CLUSTER)
    repo.finish_run(run_id, "ok")
    return run_id


def _add(
    repo, run_id, ref, namespaces, vulns, *, repo_name="reg.example.com/app", pkg="openssl", platform="linux/amd64"
):
    image = ImageRef(ref=ref, repo=repo_name, tag=ref, digest=None)
    workloads = [Workload(namespace=ns, kind="Deployment", name="w", container="c") for ns in namespaces]
    findings = [
        Finding(vuln_id=v, pkg_name=pkg, installed_version="1", severity=Severity.HIGH, target="t", pkg_type="os")
        for v in vulns
    ]
    item = InventoryItem(image=image, platform=platform, workloads=workloads)
    repo.add_result(run_id, item, ImageResult(image=image, platform=platform, status="ok", findings=findings))


def _accept(conn, vuln_id="CVE-1", *, context="ctx", expires=TODAY + timedelta(days=30), now=NOW, **narrow):
    return accepted.add(
        conn, vuln_id=vuln_id, reason="not reachable", owner="me", expires=expires, context=context, now=now, **narrow
    )


def _keys(conn, run_id, today=TODAY):
    return {(ref, vuln) for ref, vuln, _pkg, _ver in accepted.accepted_keys(conn, run_id, today)}


def test_an_entry_matches_its_cve_in_its_cluster_only(db):
    conn, repo = db
    mine, theirs = _run(repo), _run(repo, context="other")
    for run_id in (mine, theirs):
        _add(repo, run_id, "a", ["web"], ["CVE-1", "CVE-2"])
    _accept(conn)
    assert _keys(conn, mine) == {("a", "CVE-1")}
    assert _keys(conn, theirs) == set()
    _accept(conn, "CVE-2", context=None)  # all clusters
    assert _keys(conn, theirs) == {("a", "CVE-2")}


def test_package_and_image_narrow_the_match(db):
    conn, repo = db
    run_id = _run(repo)
    _add(repo, run_id, "a", ["web"], ["CVE-1"], repo_name="reg.example.com/app")
    _add(repo, run_id, "b", ["web"], ["CVE-1"], repo_name="reg.example.com/other")
    _add(repo, run_id, "c", ["web"], ["CVE-1"], pkg="zlib")
    _accept(conn, repo="reg.example.com/app", pkg_name="openssl")
    assert _keys(conn, run_id) == {("a", "CVE-1")}


def test_the_image_is_the_repository_whatever_the_tag(db):
    conn, repo = db
    run_id = _run(repo)
    _add(repo, run_id, "reg.example.com/app:1", ["web"], ["CVE-1"])
    _add(repo, run_id, "reg.example.com/app:2", ["web"], ["CVE-1"])
    _accept(conn, repo="reg.example.com/app")
    assert len(_keys(conn, run_id)) == 2


def test_a_unit_is_accepted_only_when_every_namespace_it_runs_in_is_covered(db):
    conn, repo = db
    run_id = _run(repo)
    _add(repo, run_id, "a", ["web", "api"], ["CVE-1"])
    _add(repo, run_id, "a", ["web", "api"], ["CVE-1"], platform="linux/arm64")  # a second platform repeats them
    _add(repo, run_id, "b", ["web"], ["CVE-1"])
    _add(repo, run_id, "c", [], ["CVE-1"])  # no workload
    _accept(conn, namespace="web")
    assert _keys(conn, run_id) == {("b", "CVE-1")}  # a still matters in api; c runs nowhere named
    _accept(conn, namespace="api")
    assert _keys(conn, run_id) == {("a", "CVE-1"), ("b", "CVE-1")}
    _accept(conn)  # no namespace covers everywhere, an image with no workload too
    assert _keys(conn, run_id) == {("a", "CVE-1"), ("b", "CVE-1"), ("c", "CVE-1")}


def test_expired_and_revoked_entries_stop_matching_at_once(db):
    conn, repo = db
    run_id = _run(repo)
    _add(repo, run_id, "a", ["web"], ["CVE-1", "CVE-2"])
    _accept(conn, expires=TODAY)  # its last day
    revoked = _accept(conn, "CVE-2")
    assert _keys(conn, run_id) == {("a", "CVE-1"), ("a", "CVE-2")}
    assert accepted.revoke(conn, revoked, NOW) is True
    assert accepted.revoke(conn, revoked, NOW) is False  # already revoked
    assert accepted.revoke(conn, 999, NOW) is False
    assert _keys(conn, run_id) == {("a", "CVE-1")}
    assert _keys(conn, run_id, TODAY + timedelta(days=1)) == set()


def test_register_lists_this_cluster_and_all_clusters_with_state_and_cover(db):
    conn, repo = db
    run_id = _run(repo)
    _add(repo, run_id, "a", ["web", "api"], ["CVE-1", "CVE-2"])
    _add(repo, run_id, "b", ["web"], ["CVE-1"])
    soon = _accept(conn, expires=TODAY + timedelta(days=3))
    later = _accept(conn, "CVE-2", context=None, namespace="web")
    nothing = _accept(conn, "CVE-404", expires=TODAY + timedelta(days=1))
    expired = _accept(conn, expires=TODAY - timedelta(days=1), now=NOW - timedelta(days=9))  # made back then
    revoked = _accept(conn)
    accepted.revoke(conn, revoked, NOW)
    _accept(conn, context="other")  # another cluster's: not listed
    entries = accepted.register(conn, "ctx", run_id, TODAY)
    assert [e.id for e in entries] == [nothing, soon, later, expired, revoked]
    by_id = {e.id: e for e in entries}
    assert (by_id[soon].state, by_id[soon].days_left, by_id[soon].covers) == ("active", 3, 2)
    assert by_id[later].context is None and by_id[later].covers == 1  # a runs in web; counted though api is not covered
    assert by_id[nothing].covers == 0
    assert (by_id[expired].state, by_id[expired].days_left) == ("expired", -1)
    assert by_id[revoked].state == "revoked" and by_id[revoked].revoked_at == NOW
    assert by_id[soon].reason == "not reachable" and by_id[soon].owner == "me" and by_id[soon].created_at == NOW
    assert [e.id for e in accepted.register(conn, "ctx", run_id, TODAY, vuln_id="CVE-2")] == [later]
    assert {e.covers for e in accepted.register(conn, "ctx", None, TODAY)} == {None}  # no run to count in


def test_add_rejects_what_the_form_must_not_store(db):
    conn, _ = db
    with pytest.raises(ValueError, match="CVE"):
        _accept(conn, " ")
    with pytest.raises(ValueError, match="reason"):
        accepted.add(conn, vuln_id="CVE-1", reason="", owner="me", expires=TODAY, context=None, now=NOW)
    with pytest.raises(ValueError, match="owner"):
        accepted.add(conn, vuln_id="CVE-1", reason="r", owner=" ", expires=TODAY, context=None, now=NOW)
    with pytest.raises(ValueError, match="past"):
        accepted.add(conn, vuln_id="CVE-1", reason="r", owner="me", expires=date(2026, 2, 28), context=None, now=NOW)
    blank = _accept(conn, namespace="", repo=" ", pkg_name="")
    assert accepted.register(conn, "ctx", None, TODAY)[0].id == blank
    entry = accepted.register(conn, "ctx", None, TODAY)[0]
    assert (entry.namespace, entry.repo, entry.pkg_name) == (None, None, None)  # blank means anywhere
