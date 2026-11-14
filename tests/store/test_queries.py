import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from kubedelos.config import Settings
from kubedelos.kube.inventory import InventoryWarning
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.store.db import connect
from kubedelos.store.queries import (
    CLUSTER_SCOPE_SQL,
    FINDING_UNITS_SQL,
    RESULT_STATUSES,
    RunNotShown,
    failed_images,
    fix_by_fix,
    fix_by_image,
    get_run,
    kpis,
    newest_run,
    no_fix_summary,
    previous_comparable,
)
from kubedelos.store.repo import Repo

_OPEN: list[sqlite3.Connection] = []
CLUSTER = Settings().scope


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    while _OPEN:
        _OPEN.pop().close()


class Clock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self):
        self.now += timedelta(minutes=1)
        return self.now


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "k.db")
    _OPEN.append(conn)
    return conn, Repo(conn, clock=Clock())


def _run(repo, status="ok", *, context="ctx", scope=CLUSTER, level="library,os"):
    run_id = repo.start_run(context, "cli", "0.76.1", scan_level=level, scope=scope)
    if status != "running":
        repo.finish_run(run_id, status)
    return run_id


def _scope(**kw):
    return Settings(**kw).scope


def _add(repo, run_id, ref, platform, status="ok"):
    image = ImageRef(ref=ref, repo="reg.example.com/app", tag="1", digest="sha256:" + "a" * 64)
    item = InventoryItem(
        image=image, platform=platform, workloads=[Workload(namespace="ns", kind="Deployment", name="a", container="c")]
    )
    repo.add_result(run_id, item, ImageResult(image=image, platform=platform, status=status, findings=[]))


def test_constants():
    assert RESULT_STATUSES == ("ok", "partial")
    assert "json_array_length" in CLUSTER_SCOPE_SQL


def test_newest_run_none(db):
    conn, _ = db
    assert newest_run(conn, "ctx", cluster_scope=False) is None
    assert newest_run(conn, "ctx", cluster_scope=True) is None


def test_newest_cluster_run_skips_narrower(db):
    conn, repo = db
    first = _run(repo)
    second = _run(repo, scope=_scope(namespaces=["web"]))
    assert newest_run(conn, "ctx", cluster_scope=True).id == first
    assert newest_run(conn, "ctx", cluster_scope=False).id == second


def test_newest_run_skips_failed_cancelled_running_and_other_context(db):
    conn, repo = db
    good = _run(repo, "partial")
    _run(repo, "failed")
    _run(repo, "cancelled")
    _run(repo, "running")
    _run(repo, context="other")
    run = newest_run(conn, "ctx", cluster_scope=False)
    assert run.id == good
    assert run.status == "partial"
    assert run.context == "ctx"
    assert run.finished_at is not None and run.finished_at.tzinfo is not None
    assert run.pkg_types == "library,os"
    assert run.scope["namespaces"] == []


def test_exclusions_still_cluster_scope(db):
    conn, repo = db
    run_id = _run(repo, scope=_scope(exclude_images=["busybox:*"], exclude_namespaces=["kube-system"]))
    assert newest_run(conn, "ctx", cluster_scope=True).id == run_id


def test_null_scope_never_cluster(db):
    conn, repo = db
    run_id = _run(repo, scope=None)
    assert newest_run(conn, "ctx", cluster_scope=True) is None
    run = newest_run(conn, "ctx", cluster_scope=False)
    assert run.id == run_id and run.scope is None


def test_get_run_reasons(db):
    conn, repo = db
    ok = _run(repo)
    failed = _run(repo, "failed")
    other = _run(repo, context="other")
    assert get_run(conn, "ctx", ok).id == ok
    with pytest.raises(RunNotShown) as exc:
        get_run(conn, "ctx", 999)
    assert exc.value.reason == "no run 999"
    with pytest.raises(RunNotShown) as exc:
        get_run(conn, "ctx", other)
    assert exc.value.reason == f"run {other} belongs to context other, not ctx"
    with pytest.raises(RunNotShown) as exc:
        get_run(conn, "ctx", failed)
    assert exc.value.reason == f"run {failed} is failed, so it has no results to show"


def test_run_counts_distinct_refs(db):
    conn, repo = db
    run_id = repo.start_run("ctx", "cli", "0.76.1", scan_level="os", scope=CLUSTER)
    _add(repo, run_id, "reg.example.com/app:1", "linux/amd64", "ok")
    _add(repo, run_id, "reg.example.com/app:1", "linux/arm64", "error")
    _add(repo, run_id, "reg.example.com/app:2", "linux/amd64", "cached")
    repo.finish_run(run_id, "partial")
    run = get_run(conn, "ctx", run_id)
    assert (run.images, run.images_failed) == (2, 1)


def test_run_gaps(db):
    conn, repo = db
    run_id = _run(repo)
    repo.add_warnings(
        run_id,
        [
            InventoryWarning("skipped pods in namespace a: forbidden", coverage=True),
            InventoryWarning("no owner info", coverage=False),
            InventoryWarning("skipped jobs in namespace b: forbidden", coverage=True),
        ],
    )
    assert get_run(conn, "ctx", run_id).gaps == [
        "skipped pods in namespace a: forbidden",
        "skipped jobs in namespace b: forbidden",
    ]


def test_previous_comparable(db):
    conn, repo = db
    first = _run(repo)
    _run(repo, scope=_scope(namespaces=["web"]))
    _run(repo, level="os")
    _run(repo, "failed")
    _run(repo, scope=None)
    _run(repo, context="other")
    current = _run(repo)
    assert previous_comparable(conn, get_run(conn, "ctx", first)) is None
    assert previous_comparable(conn, get_run(conn, "ctx", current)).id == first
    newer = _run(repo)
    assert previous_comparable(conn, get_run(conn, "ctx", newer)).id == current


def test_null_scope_run_has_no_comparable(db):
    conn, repo = db
    _run(repo, scope=None)
    second = _run(repo, scope=None)
    assert previous_comparable(conn, get_run(conn, "ctx", second)) is None


def _finding(vuln, sev, target="os", pkg="openssl", version="1"):
    return Finding(
        vuln_id=vuln, pkg_name=pkg, installed_version=version, severity=Severity(sev), target=target, pkg_type="os"
    )


def _add_findings(repo, run_id, ref, platform, findings):
    image = ImageRef(ref=ref, repo="reg.example.com/app", tag="1", digest="sha256:" + ref * 64)
    item = InventoryItem(
        image=image, platform=platform, workloads=[Workload(namespace="ns", kind="Deployment", name="a", container="c")]
    )
    repo.add_result(run_id, item, ImageResult(image=image, platform=platform, status="ok", findings=findings))


def test_kpis_counting_units(db):
    conn, repo = db
    run_id = _run(repo)
    _add_findings(
        repo, run_id, "a", "linux/amd64", [_finding("CVE-1", "CRITICAL"), _finding("CVE-1", "CRITICAL", "jar")]
    )
    _add_findings(repo, run_id, "a", "linux/arm64", [_finding("CVE-1", "CRITICAL")])
    _add_findings(repo, run_id, "b", "linux/amd64", [_finding("CVE-2", "HIGH"), _finding("CVE-3", "LOW")])
    _add(repo, run_id, "c", "linux/amd64", status="error")
    got = kpis(conn, run_id)
    assert (got.critical, got.high, got.images, got.images_with_critical, got.findings) == (1, 1, 3, 1, 3)
    assert got.images_failed == 1
    assert got.by_severity == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "UNKNOWN": 0}


def test_kpis_duplicate_with_disagreeing_severity_takes_the_highest(db):
    conn, repo = db
    run_id = _run(repo)
    _add_findings(repo, run_id, "a", "linux/amd64", [_finding("CVE-1", "LOW")])
    _add_findings(repo, run_id, "a", "linux/arm64", [_finding("CVE-1", "HIGH")])
    got = kpis(conn, run_id)
    assert (got.high, got.findings, got.by_severity["LOW"]) == (1, 1, 0)


def test_kpis_empty_run(db):
    conn, repo = db
    got = kpis(conn, _run(repo))
    assert (got.findings, got.images, got.critical) == (0, 0, 0)
    assert set(got.by_severity) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def test_kpis_agree_with_finding_units(db):
    conn, repo = db
    run_id = _run(repo)
    _add_findings(
        repo, run_id, "a", "linux/amd64", [_finding("CVE-1", "CRITICAL"), _finding("CVE-1", "CRITICAL", "jar")]
    )
    _add_findings(repo, run_id, "a", "linux/arm64", [_finding("CVE-1", "LOW")])
    _add_findings(repo, run_id, "b", "linux/amd64", [_finding("CVE-2", "HIGH"), _finding("CVE-3", "LOW")])
    rows = conn.execute(
        f"WITH units AS ({FINDING_UNITS_SQL}) SELECT severity, COUNT(*) AS n FROM units GROUP BY severity",  # noqa: S608
        {"run": run_id},
    ).fetchall()
    expected = {r["severity"]: r["n"] for r in rows}
    got = {k: v for k, v in kpis(conn, run_id).by_severity.items() if v}
    assert got == expected


def test_same_ref_with_differing_tag_and_digest_is_one_unit(db):
    conn, repo = db
    run_id = _run(repo)
    for platform, tag, digest in (
        ("linux/amd64", "1", "sha256:" + "a" * 64),
        ("linux/arm64", "2", "sha256:" + "b" * 64),
    ):
        image = ImageRef(ref="same", repo="reg.example.com/app", tag=tag, digest=digest)
        item = InventoryItem(image=image, platform=platform, workloads=[])
        result = ImageResult(image=image, platform=platform, status="ok", findings=[_finding("CVE-1", "HIGH")])
        repo.add_result(run_id, item, result)
    rows = conn.execute(f"WITH units AS ({FINDING_UNITS_SQL}) SELECT * FROM units", {"run": run_id}).fetchall()  # noqa: S608
    assert len(rows) == 1


def _fx(vuln, sev, pkg="openssl", version="1.1", fixed="1.2"):
    return Finding(
        vuln_id=vuln,
        pkg_name=pkg,
        installed_version=version,
        fixed_version=fixed,
        severity=Severity(sev),
        target="os",
        pkg_type="os",
    )


def _add_in(repo, run_id, ref, findings, namespaces=("ns",), platform="linux/amd64"):
    image = ImageRef(ref=ref, repo="reg.example.com/app", tag="1", digest="sha256:" + "a" * 64)
    workloads = [Workload(namespace=ns, kind="Deployment", name="a", container="c") for ns in namespaces]
    item = InventoryItem(image=image, platform=platform, workloads=workloads)
    repo.add_result(run_id, item, ImageResult(image=image, platform=platform, status="ok", findings=findings))


def test_fix_by_fix_groups_one_base_image_rebuild(db):
    conn, repo = db
    run_id = _run(repo)
    for i in range(30):
        _add_in(repo, run_id, f"img{i:02d}", [_fx("CVE-9", "CRITICAL")], namespaces=("b", "a"))
    _add_in(repo, run_id, "solo", [_fx("CVE-8", "CRITICAL")])
    rows, total = fix_by_fix(conn, run_id)
    assert total == 2 and [r.vuln_id for r in rows] == ["CVE-9", "CVE-8"]
    top = rows[0]
    assert (top.pkg_name, top.fixed_version, top.severity, top.images, top.namespaces) == (
        "openssl",
        "1.2",
        "CRITICAL",
        30,
        2,
    )
    assert len(top.sample) == 20
    assert top.sample[0] == ("img00", ["a", "b"])
    assert [ref for ref, _ in top.sample] == sorted(ref for ref, _ in top.sample)


def test_fix_by_fix_sort_and_total(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(repo, run_id, "h1", [_fx("CVE-H", "HIGH", pkg="a")], namespaces=("x",))
    _add_in(repo, run_id, "h2", [_fx("CVE-H", "HIGH", pkg="a")], namespaces=("x",))
    _add_in(repo, run_id, "c1", [_fx("CVE-C", "CRITICAL", pkg="b")], namespaces=("x",))
    _add_in(repo, run_id, "t1", [_fx("CVE-T1", "HIGH", pkg="c")], namespaces=("x", "y"))
    _add_in(repo, run_id, "t2", [_fx("CVE-T2", "HIGH", pkg="d")], namespaces=("x", "y"))
    _add_in(repo, run_id, "t3", [_fx("CVE-T2", "HIGH", pkg="d")], namespaces=("x",))
    rows, total = fix_by_fix(conn, run_id)
    assert total == 4
    # Critical first, then more images, then (equal images) more namespaces, then fewer images
    assert rows[0].vuln_id == "CVE-C"
    assert [r.vuln_id for r in rows[1:]] == ["CVE-T2", "CVE-H", "CVE-T1"]
    many = _run(repo)
    for i in range(30):
        _add_in(repo, many, f"i{i}", [_fx(f"CVE-{i:02d}", "HIGH")])
    rows, total = fix_by_fix(conn, many, limit=25)
    assert len(rows) == 25 and total == 30


def test_fix_lists_skip_unfixed_medium_and_low(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(
        repo,
        run_id,
        "a",
        [
            _fx("CVE-M", "MEDIUM"),
            _fx("CVE-L", "LOW"),
            _fx("CVE-N", "HIGH", fixed=None),
            _fx("CVE-E", "HIGH", fixed=""),
            _fx("CVE-OK", "HIGH"),
        ],
    )
    rows, total = fix_by_fix(conn, run_id)
    assert [r.vuln_id for r in rows] == ["CVE-OK"] and total == 1
    images, total = fix_by_image(conn, run_id)
    assert [(r.ref, r.critical, r.high, r.fixable) for r in images] == [("a", 0, 3, 1)] and total == 1
    _add_in(repo, run_id, "b", [_fx("CVE-M", "MEDIUM"), _fx("CVE-N", "CRITICAL", fixed=None)])
    assert fix_by_image(conn, run_id)[1] == 1


def test_installed_versions_distinct_sorted(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(repo, run_id, "a", [_fx("CVE-1", "HIGH", version="1.1.0")])
    _add_in(repo, run_id, "b", [_fx("CVE-1", "HIGH", version="1.0.9")])
    _add_in(repo, run_id, "c", [_fx("CVE-1", "HIGH", version="1.1.0")])
    rows, _ = fix_by_fix(conn, run_id)
    assert rows[0].installed == ["1.0.9", "1.1.0"] and rows[0].images == 3


def test_fix_by_image_counts_and_sort(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(
        repo,
        run_id,
        "z-crit",
        [_fx("CVE-1", "CRITICAL"), _fx("CVE-2", "CRITICAL", fixed=None), _fx("CVE-3", "HIGH")],
        namespaces=("b", "a"),
    )
    _add_in(repo, run_id, "b-high", [_fx("CVE-4", "HIGH"), _fx("CVE-5", "HIGH")])
    _add_in(repo, run_id, "a-high", [_fx("CVE-4", "HIGH"), _fx("CVE-5", "HIGH")])
    _add_in(repo, run_id, "z-arm", [_fx("CVE-6", "HIGH")], platform="linux/arm64")
    _add_in(repo, run_id, "z-arm", [_fx("CVE-6", "HIGH")], platform="linux/amd64")
    rows, total = fix_by_image(conn, run_id)
    assert total == 4
    assert [(r.ref, r.critical, r.high, r.fixable) for r in rows] == [
        ("z-crit", 2, 1, 2),
        ("a-high", 0, 2, 2),
        ("b-high", 0, 2, 2),
        ("z-arm", 0, 1, 1),
    ]
    assert rows[0].namespaces == ["a", "b"]
    assert len(fix_by_image(conn, run_id, limit=2)[0]) == 2


def test_no_fix_summary(db):
    conn, repo = db
    run_id = _run(repo)
    assert no_fix_summary(conn, run_id) == (0, 0)
    _add_in(repo, run_id, "a", [_fx("CVE-1", "HIGH", fixed=None), _fx("CVE-2", "CRITICAL", fixed="")])
    _add_in(
        repo, run_id, "b", [_fx("CVE-1", "HIGH", fixed=None), _fx("CVE-3", "HIGH"), _fx("CVE-4", "LOW", fixed=None)]
    )
    assert no_fix_summary(conn, run_id) == (3, 2)


def test_failed_images_cap_and_total(db):
    conn, repo = db
    run_id = _run(repo)
    _add(repo, run_id, "ok-image", "linux/amd64")
    for i in range(30):
        _add(repo, run_id, f"reg.example.com/app{i:02d}:1", "linux/amd64", status="error")
    _add(repo, run_id, "reg.example.com/app00:1", "linux/arm64", status="error")
    rows, total = failed_images(conn, run_id, limit=25)
    assert total == 31
    assert len(rows) == 25
    assert [(r["ref"], r["platform"]) for r in rows[:2]] == [
        ("reg.example.com/app00:1", "linux/amd64"),
        ("reg.example.com/app00:1", "linux/arm64"),
    ]
    assert set(rows[0].keys()) == {"ref", "platform", "error_kind", "error"}
    assert failed_images(conn, run_id)[1] == 31
