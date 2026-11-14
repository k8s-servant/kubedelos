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
    FindingFilter,
    RunNotShown,
    auth_failed_refs,
    failed_images,
    findings_page,
    fix_by_fix,
    fix_by_image,
    get_run,
    kpis,
    newest_run,
    previous_comparable,
    run_namespaces,
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


def _seed_units(repo, run_id):
    """Three finding units: CVE-1 on image a (two targets, two platforms), CVE-2 and CVE-3 on image b."""
    _add_findings(
        repo, run_id, "a", "linux/amd64", [_finding("CVE-1", "CRITICAL"), _finding("CVE-1", "CRITICAL", "jar")]
    )
    _add_findings(repo, run_id, "a", "linux/arm64", [_finding("CVE-1", "CRITICAL")])
    _add_findings(repo, run_id, "b", "linux/amd64", [_finding("CVE-2", "HIGH"), _finding("CVE-3", "LOW")])


def test_kpis_counting_units(db):
    conn, repo = db
    run_id = _run(repo)
    _seed_units(repo, run_id)
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


def _fx(vuln, sev, pkg="openssl", version="1.1", fixed="1.2", url=None):
    return Finding(
        vuln_id=vuln,
        pkg_name=pkg,
        installed_version=version,
        fixed_version=fixed,
        severity=Severity(sev),
        target="os",
        pkg_type="os",
        primary_url=url,
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
    fixes = fix_by_fix(conn, run_id)
    rows, total = fixes.rows, fixes.total
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
    fixes = fix_by_fix(conn, run_id)
    rows, total = fixes.rows, fixes.total
    assert total == 4
    # Critical first, then more images, then (equal images) more namespaces, then fewer images
    assert rows[0].vuln_id == "CVE-C"
    assert [r.vuln_id for r in rows[1:]] == ["CVE-T2", "CVE-H", "CVE-T1"]
    many = _run(repo)
    for i in range(30):
        _add_in(repo, many, f"i{i}", [_fx(f"CVE-{i:02d}", "HIGH")])
    fixes = fix_by_fix(conn, many, limit=25)
    rows, total = fixes.rows, fixes.total
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
    fixes = fix_by_fix(conn, run_id)
    rows, total = fixes.rows, fixes.total
    assert [r.vuln_id for r in rows] == ["CVE-OK"] and total == 1
    fixes = fix_by_image(conn, run_id)
    images, total = fixes.rows, fixes.total
    assert [(r.ref, r.critical, r.high, r.fixable) for r in images] == [("a", 0, 3, 1)] and total == 1
    _add_in(repo, run_id, "b", [_fx("CVE-M", "MEDIUM"), _fx("CVE-N", "CRITICAL", fixed=None)])
    assert fix_by_image(conn, run_id).total == 1


def test_installed_versions_distinct_sorted(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(repo, run_id, "a", [_fx("CVE-1", "HIGH", version="1.1.0")])
    _add_in(repo, run_id, "b", [_fx("CVE-1", "HIGH", version="1.0.9")])
    _add_in(repo, run_id, "c", [_fx("CVE-1", "HIGH", version="1.1.0")])
    rows = fix_by_fix(conn, run_id).rows
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
    fixes = fix_by_image(conn, run_id)
    rows, total = fixes.rows, fixes.total
    assert total == 4
    assert [(r.ref, r.critical, r.high, r.fixable) for r in rows] == [
        ("z-crit", 2, 1, 2),
        ("a-high", 0, 2, 2),
        ("b-high", 0, 2, 2),
        ("z-arm", 0, 1, 1),
    ]
    assert rows[0].namespaces == ["a", "b"]
    assert len(fix_by_image(conn, run_id, limit=2).rows) == 2


def test_fix_lists_count_the_units_with_no_fix(db):
    conn, repo = db
    run_id = _run(repo)
    for fixes in (fix_by_fix(conn, run_id), fix_by_image(conn, run_id)):
        assert (fixes.rows, fixes.total, fixes.no_fix, fixes.no_fix_images) == ([], 0, 0, 0)
    _add_in(repo, run_id, "a", [_fx("CVE-1", "HIGH", fixed=None), _fx("CVE-2", "CRITICAL", fixed="")])
    _add_in(
        repo, run_id, "b", [_fx("CVE-1", "HIGH", fixed=None), _fx("CVE-3", "HIGH"), _fx("CVE-4", "LOW", fixed=None)]
    )
    for fixes in (fix_by_fix(conn, run_id), fix_by_image(conn, run_id)):
        assert (fixes.total, fixes.no_fix, fixes.no_fix_images) == (1, 3, 2)
    # No fixable unit at all still reports the units without one.
    only = _run(repo)
    _add_in(repo, only, "c", [_fx("CVE-1", "HIGH", fixed=None)])
    for fixes in (fix_by_fix(conn, only), fix_by_image(conn, only)):
        assert (fixes.rows, fixes.total, fixes.no_fix, fixes.no_fix_images) == ([], 0, 1, 1)


def test_fix_by_fix_link_is_the_groups_highest_url(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(repo, run_id, "a", [_fx("CVE-1", "HIGH", url="https://example.com/a")])
    _add_in(repo, run_id, "b", [_fx("CVE-1", "HIGH", url="https://example.com/b")])
    _add_in(repo, run_id, "c", [_fx("CVE-2", "HIGH")])
    rows = fix_by_fix(conn, run_id).rows
    assert [(r.vuln_id, r.primary_url) for r in rows] == [("CVE-1", "https://example.com/b"), ("CVE-2", None)]


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


def test_auth_failed_refs_ignores_other_failures(db):
    conn, repo = db
    run_id = _run(repo)
    for i in range(30):
        _add(repo, run_id, f"reg.example.com/app{i:02d}:1", "linux/amd64", status="error")
    assert auth_failed_refs(conn, run_id) == []


def _fk(vuln, sev, *, pkg="openssl", version="1", fixed=None, pkg_class=None):
    return Finding(
        vuln_id=vuln,
        pkg_name=pkg,
        installed_version=version,
        fixed_version=fixed,
        severity=Severity(sev),
        target="t",
        pkg_type="os",
        pkg_class=pkg_class,
    )


def _page(conn, run_id, **filters):
    rows, total = findings_page(conn, run_id, FindingFilter(**filters), 1)
    return [(r["ref"], r["vuln_id"]) for r in rows], total


def test_findings_page_units_and_total(db):
    conn, repo = db
    run_id = _run(repo)
    _seed_units(repo, run_id)
    rows, total = findings_page(conn, run_id, FindingFilter(), 1)
    assert total == 3
    assert [(r["ref"], r["vuln_id"], r["severity"]) for r in rows] == [
        ("a", "CVE-1", "CRITICAL"),
        ("b", "CVE-2", "HIGH"),
        ("b", "CVE-3", "LOW"),
    ]
    assert rows[0]["targets"].split(",").__len__() == 2
    assert rows[0]["namespaces"] == '["ns"]'


def _filter_dataset(repo, run_id):
    _add_in(
        repo, run_id, "web-img",
        [
            _fk("CVE-1", "CRITICAL", fixed="2", pkg_class="os"),
            _fk("CVE-2", "LOW", pkg="requests", pkg_class="library"),
            _fk("CVE-3", "MEDIUM", pkg="zlib"),
        ],
        namespaces=("web",),
    )  # fmt: skip
    _add_in(repo, run_id, "db-img", [_fk("CVE-1", "CRITICAL", fixed="2", pkg_class="os")], namespaces=("db", "web"))


def test_findings_filters(db):
    conn, repo = db
    run_id = _run(repo)
    _filter_dataset(repo, run_id)
    assert _page(conn, run_id)[1] == 4
    assert _page(conn, run_id, severities=("CRITICAL",))[1] == 2
    assert _page(conn, run_id, severities=("LOW", "MEDIUM"))[1] == 2
    assert _page(conn, run_id, namespace="db") == ([("db-img", "CVE-1")], 1)
    assert _page(conn, run_id, namespace="web")[1] == 4
    assert _page(conn, run_id, namespace="nope")[1] == 0
    assert _page(conn, run_id, cve="CVE-2") == ([("web-img", "CVE-2")], 1)
    assert _page(conn, run_id, package="zlib") == ([("web-img", "CVE-3")], 1)
    assert _page(conn, run_id, has_fix="yes")[1] == 2
    assert _page(conn, run_id, has_fix="no")[1] == 2
    assert _page(conn, run_id, has_fix="any")[1] == 4
    assert _page(conn, run_id, pkg="os")[1] == 2
    assert _page(conn, run_id, pkg="library") == ([("web-img", "CVE-2")], 1)
    assert _page(conn, run_id, pkg="all")[1] == 4  # NULL pkg_class (CVE-3) shows only here
    assert _page(conn, run_id, q="db-")[1] == 1
    assert _page(conn, run_id, q="cve-3")[1] == 1
    assert _page(conn, run_id, q="requests")[1] == 1
    assert _page(conn, run_id, severities=("CRITICAL",), has_fix="yes", namespace="db")[1] == 1


def test_findings_namespaces_column_lists_every_namespace(db):
    conn, repo = db
    run_id = _run(repo)
    _filter_dataset(repo, run_id)
    rows, _ = findings_page(conn, run_id, FindingFilter(q="db-img"), 1)
    assert rows[0]["namespaces"] == '["db","web"]'
    assert run_namespaces(conn, run_id) == ["db", "web"]


def test_findings_sort_each_key_and_direction(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(
        repo, run_id, "b-img", [_fk("CVE-2", "LOW", pkg="aaa", fixed="9"), _fk("CVE-9", "HIGH", pkg="ccc")], ("zz",)
    )
    _add_in(repo, run_id, "a-img", [_fk("CVE-5", "MEDIUM", pkg="bbb", fixed="3")], ("mm", "aa"))

    def order(sort, desc):
        rows, _ = findings_page(conn, run_id, FindingFilter(sort=sort, desc=desc), 1)
        return [r["vuln_id"] for r in rows]

    assert order("severity", True) == ["CVE-9", "CVE-5", "CVE-2"]
    assert order("severity", False) == ["CVE-2", "CVE-5", "CVE-9"]
    assert order("cve", False) == ["CVE-2", "CVE-5", "CVE-9"]
    assert order("cve", True) == ["CVE-9", "CVE-5", "CVE-2"]
    assert order("package", False) == ["CVE-2", "CVE-5", "CVE-9"]
    assert order("package", True) == ["CVE-9", "CVE-5", "CVE-2"]
    assert order("image", False) == ["CVE-5", "CVE-2", "CVE-9"]
    assert order("image", True) == ["CVE-2", "CVE-9", "CVE-5"]
    assert order("namespace", False) == ["CVE-5", "CVE-2", "CVE-9"]  # a-img's smallest namespace is aa
    assert order("namespace", True) == ["CVE-2", "CVE-9", "CVE-5"]
    assert order("fixed", False) == ["CVE-5", "CVE-2", "CVE-9"]  # a fix is never sorted after its absence
    assert order("fixed", True) == ["CVE-2", "CVE-5", "CVE-9"]


def test_findings_default_order_breaks_ties_by_cve_then_image(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(repo, run_id, "y", [_fk("CVE-2", "HIGH"), _fk("CVE-1", "HIGH")])
    _add_in(repo, run_id, "x", [_fk("CVE-2", "HIGH")])
    assert _page(conn, run_id)[0] == [("y", "CVE-1"), ("x", "CVE-2"), ("y", "CVE-2")]


def test_findings_paging_total_matches_rows(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(repo, run_id, "big", [_fk(f"CVE-{i:03}", "HIGH") for i in range(250)])
    sizes = []
    for page in (1, 2, 3):
        rows, total = findings_page(conn, run_id, FindingFilter(), page)
        sizes.append((len(rows), total))
    assert sizes == [(100, 250), (100, 250), (50, 250)]
    rows, total = findings_page(conn, run_id, FindingFilter(), 4)
    assert (rows, total) == ([], 250)
    rows, total = findings_page(conn, run_id, FindingFilter(), 1, per_page=10)
    assert (len(rows), total) == (10, 250)


def test_q_matches_wildcards_literally(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(
        repo, run_id, "img",
        [_fk("CVE-1", "LOW", pkg="lib_a"), _fk("CVE-2", "LOW", pkg="libxa"), _fk("CVE-3", "LOW", pkg="100%")],
    )  # fmt: skip
    assert _page(conn, run_id, q="_a") == ([("img", "CVE-1")], 1)
    assert _page(conn, run_id, q="%") == ([("img", "CVE-3")], 1)
    assert _page(conn, run_id, q="\\")[1] == 0


def test_findings_page_other_runs_do_not_leak(db):
    conn, repo = db
    first = _run(repo)
    _add_in(repo, first, "old", [_fk("CVE-1", "LOW")])
    second = _run(repo)
    _add_in(repo, second, "new", [_fk("CVE-2", "LOW")], namespaces=("other",))
    assert _page(conn, second) == ([("new", "CVE-2")], 1)
    assert _page(conn, second, namespace="ns")[1] == 0
    assert run_namespaces(conn, second) == ["other"]


def __keys(rows):
    return [(r["ref"], r["vuln_id"], r["pkg_name"], r["installed_version"]) for r in rows]


def _keys(rows):
    return [(r["ref"], r["vuln_id"], r["pkg_name"], r["installed_version"]) for r in rows]


def test_findings_deep_pages_follow_the_same_order_in_every_sort(db):
    conn, repo = db
    run_id = _run(repo)
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for n, ns in enumerate(("zz", "aa", "mm")):
        findings = [
            _fk(f"CVE-{i % 40:03}", sevs[i % 4], pkg=f"p{i % 7}", version=str(i), fixed="2" if i % 3 else None)
            for i in range(90)
        ]
        _add_in(repo, run_id, f"img{n}", findings, namespaces=(ns,))
    for sort in ("severity", "cve", "package", "image", "namespace", "fixed"):
        for desc in (True, False):
            f = FindingFilter(sort=sort, desc=desc)
            whole, total = findings_page(conn, run_id, f, 1, per_page=1000)
            assert total == 270
            paged = []
            for page in (1, 2, 3, 4, 5):
                rows, page_total = findings_page(conn, run_id, f, page, per_page=60)
                assert page_total == 270
                paged += _keys(rows)
            assert paged == _keys(whole), (sort, desc)
            assert len(set(paged)) == 270


def test_findings_page_rows_match_finding_units(db):
    conn, repo = db
    run_id = _run(repo)
    _seed_units(repo, run_id)
    units = conn.execute(f"WITH u AS ({FINDING_UNITS_SQL}) SELECT * FROM u", {"run": run_id}).fetchall()  # noqa: S608
    rows, _ = findings_page(conn, run_id, FindingFilter(), 1)
    columns = units[0].keys()
    got = {tuple(r[c] for c in columns) for r in rows}
    assert got == {tuple(u[c] for c in columns) for u in units}
