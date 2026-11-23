import pytest

from kubedelos.config import Settings
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.store import diff
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo

CLUSTER = Settings().scope


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "k.db")
    yield conn, Repo(conn)
    conn.close()


def _run(repo):
    run_id = repo.start_run("ctx", "ctx", "ui", "0.76.1", scan_level="library,os", scope=CLUSTER)
    repo.finish_run(run_id, "ok")
    return run_id


def _add(repo, run_id, ref, vulns=(), *, status="ok", platform="linux/amd64"):
    """``ref`` is ``<repository>:<tag>``; ``vulns`` are (CVE, severity) or (CVE, severity, package, fixed)."""
    name, tag = ref.rsplit(":", 1)
    image = ImageRef(ref=ref, repo=name, tag=tag, digest=None)
    findings = []
    for v in vulns:
        vuln, sev, pkg, fixed = (*v, "openssl", "2")[:4] if len(v) == 2 else v
        findings.append(
            Finding(
                vuln_id=vuln,
                pkg_name=pkg,
                installed_version="1",
                fixed_version=fixed,
                severity=Severity(sev),
                target="t",
                pkg_type="os",
            )
        )
    item = InventoryItem(
        image=image, platform=platform, workloads=[Workload(namespace="ns", kind="Deployment", name="w", container="c")]
    )
    result = ImageResult(
        image=image,
        platform=platform,
        status=status,
        findings=findings,
        error_kind="trivy" if status == "error" else None,
    )
    repo.add_result(run_id, item, result)


def test_a_tag_bump_keeps_its_open_findings_open(db):
    conn, repo = db
    old, new = _run(repo), _run(repo)
    _add(repo, old, "reg.example.com/app:1.2", [("CVE-1", "HIGH"), ("CVE-2", "CRITICAL")])
    _add(repo, new, "reg.example.com/app:1.3", [("CVE-1", "HIGH"), ("CVE-3", "LOW")])
    d = diff.compare(conn, old, new)
    assert (d.new_total, d.gone_total, d.still_open) == (1, 1, 1)
    assert [(f.vuln_id, f.severity, f.image_gone) for f in d.new] == [("CVE-3", "LOW", False)]
    assert [(f.vuln_id, f.severity, f.image_gone) for f in d.gone] == [("CVE-2", "CRITICAL", False)]
    assert [(c.repo, c.refs_from, c.refs_to) for c in d.images_changed] == [
        ("reg.example.com/app", ["reg.example.com/app:1.2"], ["reg.example.com/app:1.3"])
    ]
    assert d.images_added == [] and d.images_gone == []


def test_added_and_gone_images_and_their_findings(db):
    conn, repo = db
    old, new = _run(repo), _run(repo)
    _add(repo, old, "reg.example.com/keep:1", [("CVE-1", "LOW")])
    _add(repo, new, "reg.example.com/keep:1", [("CVE-1", "LOW")])
    _add(repo, old, "reg.example.com/old:1", [("CVE-9", "CRITICAL")])
    _add(repo, new, "reg.example.com/fresh:1", [("CVE-8", "MEDIUM")])
    d = diff.compare(conn, old, new)
    assert [i.repo for i in d.images_added] == ["reg.example.com/fresh"]
    assert [i.repo for i in d.images_gone] == ["reg.example.com/old"]
    assert d.images_changed == [] and d.images_unchanged == 1
    assert (d.images_added_total, d.images_gone_total, d.images_changed_total) == (1, 1, 0)
    assert [(f.vuln_id, f.image_gone) for f in d.gone] == [("CVE-9", True)]
    assert [f.repo for f in d.new] == ["reg.example.com/fresh"]


def test_the_package_is_part_of_the_key_and_platforms_count_once(db):
    conn, repo = db
    old, new = _run(repo), _run(repo)
    _add(repo, old, "reg.example.com/app:1", [("CVE-1", "HIGH", "openssl", "2")])
    _add(repo, new, "reg.example.com/app:1", [("CVE-1", "HIGH", "libssl", "2")])
    _add(repo, new, "reg.example.com/app:1", [("CVE-1", "HIGH", "libssl", "2")], platform="linux/arm64")
    d = diff.compare(conn, old, new)
    assert [(f.pkg_name, f.images) for f in d.new] == [("libssl", 1)]
    assert [f.pkg_name for f in d.gone] == ["openssl"]


def test_tables_go_worst_first_and_are_capped_with_the_real_total(db):
    conn, repo = db
    old, new = _run(repo), _run(repo)
    _add(repo, old, "reg.example.com/app:1")
    _add(repo, new, "reg.example.com/app:1", [(f"CVE-{i:03}", "LOW") for i in range(6)] + [("CVE-X", "CRITICAL")])
    _add(repo, new, "reg.example.com/two:1", [("CVE-000", "LOW")])
    d = diff.compare(conn, old, new, limit=3)
    assert d.new_total == 8 and len(d.new) == 3
    assert [(f.vuln_id, f.repo) for f in d.new[:2]] == [
        ("CVE-X", "reg.example.com/app"),
        ("CVE-000", "reg.example.com/app"),
    ]


def test_a_failed_image_keeps_its_place_in_the_image_list(db):
    conn, repo = db
    old, new = _run(repo), _run(repo)
    _add(repo, old, "reg.example.com/app:1", [("CVE-1", "HIGH")])
    _add(repo, new, "reg.example.com/app:1", status="error")
    d = diff.compare(conn, old, new)
    assert d.images_unchanged == 1 and d.images_gone == []  # it still runs; it failed to scan
    assert [(f.vuln_id, f.image_gone) for f in d.gone] == [("CVE-1", False)]


def test_runs_of_other_runs_are_not_read(db):
    conn, repo = db
    old, other, new = _run(repo), _run(repo), _run(repo)
    _add(repo, other, "reg.example.com/noise:1", [("CVE-N", "CRITICAL")])
    _add(repo, old, "reg.example.com/app:1", [("CVE-1", "HIGH")])
    _add(repo, new, "reg.example.com/app:1", [("CVE-1", "HIGH")])
    d = diff.compare(conn, old, new)
    assert (d.new_total, d.gone_total, d.still_open, d.images_unchanged) == (0, 0, 1, 1)


def test_identical_runs_have_no_changes_but_count_what_stays_open(db):
    conn, repo = db
    old, new = _run(repo), _run(repo)
    for run_id in (old, new):
        _add(repo, run_id, "reg.example.com/app:1", [("CVE-1", "HIGH"), ("CVE-2", "LOW")])
    d = diff.compare(conn, old, new)
    assert (d.new_total, d.gone_total, d.still_open, d.new, d.gone) == (0, 0, 2, [], [])
