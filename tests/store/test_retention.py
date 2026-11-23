from datetime import UTC, datetime, timedelta

import pytest

from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.store import queue
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo
from kubedelos.store.retention import prune

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "k.db")
    yield c
    c.close()


def _run(conn, age_days, *, status="ok", context="my-cluster", cluster=None, scope="{}", level="os", findings=True):
    """Seed a finished run that started age_days ago, with one image, workload and finding."""
    repo = Repo(conn, clock=lambda: NOW - timedelta(days=age_days))
    run_id = repo.start_run(cluster or context, context, "cli", "0.76.1", scan_level=level, scope=scope)
    image = ImageRef(ref="reg.example.com/app:1", repo="reg.example.com/app", tag="1", digest=DIGEST)
    item = InventoryItem(
        image=image,
        platform="linux/amd64",
        workloads=[Workload(namespace="ns", kind="Deployment", name="app", container="c")],
    )
    found = [
        Finding(
            vuln_id="CVE-1", pkg_name="p", installed_version="1", fixed_version="2", severity=Severity.HIGH,
            title="t", primary_url="https://example.com", target="debian", pkg_type="os",
        )
    ]  # fmt: skip
    repo.add_result(run_id, item, ImageResult(image=image, platform="linux/amd64", status="ok", findings=found))
    if status != "running":
        repo.finish_run(run_id, status)
    return run_id


def _count(conn, table, where="1=1", args=()):
    return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", args).fetchone()[0]  # noqa: S608 (test helper)


def test_old_runs_and_their_rows_are_deleted(conn):
    old = _run(conn, 200)
    new = _run(conn, 1)
    assert prune(conn, now=NOW, retention_days=90) == [old]
    assert _count(conn, "scan_run", "id = ?", (old,)) == 0
    assert _count(conn, "image_result", "run_id = ?", (old,)) == 0
    assert _count(conn, "image_result", "run_id = ?", (new,)) == 1
    assert _count(conn, "workload") == 1
    assert _count(conn, "finding") == 1


def test_run_warnings_are_deleted_with_their_run(conn):
    old = _run(conn, 200)
    _run(conn, 1)
    conn.execute("INSERT INTO run_warning (run_id, text, coverage) VALUES (?, 'm', 0)", (old,))
    conn.commit()
    prune(conn, now=NOW, retention_days=90)
    assert _count(conn, "run_warning") == 0


def test_newest_result_run_of_each_scope_is_kept_however_old(conn):
    only = _run(conn, 400)
    assert prune(conn, now=NOW, retention_days=90) == []
    assert _count(conn, "scan_run", "id = ?", (only,)) == 1


def test_scopes_are_kept_apart(conn):
    other_scope = _run(conn, 400, scope='{"namespaces":["x"]}')
    other_level = _run(conn, 400, level="os,library")
    other_context = _run(conn, 400, context="other-cluster")
    old = _run(conn, 300)
    _run(conn, 1)
    assert prune(conn, now=NOW, retention_days=90) == [old]
    for kept in (other_scope, other_level, other_context):
        assert _count(conn, "scan_run", "id = ?", (kept,)) == 1


def test_retention_keeps_the_newest_result_per_cluster_scope_and_level(conn):
    old = _run(conn, 400, context="prod", cluster="https://k.example.com")
    newest = _run(conn, 300, context="prod-admin", cluster="https://k.example.com")
    assert prune(conn, now=NOW, retention_days=90) == [old]  # one cluster, so only its newest result stays
    assert _count(conn, "scan_run", "id = ?", (newest,)) == 1


def test_failed_runs_do_not_count_as_the_kept_result(conn):
    failed = _run(conn, 300, status="failed")
    ok = _run(conn, 200)
    assert prune(conn, now=NOW, retention_days=90) == [failed]
    assert _count(conn, "scan_run", "id = ?", (ok,)) == 1


def test_running_runs_are_never_deleted(conn):
    running = _run(conn, 400, status="running")
    assert prune(conn, now=NOW, retention_days=90) == []
    assert _count(conn, "scan_run", "id = ?", (running,)) == 1


def test_run_named_by_a_queued_retry_is_kept(conn):
    old = _run(conn, 200)
    _run(conn, 1)
    queue.enqueue(conn, kind="retry", trigger="ui", overrides={}, target_run_id=old, now=NOW)
    assert prune(conn, now=NOW, retention_days=90) == []
    assert _count(conn, "scan_run", "id = ?", (old,)) == 1


def test_finished_requests_pointing_at_deleted_runs_are_detached(conn):
    old = _run(conn, 200)
    _run(conn, 1)
    queue.enqueue(conn, kind="retry", trigger="ui", overrides={}, target_run_id=old, now=NOW - timedelta(days=1))
    queue.claim_next(conn)
    queue.attach_run(conn, 1, old)
    assert prune(conn, now=NOW, retention_days=90) == [old]
    row = conn.execute("SELECT run_id, target_run_id FROM scan_request").fetchone()
    assert (row["run_id"], row["target_run_id"]) == (None, None)


def test_old_finished_requests_are_deleted_and_queued_ones_kept(conn):
    old = NOW - timedelta(days=200)
    queue.enqueue(conn, kind="scan", trigger="ui", overrides={"a": 1}, now=old)
    queue.claim_next(conn)
    queue.enqueue(conn, kind="scan", trigger="ui", overrides={"b": 1}, now=old)
    assert prune(conn, now=NOW, retention_days=90) == []
    assert [r["state"] for r in conn.execute("SELECT state FROM scan_request")] == ["queued"]


def _cache(conn, key, age):
    conn.execute(
        "INSERT INTO image_cache (image_key, platform, scan_level, scanned_at, report_json)"
        " VALUES (?, 'linux/amd64', 'os', ?, '{}')",
        (key, (NOW - age).isoformat()),
    )
    conn.commit()


def test_zero_keeps_every_run_but_prunes_the_cache(conn):
    _run(conn, 400)
    _run(conn, 1)
    _cache(conn, "stale", timedelta(hours=25))
    _cache(conn, "fresh", timedelta(hours=1))
    assert prune(conn, now=NOW, retention_days=0) == []
    assert _count(conn, "scan_run") == 2
    assert [r[0] for r in conn.execute("SELECT image_key FROM image_cache")] == ["fresh"]


def test_acceptances_are_untouched(conn):
    _run(conn, 200)
    _run(conn, 1)
    conn.execute(
        "INSERT INTO acceptance (vuln_id, reason, owner, expires_at, created_at) VALUES ('CVE-1', 'r', 'o', ?, ?)",
        ((NOW - timedelta(days=300)).isoformat(),) * 2,
    )
    conn.commit()
    prune(conn, now=NOW, retention_days=90)
    assert _count(conn, "acceptance") == 1
