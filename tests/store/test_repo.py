import json
import sqlite3
import stat
from datetime import UTC, datetime, timedelta

import pytest

from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo

DIGEST = "sha256:" + "a" * 64


def _item(ref="reg.io/app:1", digest=DIGEST, workloads=None):
    image = ImageRef(ref=ref, repo="reg.io/app", tag="1", digest=digest)
    wl = (
        workloads if workloads is not None else [Workload(namespace="ns", kind="Deployment", name="app", container="c")]
    )
    return InventoryItem(image=image, platform="linux/amd64", workloads=wl)


def _finding(vuln_id="CVE-1", severity=Severity.HIGH):
    return Finding(
        vuln_id=vuln_id, pkg_name="openssl", installed_version="1", fixed_version="2",
        severity=severity, title="t", primary_url="https://x", target="debian", pkg_type="os",
    )  # fmt: skip


def _result(item, status="ok", findings=None, **kw):
    return ImageResult(image=item.image, platform=item.platform, status=status, findings=findings or [], **kw)


def test_connect_creates_private_parent_dirs(tmp_path):
    connect(tmp_path / "a" / "b" / "k.db").close()
    assert stat.S_IMODE((tmp_path / "a").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "a" / "b").stat().st_mode) == 0o700


def test_migrations_idempotent(tmp_path):
    path = tmp_path / "d" / "k.db"
    connect(path).close()
    conn = connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_run_roundtrip_counts(tmp_path):
    repo = Repo(connect(tmp_path / "k.db"))
    run = repo.start_run("ctx", "cli", "0.76.1")
    assert repo.get_run(run)["status"] == "running"
    for i, status in enumerate(["ok", "ok", "error"]):
        item = _item(ref=f"reg.io/app:{i}", digest=f"sha256:{i:064d}")
        repo.add_result(run, item, _result(item, status, error_kind="trivy" if status == "error" else None))
    repo.finish_run(run, "partial")
    row = repo.get_run(run)
    assert (row["images_total"], row["images_error"], row["status"]) == (3, 1, "partial")
    assert row["finished_at"] is not None
    assert repo.latest_run_id() == run
    assert repo.get_run(999) is None


def test_latest_run_id_empty(tmp_path):
    assert Repo(connect(tmp_path / "k.db")).latest_run_id() is None


def test_run_findings_joins_workloads_and_orders(tmp_path):
    repo = Repo(connect(tmp_path / "k.db"))
    run = repo.start_run("ctx", "cli", "0.76.1")
    wls = [
        Workload(namespace="zz", kind="Deployment", name="b", container="c", owner="o@x", team="t"),
        Workload(namespace="aa", kind="StatefulSet", name="a", container="c"),
    ]
    item = _item(workloads=wls)
    repo.add_result(
        run, item, _result(item, findings=[_finding("CVE-L", Severity.LOW), _finding("CVE-C", Severity.CRITICAL)])
    )
    rows = repo.run_findings(run)
    assert len(rows) == 4
    assert [(r["vuln_id"], r["namespace"]) for r in rows] == [
        ("CVE-C", "aa"), ("CVE-C", "zz"), ("CVE-L", "aa"), ("CVE-L", "zz"),
    ]  # fmt: skip
    first = rows[1]
    assert first["workload"] == "b" and first["owner"] == "o@x" and first["team"] == "t"
    assert first["image"] == "reg.io/app:1" and first["digest"] == DIGEST and first["platform"] == "linux/amd64"
    assert first["severity"] == "CRITICAL" and first["pkg_type"] == "os" and first["target"] == "debian"


def test_cached_status_stored_as_is(tmp_path):
    repo = Repo(connect(tmp_path / "k.db"))
    run = repo.start_run("ctx", "cli", "0.76.1")
    item = _item()
    repo.add_result(run, item, _result(item, "cached", findings=[_finding()]))
    assert repo._conn.execute("SELECT status FROM image_result").fetchone()[0] == "cached"
    assert len(repo.run_findings(run)) == 1


def test_add_result_is_atomic(tmp_path):
    repo = Repo(connect(tmp_path / "k.db"))
    run = repo.start_run("ctx", "cli", "0.76.1")
    item = _item()
    with pytest.raises(sqlite3.IntegrityError):
        repo.add_result(run + 100, item, _result(item, findings=[_finding()]))
    assert repo._conn.execute("SELECT COUNT(*) FROM image_result").fetchone()[0] == 0


def test_cache_hit_and_expiry(tmp_path):
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    repo = Repo(connect(tmp_path / "k.db"), clock=lambda: now[0])
    item = _item()
    report = _result(item, findings=[_finding()]).model_dump(mode="json")
    repo.put_cache(DIGEST, "linux/amd64", report)
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(hours=1)) == report
    assert repo.get_cached(DIGEST, "linux/arm64", timedelta(hours=1)) is None
    now[0] += timedelta(hours=2)
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(hours=1)) is None
    # upsert refreshes the entry
    repo.put_cache(DIGEST, "linux/amd64", {"v": 2})
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(hours=1)) == {"v": 2}
    assert repo._conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 1
    assert json.loads(repo._conn.execute("SELECT report_json FROM image_cache").fetchone()[0]) == {"v": 2}
    assert repo._conn.execute("SELECT trivy_db_version FROM image_cache").fetchone()[0] == "0.76.1"


def test_tag_refs_not_cached(tmp_path):
    repo = Repo(connect(tmp_path / "k.db"))
    repo.put_cache("reg.io/app:latest", "linux/amd64", {"a": 1})
    assert repo._conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 0
    assert repo.get_cached("reg.io/app:latest", "linux/amd64", timedelta(days=1)) is None


@pytest.mark.parametrize("status", ["running", "bogus", ""])
def test_finish_run_rejects_bad_status(tmp_path, status):
    repo = Repo(connect(tmp_path / "k.db"))
    run = repo.start_run("ctx", "cli", "0.76.1")
    with pytest.raises(ValueError):
        repo.finish_run(run, status)
    assert repo.get_run(run)["status"] == "running"


@pytest.mark.parametrize(
    "key",
    ["sha256:5000/app:latest", "sha256:abc", "reg.io/app@sha256:" + "A" * 64, "reg.io/app@sha256:" + "a" * 63,
     "x@sha256:" + "a" * 64 + "/y"],
)  # fmt: skip
def test_non_digest_keys_not_cached(tmp_path, key):
    repo = Repo(connect(tmp_path / "k.db"))
    repo.put_cache(key, "linux/amd64", {"a": 1})
    assert repo._conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 0
    assert repo.get_cached(key, "linux/amd64", timedelta(days=1)) is None


@pytest.mark.parametrize("key", [DIGEST, "reg.io/app@" + DIGEST])
def test_valid_digest_keys_cached(tmp_path, key):
    repo = Repo(connect(tmp_path / "k.db"))
    repo.put_cache(key, "linux/amd64", {"a": 1})
    assert repo.get_cached(key, "linux/amd64", timedelta(days=1)) == {"a": 1}


def test_cache_miss_on_other_trivy_version(tmp_path):
    repo = Repo(connect(tmp_path / "k.db"))
    repo.put_cache(DIGEST, "linux/amd64", {"a": 1})
    repo._conn.execute("UPDATE image_cache SET trivy_db_version = '0.0.1'")
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(days=1)) is None


def test_db_files_are_private(tmp_path):
    path = tmp_path / "kubedelos" / "k.db"
    conn = connect(path)
    Repo(conn).start_run("c", "cli", "v")
    for f in (path, path.with_name("k.db-wal"), path.with_name("k.db-shm")):
        if f.exists():
            assert stat.S_IMODE(f.stat().st_mode) == 0o600, f
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_existing_foreign_parent_dir_not_chmodded(tmp_path):
    (tmp_path / "shared").mkdir(mode=0o755)
    (tmp_path / "shared").chmod(0o755)
    connect(tmp_path / "shared" / "k.db").close()
    assert stat.S_IMODE((tmp_path / "shared").stat().st_mode) == 0o755


def test_existing_kubedelos_dir_is_tightened(tmp_path):
    (tmp_path / "kubedelos").mkdir()
    (tmp_path / "kubedelos").chmod(0o755)
    connect(tmp_path / "kubedelos" / "k.db").close()
    assert stat.S_IMODE((tmp_path / "kubedelos").stat().st_mode) == 0o700
