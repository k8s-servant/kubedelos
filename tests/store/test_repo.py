import json
import sqlite3
import stat
from datetime import UTC, datetime, timedelta

import pytest

from kubedelos.kube.inventory import InventoryWarning
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.store.db import MIGRATIONS, connect, connect_readonly
from kubedelos.store.repo import Repo

DIGEST = "sha256:" + "a" * 64
_OPEN: list[sqlite3.Connection] = []


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    while _OPEN:
        _OPEN.pop().close()


def _repo(tmp_path, **kw):
    conn = connect(tmp_path / "k.db")
    _OPEN.append(conn)
    return Repo(conn, **kw)


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
    _OPEN.append(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_run_roundtrip_counts(tmp_path):
    repo = _repo(tmp_path)
    run = repo.start_run("ctx", "cli", "0.76.1", scan_level="library,os")
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
    assert _repo(tmp_path).latest_run_id() is None


def test_run_findings_joins_workloads_and_orders(tmp_path):
    repo = _repo(tmp_path)
    run = repo.start_run("ctx", "cli", "0.76.1", scan_level="library,os")
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
    assert first["repo"] == "reg.io/app" and first["tag"] == "1"
    assert first["severity"] == "CRITICAL" and first["pkg_type"] == "os" and first["target"] == "debian"


def test_cached_status_stored_as_is(tmp_path):
    repo = _repo(tmp_path)
    run = repo.start_run("ctx", "cli", "0.76.1", scan_level="library,os")
    item = _item()
    repo.add_result(run, item, _result(item, "cached", findings=[_finding()]))
    assert repo._conn.execute("SELECT status FROM image_result").fetchone()[0] == "cached"
    assert len(repo.run_findings(run)) == 1


def test_add_result_is_atomic(tmp_path):
    repo = _repo(tmp_path)
    run = repo.start_run("ctx", "cli", "0.76.1", scan_level="library,os")
    item = _item()
    with pytest.raises(sqlite3.IntegrityError):
        repo.add_result(run + 100, item, _result(item, findings=[_finding()]))
    assert repo._conn.execute("SELECT COUNT(*) FROM image_result").fetchone()[0] == 0


def test_cache_hit_and_expiry(tmp_path):
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    repo = _repo(tmp_path, clock=lambda: now[0])
    item = _item()
    report = _result(item, findings=[_finding()])
    repo.put_cache(DIGEST, "linux/amd64", report, scan_level="library,os")
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(hours=1), scan_level="library,os") == report
    assert repo.get_cached(DIGEST, "linux/arm64", timedelta(hours=1), scan_level="library,os") is None
    now[0] += timedelta(hours=2)
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(hours=1), scan_level="library,os") is None
    # upsert refreshes the entry
    newer = _result(item, os_family="debian")
    repo.put_cache(DIGEST, "linux/amd64", newer, scan_level="library,os")
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(hours=1), scan_level="library,os") == newer
    assert repo._conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 1
    assert json.loads(repo._conn.execute("SELECT report_json FROM image_cache").fetchone()[0])["os_family"] == "debian"
    assert repo._conn.execute("SELECT trivy_db_version FROM image_cache").fetchone()[0] == "0.76.1+c1"


@pytest.mark.parametrize("blob", ["{not json", '{"image": 1}', '{"status": "ok"}', "[]"])
def test_invalid_cache_row_is_a_miss_and_deleted(tmp_path, blob):
    repo = _repo(tmp_path)
    repo.put_cache(DIGEST, "linux/amd64", _result(_item()), scan_level="library,os")
    repo._conn.execute("UPDATE image_cache SET report_json = ?", (blob,))
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(days=1), scan_level="library,os") is None
    assert repo._conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 0


def test_tag_refs_not_cached(tmp_path):
    repo = _repo(tmp_path)
    repo.put_cache("reg.io/app:latest", "linux/amd64", _result(_item()), scan_level="library,os")
    assert repo._conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 0
    assert repo.get_cached("reg.io/app:latest", "linux/amd64", timedelta(days=1), scan_level="library,os") is None


@pytest.mark.parametrize("status", ["running", "bogus", ""])
def test_finish_run_rejects_bad_status(tmp_path, status):
    repo = _repo(tmp_path)
    run = repo.start_run("ctx", "cli", "0.76.1", scan_level="library,os")
    with pytest.raises(ValueError):
        repo.finish_run(run, status)
    assert repo.get_run(run)["status"] == "running"


@pytest.mark.parametrize(
    "key",
    ["sha256:5000/app:latest", "sha256:abc", "reg.io/app@sha256:" + "A" * 64, "reg.io/app@sha256:" + "a" * 63,
     "x@sha256:" + "a" * 64 + "/y", DIGEST + "\n", "reg.io/app@" + DIGEST + "\n"],
)  # fmt: skip
def test_non_digest_keys_not_cached(tmp_path, key):
    repo = _repo(tmp_path)
    repo.put_cache(key, "linux/amd64", _result(_item()), scan_level="library,os")
    assert repo._conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 0
    assert repo.get_cached(key, "linux/amd64", timedelta(days=1), scan_level="library,os") is None


@pytest.mark.parametrize("key", [DIGEST, "reg.io/app@" + DIGEST])
def test_valid_digest_keys_cached(tmp_path, key):
    repo = _repo(tmp_path)
    report = _result(_item())
    repo.put_cache(key, "linux/amd64", report, scan_level="library,os")
    assert repo.get_cached(key, "linux/amd64", timedelta(days=1), scan_level="library,os") == report


def test_cache_miss_on_other_trivy_version(tmp_path):
    repo = _repo(tmp_path)
    repo.put_cache(DIGEST, "linux/amd64", _result(_item()), scan_level="library,os")
    repo._conn.execute("UPDATE image_cache SET trivy_db_version = '0.76.1'")  # pre-+c1 rows are a miss
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(days=1), scan_level="library,os") is None


def test_db_files_are_private(tmp_path):
    path = tmp_path / "kubedelos" / "k.db"
    conn = connect(path)
    _OPEN.append(conn)
    Repo(conn).start_run("c", "cli", "v", scan_level="library,os")
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


def test_run_errors_lists_failed_images_only(tmp_path):
    repo = _repo(tmp_path)
    run = repo.start_run("ctx", "cli", "0.76.1", scan_level="library,os")
    ok, bad = _item(), _item(ref="reg.io/bad:1", digest=None)
    repo.add_result(run, ok, _result(ok))
    repo.add_result(run, bad, _result(bad, status="error", error_kind="not_found", error="manifest unknown"))
    other = repo.start_run("ctx", "cli", "0.76.1", scan_level="library,os")
    repo.add_result(other, bad, _result(bad, status="error", error_kind="auth", error="denied"))
    rows = [dict(r) for r in repo.run_errors(run)]
    assert rows == [
        {"ref": "reg.io/bad:1", "platform": "linux/amd64", "error_kind": "not_found", "error": "manifest unknown"}
    ]


def test_cache_is_keyed_by_scan_level(tmp_path):
    repo = _repo(tmp_path)
    os_only = _result(_item(), findings=[_finding("CVE-OS")])
    full = _result(_item(), findings=[_finding("CVE-OS"), _finding("CVE-LIB")])
    repo.put_cache(DIGEST, "linux/amd64", os_only, scan_level="os")
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(hours=1), scan_level="library,os") is None
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(hours=1), scan_level="os") == os_only
    repo.put_cache(DIGEST, "linux/amd64", full, scan_level="library,os")
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(hours=1), scan_level="os") == os_only  # both kept
    assert repo.get_cached(DIGEST, "linux/amd64", timedelta(hours=1), scan_level="library,os") == full


def test_run_records_scan_level(tmp_path):
    repo = _repo(tmp_path)
    run = repo.start_run("ctx", "cli", "0.76.1", scan_level="os")
    assert repo.get_run(run)["pkg_types"] == "os"


def test_run_findings_include_pkg_class(tmp_path):
    repo = _repo(tmp_path)
    run = repo.start_run("ctx", "cli", "0.76.1", scan_level="library,os")
    finding = _finding().model_copy(update={"pkg_class": "library"})
    repo.add_result(run, _item(), _result(_item(), findings=[finding]))
    assert [r["pkg_class"] for r in repo.run_findings(run)] == ["library"]


def test_migration_from_v1_keeps_runs_drops_cache(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(f"BEGIN;\n{MIGRATIONS[0]}\nPRAGMA user_version = 1;\nCOMMIT;")
    old.execute(
        "INSERT INTO scan_run (started_at, status, context, trigger, trivy_version)"
        " VALUES ('2026-11-01T00:00:00+00:00', 'ok', 'ctx', 'cli', '0.76.1')"
    )
    old.execute(
        "INSERT INTO image_cache (image_key, platform, trivy_db_version, scanned_at, report_json)"
        " VALUES (?, 'linux/amd64', 'x', '2026-11-01T00:00:00+00:00', '{}')",
        (DIGEST,),
    )
    old.commit()
    old.close()
    conn = connect(path)
    _OPEN.append(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    assert [tuple(r) for r in conn.execute("SELECT context, pkg_types FROM scan_run")] == [("ctx", None)]
    assert conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 0


def test_run_records_scope(tmp_path):
    repo = _repo(tmp_path)
    run = repo.start_run("ctx", "cli", "0.76.1", scan_level="os", scope='{"x":1}')
    assert repo.get_run(run)["scope"] == '{"x":1}'


def test_add_and_read_warnings(tmp_path):
    repo = _repo(tmp_path)
    run_id = repo.start_run("ctx", "cli", "0.76.1", scan_level="os")
    repo.add_warnings(
        run_id,
        [
            InventoryWarning("namespace missing not found", coverage=True),
            InventoryWarning("no owner info", coverage=False),
        ],
    )
    rows = repo.run_warnings(run_id)
    assert [(r["text"], r["coverage"]) for r in rows] == [("namespace missing not found", 1), ("no owner info", 0)]


def test_connect_readonly_cannot_write(tmp_path):
    connect(tmp_path / "k.db").close()
    conn = connect_readonly(tmp_path / "k.db")
    _OPEN.append(conn)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("INSERT INTO scan_run (started_at, status) VALUES ('x', 'ok')")


def test_connect_readonly_missing_file_raises(tmp_path):
    with pytest.raises(sqlite3.OperationalError):
        connect_readonly(tmp_path / "nope.db")
    assert not (tmp_path / "nope.db").exists()


def test_connect_readonly_path_with_space_and_hash(tmp_path):
    path = tmp_path / "a b#c" / "k.db"
    connect(path).close()
    conn = connect_readonly(path)
    _OPEN.append(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
