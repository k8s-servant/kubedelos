import sqlite3

import pytest

from kubedelos.models import Exposure, Network, PodSecurity, Rights, WorkloadFacts
from kubedelos.risk import NO_FACTS_POINTS, workload_points
from kubedelos.store import db
from kubedelos.store.db import MIGRATIONS, connect

_FACTS = WorkloadFacts(
    pod=PodSecurity(
        privileged=True, allow_privilege_escalation=True, runs_as_root=True, read_only_root_fs=False,
        host_network=False, host_pid=False, host_ipc=False, service_account="default", automount_token=None,
    ),
    exposure=Exposure(level="external"),
    network=Network(ingress_isolated=False, egress_isolated=None),
    rights=Rights(status="off"),
)  # fmt: skip


def _old_database(path, versions: int) -> sqlite3.Connection:
    conn = sqlite3.connect(path, autocommit=True)
    for index, step in enumerate(MIGRATIONS[:versions]):
        if callable(step):
            conn.execute("BEGIN")
            step(conn)
            conn.execute(f"PRAGMA user_version = {index + 1}")
            conn.execute("COMMIT")
        else:
            conn.executescript(f"BEGIN;\n{step}\nPRAGMA user_version = {index + 1};\nCOMMIT;")
    conn.autocommit = sqlite3.LEGACY_TRANSACTION_CONTROL
    return conn


def test_migration_13_backfills_risk_points(tmp_path):
    path = tmp_path / "k.db"
    old = _old_database(path, 12)
    old.execute("INSERT INTO scan_run (id, started_at, status) VALUES (1, 'now', 'ok')")
    old.execute("INSERT INTO image_result (id, run_id, image_key, ref, status) VALUES (1, 1, 'k', 'r', 'ok')")
    for name, facts in (("a", _FACTS.model_dump_json()), ("b", None), ("c", "{not json")):
        old.execute(
            "INSERT INTO workload (image_result_id, namespace, kind, name, container, facts)"
            " VALUES (1, 'ns', 'Deployment', ?, 'c', ?)",
            (name, facts),
        )
    old.commit()
    old.close()
    conn = connect(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS) == 15
        points = [r[0] for r in conn.execute("SELECT risk_points FROM workload ORDER BY id")]
        assert points == [workload_points(_FACTS), NO_FACTS_POINTS, NO_FACTS_POINTS]
        assert NO_FACTS_POINTS == 18
        assert conn.execute("SELECT COUNT(*) FROM threat_intel").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM threat_feed").fetchone()[0] == 0
    finally:
        conn.close()


def test_failed_callable_migration_rolls_back(tmp_path, monkeypatch):
    path = tmp_path / "k.db"
    old = _old_database(path, 13)
    old.execute("INSERT INTO scan_run (id, started_at, status) VALUES (1, 'now', 'ok')")
    old.commit()
    old.close()

    def broken(conn: sqlite3.Connection) -> None:
        conn.execute("UPDATE scan_run SET status = 'failed'")
        raise RuntimeError("boom")

    monkeypatch.setattr(db, "MIGRATIONS", [*MIGRATIONS[:13], broken])
    with pytest.raises(RuntimeError):
        connect(path)
    check = sqlite3.connect(path)
    try:
        assert check.execute("PRAGMA user_version").fetchone()[0] == 13
        assert check.execute("SELECT status FROM scan_run").fetchone()[0] == "ok"
    finally:
        check.close()


def _rows(conn: sqlite3.Connection, sql: str) -> list[tuple]:
    return [tuple(r) for r in conn.execute(sql)]


def test_migration_14_keys_existing_runs_by_their_context(tmp_path):
    path = tmp_path / "k.db"
    old = _old_database(path, 13)
    for context in ("a", "b", "a", None):
        old.execute(
            "INSERT INTO scan_run (started_at, status, context, number)"
            " VALUES ('now', 'ok', ?, (SELECT COALESCE(MAX(number), 0) + 1 FROM scan_run WHERE context IS ?))",
            (context, context),
        )
    for context in ("a", None):
        old.execute(
            "INSERT INTO acceptance (vuln_id, context, reason, owner, expires_at, created_at)"
            " VALUES ('CVE-1', ?, 'r', 'o', '2027-01-01', '2026-11-01')",
            (context,),
        )
    old.commit()
    old.close()
    conn = connect(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
        assert _rows(conn, "SELECT cluster, context, number FROM scan_run ORDER BY id") == [
            ("a", "a", 1),
            ("b", "b", 1),
            ("a", "a", 2),
            (None, None, 1),
        ]
        assert _rows(conn, "SELECT cluster, context FROM acceptance ORDER BY id") == [("a", "a"), (None, None)]
        indexes = {r[0]: r[1] for r in conn.execute("SELECT name, sql FROM sqlite_master WHERE tbl_name = 'scan_run'")}
        assert "idx_scan_run_number_no_context" not in indexes
        assert "(context, id)" in indexes["idx_scan_run_context"]  # for the newest run through a context
        assert "(cluster, number)" in indexes["idx_scan_run_number"]
        assert "WHERE cluster IS NULL" in indexes["idx_scan_run_number_no_cluster"]
        assert "(cluster, status, id)" in indexes["idx_scan_run_cluster"]
    finally:
        conn.close()


def test_run_numbers_are_unique_per_cluster_after_migration_14(tmp_path):
    conn = connect(tmp_path / "k.db")
    try:
        insert = "INSERT INTO scan_run (started_at, status, cluster, context, number) VALUES ('now', 'ok', ?, ?, 1)"
        conn.execute(insert, ("https://k.example.com", "prod"))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(insert, ("https://k.example.com", "prod-admin"))
        conn.execute(insert, (None, None))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(insert, (None, "other"))
    finally:
        conn.close()


def test_migration_15_leaves_existing_runs_without_a_trivy_db_date(tmp_path):
    path = tmp_path / "k.db"
    old = _old_database(path, 14)
    old.execute("INSERT INTO scan_run (started_at, status, context, cluster, number) VALUES ('now', 'ok', 'a', 'a', 1)")
    old.commit()
    old.close()
    conn = connect(path)
    try:
        assert _rows(conn, "SELECT trivy_db_built_at FROM scan_run") == [(None,)]
    finally:
        conn.close()
