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
    conn = sqlite3.connect(path)
    for index, script in enumerate(MIGRATIONS[:versions]):
        conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {index + 1};\nCOMMIT;")
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
        assert conn.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS) == 13
        points = [r[0] for r in conn.execute("SELECT risk_points FROM workload ORDER BY id")]
        assert points == [workload_points(_FACTS), NO_FACTS_POINTS, NO_FACTS_POINTS]
        assert NO_FACTS_POINTS == 18
        assert conn.execute("SELECT COUNT(*) FROM threat_intel").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM threat_feed").fetchone()[0] == 0
    finally:
        conn.close()


def test_failed_callable_migration_rolls_back(tmp_path, monkeypatch):
    path = tmp_path / "k.db"
    old = _old_database(path, 12)
    old.execute("INSERT INTO scan_run (id, started_at, status) VALUES (1, 'now', 'ok')")
    old.commit()
    old.close()

    def broken(conn: sqlite3.Connection) -> None:
        conn.execute("UPDATE scan_run SET status = 'failed'")
        raise RuntimeError("boom")

    monkeypatch.setattr(db, "MIGRATIONS", [*MIGRATIONS[:12], broken])
    with pytest.raises(RuntimeError):
        connect(path)
    check = sqlite3.connect(path)
    try:
        assert check.execute("PRAGMA user_version").fetchone()[0] == 12
        assert check.execute("SELECT status FROM scan_run").fetchone()[0] == "ok"
    finally:
        check.close()
