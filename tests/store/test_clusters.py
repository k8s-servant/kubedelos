import pytest

from kubedelos.store.clusters import ClusterBusy, Forgotten, forget_cluster, merge_contexts
from kubedelos.store.db import connect

K = "https://k.example.com"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "k.db")
    yield c
    c.close()


def _run(conn, cluster, context, number):
    cur = conn.execute(
        "INSERT INTO scan_run (started_at, status, cluster, context, number) VALUES ('t', 'ok', ?, ?, ?)",
        (cluster, context, number),
    )
    conn.commit()
    return cur.lastrowid


def _rows(conn):
    return [tuple(r) for r in conn.execute("SELECT id, cluster, number, context FROM scan_run ORDER BY id")]


def _seed(conn):
    _run(conn, "prod", "prod", 1)  # id 1
    _run(conn, K, "prod-admin", 1)  # id 2
    _run(conn, "prod", "prod", 2)  # id 3


def test_merge_moves_old_runs_and_renumbers_by_id(conn):
    _seed(conn)
    assert merge_contexts(conn, {"prod": K, "prod-admin": K}) == [("prod", K)]
    assert _rows(conn) == [(1, K, 1, "prod"), (2, K, 2, "prod-admin"), (3, K, 3, "prod")]


def test_merge_is_idempotent(conn):
    _seed(conn)
    keys = {"prod": K, "prod-admin": K}
    merge_contexts(conn, keys)
    before = _rows(conn)
    assert merge_contexts(conn, keys) == []
    assert _rows(conn) == before


def test_merge_leaves_contexts_missing_from_the_kubeconfig(conn):
    _seed(conn)
    assert merge_contexts(conn, {"prod-admin": K}) == []
    assert _rows(conn) == [(1, "prod", 1, "prod"), (2, K, 1, "prod-admin"), (3, "prod", 2, "prod")]


def test_merge_skips_a_context_that_is_its_own_cluster(conn):
    _seed(conn)
    assert merge_contexts(conn, {"prod": "prod"}) == []


def test_merge_moves_acceptances_scoped_to_the_context(conn):
    _seed(conn)
    for ctx, cluster in (("prod", "prod"), ("prod", None), ("other", "other")):
        conn.execute(
            "INSERT INTO acceptance (vuln_id, context, cluster, reason, owner, expires_at, created_at)"
            " VALUES ('CVE-1', ?, ?, 'r', 'o@example.com', 'x', 'x')",
            (ctx, cluster),
        )
    conn.commit()
    merge_contexts(conn, {"prod": K})
    got = [tuple(r) for r in conn.execute("SELECT context, cluster FROM acceptance ORDER BY id")]
    assert got == [("prod", K), ("prod", None), ("other", "other")]


def test_merge_rolls_back_on_error(conn):
    _seed(conn)
    conn.execute("CREATE TRIGGER boom BEFORE UPDATE OF number ON scan_run BEGIN SELECT RAISE(ABORT, 'boom'); END")
    conn.commit()
    with pytest.raises(Exception, match="boom"):
        merge_contexts(conn, {"prod": K})
    assert not conn.in_transaction
    assert _rows(conn) == [(1, "prod", 1, "prod"), (2, K, 1, "prod-admin"), (3, "prod", 2, "prod")]


def test_two_contexts_with_old_runs_merge_into_one_key_in_one_call(conn):
    _run(conn, "prod", "prod", 1)  # id 1
    _run(conn, "prod-admin", "prod-admin", 1)  # id 2: the same number as id 1, under its own name
    _run(conn, "prod", "prod", 2)  # id 3
    _run(conn, "prod-admin", "prod-admin", 2)  # id 4
    conn.execute(
        "INSERT INTO acceptance (vuln_id, cluster, context, reason, owner, expires_at, created_at)"
        " VALUES ('CVE-1', 'prod-admin', 'prod-admin', 'r', 'o', '2099-01-01', 't')"
    )
    conn.commit()
    assert merge_contexts(conn, {"prod": K, "prod-admin": K}) == [("prod", K), ("prod-admin", K)]
    assert _rows(conn) == [
        (1, K, 1, "prod"),
        (2, K, 2, "prod-admin"),
        (3, K, 3, "prod"),
        (4, K, 4, "prod-admin"),
    ]
    assert [tuple(r) for r in conn.execute("SELECT cluster, context FROM acceptance")] == [(K, "prod-admin")]


def _result(conn, run_id):
    conn.execute(
        "INSERT INTO image_result (run_id, image_key, ref, status) VALUES (?, 'sha256:a', 'registry.example/a', 'ok')",
        (run_id,),
    )
    result_id = conn.execute("SELECT MAX(id) FROM image_result").fetchone()[0]
    conn.execute(
        "INSERT INTO workload (image_result_id, namespace, kind, name, container) VALUES (?, 'ns', 'Pod', 'p', 'c')",
        (result_id,),
    )
    conn.execute(
        "INSERT INTO finding (image_result_id, vuln_id, pkg_name, installed_version, severity, target, pkg_type)"
        " VALUES (?, 'CVE-1', 'p', '1', 'HIGH', 't', 'os')",
        (result_id,),
    )
    conn.execute("INSERT INTO run_warning (run_id, text, coverage) VALUES (?, 'w', 0)", (run_id,))
    conn.commit()


def _acceptance(conn, cluster):
    conn.execute(
        "INSERT INTO acceptance (vuln_id, cluster, context, reason, owner, expires_at, created_at)"
        " VALUES ('CVE-1', ?, 'x', 'r', 'o', '2027-01-01', '2026-11-01')",
        (cluster,),
    )
    conn.commit()


def _count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608 - test table names


def test_forget_deletes_one_clusters_runs_and_everything_they_hold(conn):
    gone = [_run(conn, K, "prod", 1), _run(conn, K, "prod-admin", 2)]
    kept = _run(conn, "kind-dev", "kind-dev", 1)
    for run_id in [*gone, kept]:
        _result(conn, run_id)
    for cluster in (K, "kind-dev", None):
        _acceptance(conn, cluster)
    assert forget_cluster(conn, K, acceptances=False) == Forgotten(runs=2, acceptances=0)
    assert [r[0] for r in _rows(conn)] == [kept]
    assert (_count(conn, "image_result"), _count(conn, "workload"), _count(conn, "finding")) == (1, 1, 1)
    assert _count(conn, "run_warning") == 1
    assert _count(conn, "acceptance") == 3  # acceptances stay unless asked for


def test_forget_can_delete_the_clusters_acceptances_but_never_all_cluster_ones(conn):
    _run(conn, K, "prod", 1)
    for cluster in (K, K, "kind-dev", None):
        _acceptance(conn, cluster)
    assert forget_cluster(conn, K, acceptances=True) == Forgotten(runs=1, acceptances=2)
    assert sorted(r[0] or "" for r in conn.execute("SELECT cluster FROM acceptance")) == ["", "kind-dev"]


def test_forget_refuses_while_a_run_of_the_cluster_is_running(conn):
    done = _run(conn, K, "prod", 1)
    conn.execute("UPDATE scan_run SET status = 'running' WHERE id = ?", (_run(conn, K, "prod", 2),))
    conn.commit()
    with pytest.raises(ClusterBusy):
        forget_cluster(conn, K, acceptances=True)
    assert _rows(conn)[0][0] == done and _count(conn, "scan_run") == 2


def test_forget_clears_the_queues_links_to_its_runs(conn):
    run_id = _run(conn, K, "prod", 1)
    conn.execute(
        "INSERT INTO scan_request (kind, trigger, requested_at, target_run_id, overrides, state, run_id)"
        " VALUES ('retry', 'ui', 't', ?, '{}', 'started', ?)",
        (run_id, run_id),
    )
    conn.commit()
    forget_cluster(conn, K, acceptances=False)
    assert tuple(conn.execute("SELECT target_run_id, run_id FROM scan_request").fetchone()) == (None, None)
