import pytest

from kubedelos.store.clusters import merge_contexts
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
