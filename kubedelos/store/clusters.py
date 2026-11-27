"""Fold the history a kube-context made before its cluster was known into that cluster.

Runs and accepted risks recorded earlier are keyed by the context name. Once the cluster behind a context is known
(``kube.client.cluster_keys``: its API server, TLS server name and CA), they belong to that cluster, so contexts that
point at one cluster share one history.
``merge_contexts`` moves them over and renumbers each touched cluster 1..n by id, in one transaction.

``forget_cluster`` deletes one cluster's history (its runs and all they hold, and its acceptances when asked), for the
local UI's "start fresh" on a cluster that is gone or was only a test. Acceptances for all clusters are never touched.
"""

import sqlite3
from dataclasses import dataclass

from kubedelos.store.queue import write_lock
from kubedelos.store.retention import delete_runs


class ClusterBusy(Exception):
    """A run of the cluster is still running, so its history can't be deleted now."""


@dataclass(frozen=True)
class Forgotten:
    runs: int
    acceptances: int


def history_counts(conn: sqlite3.Connection, cluster: str) -> tuple[int, int]:
    """How many runs, and how many acceptances scoped to it, ``cluster`` has."""
    runs = conn.execute("SELECT COUNT(*) FROM scan_run WHERE cluster = ?", (cluster,)).fetchone()[0]
    accepted = conn.execute("SELECT COUNT(*) FROM acceptance WHERE cluster = ?", (cluster,)).fetchone()[0]
    return runs, accepted


def forget_cluster(conn: sqlite3.Connection, cluster: str, *, acceptances: bool) -> Forgotten:
    """Delete every run of ``cluster`` and, with ``acceptances``, the acceptances scoped to it, in one transaction.

    Raises :class:`ClusterBusy` when one of its runs is ``running``; then nothing is deleted.
    """
    with write_lock(conn):
        if conn.execute(
            "SELECT 1 FROM scan_run WHERE cluster = ? AND status = 'running' LIMIT 1", (cluster,)
        ).fetchone():
            raise ClusterBusy("a scan of this cluster is running")
        ids = [row[0] for row in conn.execute("SELECT id FROM scan_run WHERE cluster = ? ORDER BY id", (cluster,))]
        delete_runs(conn, ids)
        dropped = conn.execute("DELETE FROM acceptance WHERE cluster = ?", (cluster,)).rowcount if acceptances else 0
    return Forgotten(runs=len(ids), acceptances=dropped)


def merge_contexts(conn: sqlite3.Connection, keys: dict[str, str]) -> list[tuple[str, str]]:
    """Move rows still keyed by a context name to that context's cluster key; return the (context, key) pairs moved.

    ``scan_run.context`` stays as it is (the context a run went through), and acceptances for all clusters (NULL) are
    left alone. Nothing changes if any step fails.
    """
    pairs = sorted((c, k) for c, k in keys.items() if c != k)
    if conn.in_transaction:
        conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        moved = []
        for context, key in pairs:
            # Park the numbers on -id so the moved runs cannot clash with the cluster's own; _renumber fixes them.
            runs = conn.execute(
                "UPDATE scan_run SET cluster = ?, number = -id WHERE cluster = ?", (key, context)
            ).rowcount
            accepted = conn.execute("UPDATE acceptance SET cluster = ? WHERE cluster = ?", (key, context)).rowcount
            if runs or accepted:
                moved.append((context, key))
        for key in sorted({k for _, k in moved}):
            _renumber(conn, key)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return moved


def _renumber(conn: sqlite3.Connection, cluster: str) -> None:
    """Number the cluster's runs 1..n by id. Park them on ``-id`` first so the unique index never sees a clash."""
    conn.execute("UPDATE scan_run SET number = -id WHERE cluster = ?", (cluster,))
    conn.execute(
        "UPDATE scan_run SET number = (SELECT n FROM (SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS n FROM scan_run"
        " WHERE cluster = :c) o WHERE o.id = scan_run.id) WHERE cluster = :c",
        {"c": cluster},
    )
