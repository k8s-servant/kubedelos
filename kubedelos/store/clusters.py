"""Fold the history a kube-context made before its cluster was known into that cluster.

Runs and accepted risks recorded earlier are keyed by the context name. Once the cluster behind a context is known
(``kube.client.cluster_keys``: its API server, TLS server name and CA), they belong to that cluster, so contexts that
point at one cluster share one history.
``merge_contexts`` moves them over and renumbers each touched cluster 1..n by id, in one transaction.
"""

import sqlite3


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
