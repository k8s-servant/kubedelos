"""Retention: delete scan runs past the retention period, and expired image-cache rows.

``kubedelos serve`` runs on a schedule and would otherwise grow the database without bound. The newest ``ok`` or
``partial`` run of each (context, scope, scan level) always stays, so the latest result of every comparable scan
survives however old it is, and a run a queued retry still names stays too. Acceptances are never touched.
"""

import sqlite3
from datetime import datetime, timedelta

from kubedelos.store.queue import _write_lock


def prune(
    conn: sqlite3.Connection, *, now: datetime, retention_days: int, cache_max_age: timedelta = timedelta(hours=24)
) -> list[int]:
    """Delete old runs, old finished requests and stale cache rows in one transaction; return the deleted run ids.

    ``retention_days == 0`` keeps every run and request but still prunes the cache.
    """
    with _write_lock(conn):
        conn.execute("DELETE FROM image_cache WHERE scanned_at < ?", ((now - cache_max_age).isoformat(),))
        if retention_days == 0:
            return []
        cutoff = (now - timedelta(days=retention_days)).isoformat()
        doomed = [
            row[0]
            for row in conn.execute(
                """
                SELECT id FROM scan_run
                WHERE started_at < :cutoff AND status != 'running'
                  AND id NOT IN (
                      SELECT MAX(id) FROM scan_run WHERE status IN ('ok', 'partial')
                      GROUP BY context, scope, pkg_types)
                  AND id NOT IN (
                      SELECT target_run_id FROM scan_request WHERE state = 'queued' AND target_run_id IS NOT NULL)
                ORDER BY id
                """,
                {"cutoff": cutoff},
            )
        ]
        for run_id in doomed:
            conn.execute(
                "DELETE FROM finding WHERE image_result_id IN (SELECT id FROM image_result WHERE run_id = ?)", (run_id,)
            )
            conn.execute(
                "DELETE FROM workload WHERE image_result_id IN (SELECT id FROM image_result WHERE run_id = ?)",
                (run_id,),
            )
            conn.execute("DELETE FROM image_result WHERE run_id = ?", (run_id,))
            conn.execute("DELETE FROM run_warning WHERE run_id = ?", (run_id,))
            conn.execute("UPDATE scan_request SET run_id = NULL WHERE run_id = ?", (run_id,))
            conn.execute("UPDATE scan_request SET target_run_id = NULL WHERE target_run_id = ?", (run_id,))
            conn.execute("DELETE FROM scan_run WHERE id = ?", (run_id,))
        conn.execute("DELETE FROM scan_request WHERE state != 'queued' AND requested_at < ?", (cutoff,))
        return doomed
