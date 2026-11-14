"""Read-only queries that pick which scan run a UI page shows, and describe it.

Only runs that finished with results (``ok`` or ``partial``) are ever shown. Kept apart from ``Repo`` because these are
the reads the UI makes on a read-only connection, and the counting rules (an image is a distinct ref, not a platform
row) live in one place.
"""

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime

RESULT_STATUSES = ("ok", "partial")
_STATUS_SQL = "(" + ", ".join(f"'{s}'" for s in RESULT_STATUSES) + ")"

# Whole-cluster runs: no namespace list and no selectors. Exclusions do not narrow a run. NULL scope (not recorded) never matches.
CLUSTER_SCOPE_SQL = (
    "scope IS NOT NULL AND json_array_length(scope, '$.namespaces') = 0"
    " AND json_extract(scope, '$.namespace_selector') IS NULL AND json_extract(scope, '$.selector') IS NULL"
)

_RUN_SQL = """
SELECT id, context, status, finished_at, pkg_types, scope,
       (SELECT COUNT(DISTINCT ref) FROM image_result WHERE run_id = scan_run.id) AS images,
       (SELECT COUNT(DISTINCT ref) FROM image_result WHERE run_id = scan_run.id AND status = 'error') AS images_failed
FROM scan_run
"""


class RunNotShown(Exception):
    """A requested run cannot be shown; ``reason`` is the sentence to display."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Run:
    id: int
    context: str | None
    status: str
    finished_at: datetime | None
    pkg_types: str | None
    scope: dict | None
    images: int
    images_failed: int
    gaps: list[str] = field(default_factory=list)


def _build(conn: sqlite3.Connection, row: sqlite3.Row) -> Run:
    gaps = conn.execute("SELECT text FROM run_warning WHERE run_id = ? AND coverage = 1 ORDER BY id", (row["id"],))
    return Run(
        id=row["id"],
        context=row["context"],
        status=row["status"],
        finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
        pkg_types=row["pkg_types"],
        scope=json.loads(row["scope"]) if row["scope"] else None,
        images=row["images"],
        images_failed=row["images_failed"],
        gaps=[r["text"] for r in gaps.fetchall()],
    )


def newest_run(conn: sqlite3.Connection, context: str, *, cluster_scope: bool) -> Run | None:
    extra = f" AND {CLUSTER_SCOPE_SQL}" if cluster_scope else ""
    row = conn.execute(
        f"{_RUN_SQL} WHERE context = ? AND status IN {_STATUS_SQL}{extra} ORDER BY id DESC LIMIT 1", (context,)
    ).fetchone()
    return _build(conn, row) if row else None


def get_run(conn: sqlite3.Connection, context: str, run_id: int) -> Run:
    row = conn.execute(f"{_RUN_SQL} WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        raise RunNotShown(f"no run {run_id}")
    if row["context"] != context:
        raise RunNotShown(f"run {run_id} belongs to context {row['context']}, not {context}")
    if row["status"] not in RESULT_STATUSES:
        raise RunNotShown(f"run {run_id} is {row['status']}, so it has no results to show")
    return _build(conn, row)


def previous_comparable(conn: sqlite3.Connection, run: Run) -> Run | None:
    """The newest earlier result run with the same context, scope text and package types; NULL scope never matches."""
    row = conn.execute(
        f"{_RUN_SQL} WHERE id < :id AND context = :context AND status IN {_STATUS_SQL}"  # noqa: S608 - only module constants are interpolated
        " AND scope IS NOT NULL AND scope = (SELECT scope FROM scan_run WHERE id = :id)"
        " AND pkg_types IS (SELECT pkg_types FROM scan_run WHERE id = :id) ORDER BY id DESC LIMIT 1",
        {"id": run.id, "context": run.context},
    ).fetchone()
    return _build(conn, row) if row else None
