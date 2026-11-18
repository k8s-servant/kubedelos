"""The scan queue: durable scan requests in SQLite, shared by the UI, the scheduler and the worker.

Requests wait as ``queued`` until the single worker claims them (``started``); a cancelled or orphaned one ends as
``cancelled``. Equal requests coalesce while queued, and the queue is bounded, so a stuck worker cannot be flooded.
Enqueue and claim each run in one ``BEGIN IMMEDIATE`` transaction, so two threads or processes never both add or
both claim the same request.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime

MAX_QUEUED = 10


class QueueFull(Exception):
    """The queue already holds MAX_QUEUED distinct requests."""


@dataclass(frozen=True)
class Request:
    id: int
    kind: str
    trigger: str
    requested_by: str | None
    requested_at: str
    target_run_id: int | None
    overrides: dict
    state: str
    run_id: int | None


@dataclass(frozen=True)
class Enqueued:
    id: int
    added: bool  # False: an equal request was already queued and its id is returned


def canonical(overrides: dict) -> str:
    """Key-order independent text form of the overrides, used to compare requests."""
    return json.dumps(overrides, sort_keys=True, separators=(",", ":"), default=list)


@contextmanager
def write_lock(conn: sqlite3.Connection) -> Iterator[None]:
    """Hold SQLite's write lock for the block; commit on success, roll back on any exception."""
    conn.commit()  # legacy transaction mode: end any open transaction so BEGIN IMMEDIATE starts a fresh one
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        conn.rollback()
        raise
    conn.commit()


def _request(row: sqlite3.Row) -> Request:
    return Request(
        id=row["id"],
        kind=row["kind"],
        trigger=row["trigger"],
        requested_by=row["requested_by"],
        requested_at=row["requested_at"],
        target_run_id=row["target_run_id"],
        overrides=json.loads(row["overrides"]),
        state=row["state"],
        run_id=row["run_id"],
    )


def _find_equal(
    conn: sqlite3.Connection, kind: str, trigger: str, overrides_text: str, target: int | None
) -> int | None:
    if trigger == "schedule":
        row = conn.execute(
            "SELECT id FROM scan_request WHERE state = 'queued' AND trigger = 'schedule' ORDER BY id LIMIT 1"
        ).fetchone()
    elif kind == "retry":
        row = conn.execute(
            "SELECT id FROM scan_request WHERE state = 'queued' AND kind = 'retry' AND target_run_id = ? "
            "ORDER BY id LIMIT 1",
            (target,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT id FROM scan_request WHERE state = 'queued' AND trigger = 'ui' AND kind = 'scan' "
            "AND overrides = ? ORDER BY id LIMIT 1",
            (overrides_text,),
        ).fetchone()
    return row["id"] if row else None


def enqueue(
    conn: sqlite3.Connection,
    *,
    kind: str,
    trigger: str,
    overrides: dict,
    requested_by: str | None = None,
    target_run_id: int | None = None,
    now: datetime,
) -> Enqueued:
    """Queue a request, or return the id of an equal queued one. Raises QueueFull past MAX_QUEUED."""
    text = canonical(overrides)
    with write_lock(conn):
        existing = _find_equal(conn, kind, trigger, text, target_run_id)
        if existing is not None:
            return Enqueued(id=existing, added=False)
        waiting = conn.execute("SELECT COUNT(*) FROM scan_request WHERE state = 'queued'").fetchone()[0]
        if waiting >= MAX_QUEUED:
            raise QueueFull(f"{MAX_QUEUED} scan requests are already queued")
        cur = conn.execute(
            "INSERT INTO scan_request (kind, trigger, requested_by, requested_at, target_run_id, overrides, state) "
            "VALUES (?, ?, ?, ?, ?, ?, 'queued')",
            (kind, trigger, requested_by, now.isoformat(), target_run_id, text),
        )
        return Enqueued(id=cur.lastrowid, added=True)


def claim_next(conn: sqlite3.Connection) -> Request | None:
    """Mark the oldest queued request started and return it, or None when nothing waits."""
    with write_lock(conn):
        row = conn.execute("SELECT * FROM scan_request WHERE state = 'queued' ORDER BY id LIMIT 1").fetchone()
        if row is None:
            return None
        conn.execute("UPDATE scan_request SET state = 'started' WHERE id = ?", (row["id"],))
        return replace(_request(row), state="started")


def attach_run(conn: sqlite3.Connection, request_id: int, run_id: int | None) -> None:
    """Record the scan_run a started request produced."""
    with conn:
        conn.execute("UPDATE scan_request SET run_id = ? WHERE id = ?", (run_id, request_id))


def cancel(conn: sqlite3.Connection, request_id: int) -> bool:
    """Cancel a request that is still queued; True when it was."""
    with conn:
        cur = conn.execute(
            "UPDATE scan_request SET state = 'cancelled' WHERE id = ? AND state = 'queued'", (request_id,)
        )
    return cur.rowcount == 1


def requeue(conn: sqlite3.Connection, request_id: int) -> bool:
    """Put a started request that has no run yet back in the queue (the scan slot was busy); True when it was."""
    with conn:
        cur = conn.execute(
            "UPDATE scan_request SET state = 'queued' WHERE id = ? AND state = 'started' AND run_id IS NULL",
            (request_id,),
        )
    return cur.rowcount == 1


def queued(conn: sqlite3.Connection) -> list[Request]:
    """The waiting requests, oldest first."""
    rows = conn.execute("SELECT * FROM scan_request WHERE state = 'queued' ORDER BY id").fetchall()
    return [_request(row) for row in rows]


def abandon_started(conn: sqlite3.Connection) -> int:
    """Cancel started requests that never got a run (the process died between claim and run); returns the count."""
    with conn:
        cur = conn.execute("UPDATE scan_request SET state = 'cancelled' WHERE state = 'started' AND run_id IS NULL")
    return cur.rowcount
