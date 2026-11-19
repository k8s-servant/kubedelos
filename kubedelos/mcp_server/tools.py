"""The query functions behind the MCP tools: plain functions over a read-only connection that return JSON-ready dicts.

They are kept apart from the SDK wiring in ``server.py`` so they can be tested, and reused by every tool, without a
protocol round trip. Errors that the agent should read are raised as ``ToolError``.
"""

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.mcpserver.exceptions import ToolError

from kubedelos import analytics
from kubedelos.store import queries
from kubedelos.store.db import MIGRATIONS, connect_readonly

DEFAULT_LIMIT = 25
MAX_LIMIT = 100


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class Db:
    """Where the database is, and the cluster tools use when called without one."""

    path: Path
    default_cluster: str | None

    def open(self) -> sqlite3.Connection:
        """A read-only connection; the server starts without a database, so the tools explain what is missing."""
        if not self.path.is_file():
            raise ToolError(f'no kubedelos database at {self.path}; run "kubedelos ui" and start a scan first')
        conn = connect_readonly(self.path)
        try:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
        except sqlite3.Error:
            conn.close()
            raise
        if version < len(MIGRATIONS):
            conn.close()
            raise ToolError(
                f'the database at {self.path} was written by an older kubedelos; open "kubedelos ui" once to update it'
            )
        if version > len(MIGRATIONS):
            conn.close()
            raise ToolError(f"the database at {self.path} was written by a newer kubedelos; upgrade kubedelos")
        return conn


def clamp(limit: int, default: int = DEFAULT_LIMIT) -> int:
    """``limit`` bounded to ``MAX_LIMIT``; zero or below means ``default``. Large values are clamped, not refused."""
    return default if limit <= 0 else min(limit, MAX_LIMIT)


def resolve_cluster(conn: sqlite3.Connection, db: Db, cluster: str | None) -> str:
    """The cluster to query: the argument, else ``--context``, else the context with the newest finished run."""
    scans = queries.context_scans(conn)
    name = cluster or db.default_cluster or _newest_finished(scans)
    if name is None or name not in scans:
        raise ToolError(f"unknown cluster {name}; known: {', '.join(sorted(scans))}")
    return name


def _newest_finished(scans: dict[str, datetime | None]) -> str | None:
    finished = {name: when for name, when in scans.items() if when is not None}
    return max(finished, key=lambda name: finished[name]) if finished else None


def _dashboard_run(conn: sqlite3.Connection, cluster: str) -> queries.Run | None:
    """The run the dashboard shows: the newest whole-cluster result run, else the newest result run of any scope."""
    return queries.newest_run(conn, cluster, cluster_scope=True) or queries.newest_run(
        conn, cluster, cluster_scope=False
    )


def run_payload(run: queries.Run, now: datetime) -> dict:
    return {
        "number": run.number,
        "status": run.status,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "scope": analytics.describe_scope(run.scope),
        "stale": analytics.is_stale(run.finished_at, now),
        "fact_sources": run.fact_sources,
    }


def list_clusters(conn: sqlite3.Connection, db: Db, now: datetime) -> dict:
    scans = queries.context_scans(conn)
    clusters = []
    for name in sorted(scans):
        run = _dashboard_run(conn, name)
        last = scans[name]
        clusters.append(
            {
                "name": name,
                "last_scan": last.isoformat() if last else None,
                "status": run.status if run else None,
                "stale": analytics.is_stale(last, now),
                "newest_run": run.number if run else None,
            }
        )
    return {"clusters": clusters, "default": db.default_cluster or _newest_finished(scans)}
