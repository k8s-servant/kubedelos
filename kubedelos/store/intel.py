"""Reads of the threat feeds and of what a run knows, for the risk score.

``intel_for`` gives what CISA KEV and EPSS say about some CVEs, ``feeds`` when each feed was last fetched, and
``risk_shown`` whether a run has anything to score beyond severity: workload facts, or a copy of either feed. Without
both, the risk score would only repeat the severity, so the UI leaves it out. All read-only: the feeds are written by
``kubedelos.threatintel`` alone.
"""

import json
import sqlite3
from collections.abc import Iterable
from datetime import date, datetime

from kubedelos.risk import Intel

# Through the run's image rows (idx_image_result_run), then their workloads (idx_workload_image_result): never a scan.
RUN_HAS_FACTS_SQL = (
    "SELECT EXISTS (SELECT 1 FROM image_result r JOIN workload w ON w.image_result_id = r.id"
    " WHERE r.run_id = :run AND w.facts IS NOT NULL LIMIT 1)"
)


def _date(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def intel_for(conn: sqlite3.Connection, vuln_ids: Iterable[str]) -> dict[str, Intel]:
    """``Intel`` for each of ``vuln_ids`` the feeds name; an id they don't name is absent."""
    rows = conn.execute(
        "SELECT vuln_id, kev, kev_added, epss, epss_percentile FROM threat_intel"
        " WHERE vuln_id IN (SELECT value FROM json_each(?))",
        (json.dumps(sorted(set(vuln_ids))),),
    )
    return {
        vuln_id: Intel(kev=bool(kev), kev_added=_date(added), epss=epss, percentile=percentile)
        for vuln_id, kev, added, epss, percentile in rows
    }


def feeds(conn: sqlite3.Connection) -> dict[str, datetime]:
    """When each feed with a stored copy was fetched, by name (``kev``, ``epss``)."""
    return {name: datetime.fromisoformat(at) for name, at in conn.execute("SELECT name, fetched_at FROM threat_feed")}


def run_has_facts(conn: sqlite3.Connection, run_id: int) -> bool:
    """Whether any workload row of the run carries attack-surface facts."""
    return bool(conn.execute(RUN_HAS_FACTS_SQL, {"run": run_id}).fetchone()[0])


def risk_shown(conn: sqlite3.Connection, run_id: int) -> bool:
    """Whether the run's risk score says more than its severity: it has facts, or a feed has a copy."""
    return run_has_facts(conn, run_id) or bool(feeds(conn))
