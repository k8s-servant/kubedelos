"""Accepted risk: the ``acceptance`` table, its register, and the SQL that tells which finding units it covers.

An acceptance takes a finding off the work lists (the fix lists and the findings page) until it expires; it never
changes a count. Matching happens on read, so a revoke or an expiry takes effect on the next page, and an old run is
judged by today's register. An entry matches a unit when it is active, applies to the run's cluster (or to all
clusters), names the unit's CVE, and its package and image repository, when set, are the unit's. A unit is accepted
only when every namespace its image runs in is covered: a finding accepted in ``web`` still matters in ``api``, and an
image with no workload is covered only by an entry with no namespace.

``ACCEPTED_CTES`` reads the run's finding rows by (image row, CVE) through ``idx_finding_unit``, one lookup per image
and active entry, so it costs next to nothing when there are no entries.
"""

import json
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime
from typing import Literal

# ``WITH ...`` items that end in ``accepted``: the run's accepted unit keys (ref, vuln_id, pkg_name, installed_version).
# Parameters ``:run`` and ``:today`` (an ISO date). The run row names the cluster. Prefix with ``WITH`` or a comma.
ACCEPTED_CTES = """
acc_active AS MATERIALIZED (
  SELECT a.vuln_id, a.namespace, a.repo, a.pkg_name FROM acceptance a
  WHERE a.revoked_at IS NULL AND a.expires_at >= :today
    AND (a.context IS NULL OR a.context = (SELECT context FROM scan_run WHERE id = :run))),
acc_cand AS MATERIALIZED (
  SELECT DISTINCT r.ref, f.vuln_id, f.pkg_name, f.installed_version, e.namespace AS e_ns
  FROM image_result r CROSS JOIN acc_active e CROSS JOIN finding f
    ON f.image_result_id = r.id AND f.vuln_id = e.vuln_id
  WHERE r.run_id = :run AND (e.pkg_name IS NULL OR e.pkg_name = f.pkg_name) AND (e.repo IS NULL OR e.repo = r.repo)),
acc_ns AS MATERIALIZED (
  SELECT DISTINCT r.ref, w.namespace FROM image_result r JOIN workload w ON w.image_result_id = r.id
  WHERE r.run_id = :run AND r.ref IN (SELECT ref FROM acc_cand)),
accepted AS MATERIALIZED (
  SELECT DISTINCT c.ref, c.vuln_id, c.pkg_name, c.installed_version FROM acc_cand c
  WHERE c.e_ns IS NULL OR (
    EXISTS (SELECT 1 FROM acc_ns n WHERE n.ref = c.ref)
    AND NOT EXISTS (SELECT 1 FROM acc_ns n WHERE n.ref = c.ref AND NOT EXISTS (
      SELECT 1 FROM acc_cand c2 WHERE c2.ref = c.ref AND c2.vuln_id = c.vuln_id AND c2.pkg_name IS c.pkg_name
        AND c2.installed_version IS c.installed_version AND c2.e_ns = n.namespace))))
"""

# How many units of the run each listed entry's conditions match, ignoring the every-namespace rule: "covers N".
_COVERS_SQL = """
SELECT id, COUNT(*) AS n FROM (
  SELECT DISTINCT e.id, r.ref, f.vuln_id, f.pkg_name, f.installed_version
  FROM image_result r CROSS JOIN acceptance e CROSS JOIN finding f
    ON f.image_result_id = r.id AND f.vuln_id = e.vuln_id
  WHERE r.run_id = :run AND e.id IN (SELECT value FROM json_each(:ids))
    AND (e.pkg_name IS NULL OR e.pkg_name = f.pkg_name) AND (e.repo IS NULL OR e.repo = r.repo)
    AND (e.namespace IS NULL OR EXISTS (
      SELECT 1 FROM workload w WHERE w.image_result_id = r.id AND w.namespace = e.namespace)))
GROUP BY id
"""

State = Literal["active", "expired", "revoked"]


@dataclass(frozen=True)
class Entry:
    """One register row. ``context`` None means all clusters; a None namespace, repo or package means anywhere."""

    id: int
    vuln_id: str
    context: str | None
    namespace: str | None
    repo: str | None
    pkg_name: str | None
    reason: str
    owner: str
    expires: date
    created_at: datetime
    revoked_at: datetime | None
    state: State
    days_left: int  # negative once expired; 0 on the last day
    covers: int | None  # units of the register's run it matches; None when there is no run


def _blank_none(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


def add(
    conn: sqlite3.Connection,
    *,
    vuln_id: str,
    reason: str,
    owner: str,
    expires: date,
    context: str | None,
    now: datetime,
    namespace: str | None = None,
    repo: str | None = None,
    pkg_name: str | None = None,
) -> int:
    """Store a new acceptance and return its id. Raises ValueError when a required field is blank or ``expires`` is past."""
    vuln_id, reason, owner = vuln_id.strip(), reason.strip(), owner.strip()
    for name, value in (("CVE", vuln_id), ("reason", reason), ("owner", owner)):
        if not value:
            raise ValueError(f"a {name} is required")
    if expires < now.date():
        raise ValueError("the expiry date is in the past")
    with conn:
        cursor = conn.execute(
            "INSERT INTO acceptance (vuln_id, context, namespace, repo, pkg_name, reason, owner, expires_at, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                vuln_id,
                context,
                _blank_none(namespace),
                _blank_none(repo),
                _blank_none(pkg_name),
                reason,
                owner,
                expires.isoformat(),
                now.isoformat(),
            ),
        )
    return cursor.lastrowid


def revoke(conn: sqlite3.Connection, entry_id: int, now: datetime) -> bool:
    """Revoke an entry; False when there is no such entry or it was revoked already."""
    with conn:
        cursor = conn.execute(
            "UPDATE acceptance SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (now.isoformat(), entry_id)
        )
    return cursor.rowcount == 1


def get(conn: sqlite3.Connection, entry_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM acceptance WHERE id = ?", (entry_id,)).fetchone()


def accepted_keys(conn: sqlite3.Connection, run_id: int, today: date) -> set[tuple]:
    """The run's accepted unit keys: (ref, vuln_id, pkg_name, installed_version)."""
    rows = conn.execute(
        f"WITH {ACCEPTED_CTES} SELECT ref, vuln_id, pkg_name, installed_version FROM accepted",  # noqa: S608
        {"run": run_id, "today": today.isoformat()},
    )
    return {tuple(row) for row in rows}


def _state(row: sqlite3.Row, today: date) -> State:
    if row["revoked_at"]:
        return "revoked"
    return "active" if date.fromisoformat(row["expires_at"]) >= today else "expired"


def register(
    conn: sqlite3.Connection, context: str, run_id: int | None, today: date, vuln_id: str | None = None
) -> list[Entry]:
    """The entries that apply to ``context`` (its own and all-cluster ones), optionally of one CVE.

    Active first, soonest to expire first; then expired, most recent first; then revoked, most recent first. ``covers``
    counts in ``run_id``.
    """
    rows = conn.execute(
        "SELECT * FROM acceptance WHERE (context IS NULL OR context = :context)"
        " AND (:vuln IS NULL OR vuln_id = :vuln) ORDER BY id",
        {"context": context, "vuln": vuln_id},
    ).fetchall()
    covers: dict[int, int] = {}
    if run_id is not None and rows:
        covers = {
            r["id"]: r["n"]
            for r in conn.execute(_COVERS_SQL, {"run": run_id, "ids": json.dumps([row["id"] for row in rows])})
        }
    entries = [
        Entry(
            id=row["id"],
            vuln_id=row["vuln_id"],
            context=row["context"],
            namespace=row["namespace"],
            repo=row["repo"],
            pkg_name=row["pkg_name"],
            reason=row["reason"],
            owner=row["owner"],
            expires=date.fromisoformat(row["expires_at"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            revoked_at=datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None,
            state=_state(row, today),
            days_left=(date.fromisoformat(row["expires_at"]) - today).days,
            covers=covers.get(row["id"], 0) if run_id is not None else None,
        )
        for row in rows
    ]

    def order(e: Entry) -> tuple:
        if e.state == "active":
            return (0, e.days_left, e.id)
        if e.state == "expired":
            return (1, -e.days_left, -e.id)
        return (2, -e.revoked_at.timestamp(), -e.id)

    return sorted(entries, key=order)
