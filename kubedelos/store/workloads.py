"""Reads that put workloads next to findings: which workloads run an image with a CVE, what facts they carry and how
many findings each has, for the MCP server's per-workload tools.

Every query is parameterised and keyed by ``image_result.run_id`` (and then by the run's image rows), so it never reads
another run. A finding is counted in the units of ``queries.FINDING_UNITS_SQL``, the same as the dashboard and the
findings page, so the numbers agree with the UI.
"""

import json
import sqlite3
from dataclasses import dataclass

from kubedelos.models import Severity, WorkloadFacts, parse_facts
from kubedelos.risk import NO_FACTS_POINTS
from kubedelos.store import queries
from kubedelos.store.queries import REF_UNIT_COUNTS_SQL, REF_UNITS_SQL

SEVERITIES = tuple(s.value for s in Severity)
_SEVERITY_OF_RANK = {4 - i: name for i, name in enumerate(queries.SEVERITIES)}  # as ``queries.kpis`` maps it


@dataclass(frozen=True)
class WorkloadRow:
    """One container of one workload in a run, with the image it runs, its facts and its finding counts."""

    namespace: str
    kind: str
    name: str
    container: str
    ref: str
    status: str  # the image result's status; "error" if any platform of the image failed
    facts: WorkloadFacts | None
    counts: dict[str, int]  # finding units by severity, every severity present


def workloads(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    vuln_id: str | None = None,
    namespace: str | None = None,
    name: str | None = None,
    kind: str | None = None,
    counts: bool = True,
) -> list[WorkloadRow]:
    """The run's workload containers, by namespace, kind, name and container, narrowed by exact matches.

    ``vuln_id`` keeps the workloads whose image has that CVE. A second platform repeats an image's workloads; they are
    merged into one row. ``counts=False`` skips the finding counts (every severity reads zero), which cost a pass over
    the images' findings.
    """
    rows = conn.execute(
        "SELECT w.namespace, w.kind, w.name, w.container, r.ref, MAX(w.facts) AS facts,"
        " CASE WHEN MAX(r.status = 'error') THEN 'error' ELSE MAX(r.status) END AS status"
        " FROM image_result r JOIN workload w ON w.image_result_id = r.id"
        " WHERE r.run_id = :run"
        " AND (:namespace IS NULL OR w.namespace = :namespace)"
        " AND (:name IS NULL OR w.name = :name)"
        " AND (:kind IS NULL OR w.kind = :kind)"
        " AND (:vuln IS NULL OR EXISTS (SELECT 1 FROM finding f WHERE f.image_result_id = r.id AND f.vuln_id = :vuln))"
        " GROUP BY w.namespace, w.kind, w.name, w.container, r.ref"
        " ORDER BY w.namespace, w.kind, w.name, w.container, r.ref",
        {"run": run_id, "namespace": namespace, "name": name, "kind": kind, "vuln": vuln_id},
    ).fetchall()
    by_ref = _counts(conn, run_id, sorted({row["ref"] for row in rows}) if counts else [])
    zero = dict.fromkeys(SEVERITIES, 0)
    return [
        WorkloadRow(
            namespace=row["namespace"],
            kind=row["kind"],
            name=row["name"],
            container=row["container"],
            ref=row["ref"],
            status=row["status"],
            facts=parse_facts(row["facts"]),
            counts=dict(by_ref.get(row["ref"], zero)),  # a copy, so no two rows share one dict
        )
        for row in rows
    ]


def _counts(conn: sqlite3.Connection, run_id: int, refs: list[str]) -> dict[str, dict[str, int]]:
    """Finding units by severity for each of ``refs``; an image with none has every severity at zero."""
    by_ref = {ref: dict.fromkeys(SEVERITIES, 0) for ref in refs}
    if not refs:
        return by_ref
    rows = conn.execute(
        f"WITH units AS ({REF_UNIT_COUNTS_SQL}) SELECT ref, sev_rank, COUNT(*) AS n FROM units GROUP BY ref, sev_rank",  # noqa: S608
        {"run": run_id, "refs": json.dumps(refs)},
    )
    for row in rows:
        by_ref[row["ref"]][_SEVERITY_OF_RANK[row["sev_rank"]]] = row["n"]
    return by_ref


def cve_packages(conn: sqlite3.Connection, run_id: int, vuln_id: str) -> list[dict]:
    """The distinct packages, versions, severities and texts the run reports for ``vuln_id`` (an exact match)."""
    rows = conn.execute(
        "SELECT DISTINCT f.pkg_name, f.installed_version, f.fixed_version, f.severity, f.title, f.primary_url"
        " FROM image_result r CROSS JOIN finding f ON f.image_result_id = r.id"  # CROSS: the run's images first
        " WHERE r.run_id = ? AND f.vuln_id = ?"
        " ORDER BY f.pkg_name, f.installed_version, f.fixed_version, f.severity",
        (run_id, vuln_id),
    )
    return [dict(row) for row in rows]


def cve_images(conn: sqlite3.Connection, run_id: int, vuln_id: str) -> list[str]:
    """The distinct image refs of the run that have ``vuln_id``, sorted (an image with no workload included)."""
    rows = conn.execute(
        "SELECT DISTINCT r.ref FROM image_result r CROSS JOIN finding f ON f.image_result_id = r.id"  # CROSS: as above
        " WHERE r.run_id = ? AND f.vuln_id = ? ORDER BY r.ref",
        (run_id, vuln_id),
    )
    return [row["ref"] for row in rows]


def cve_severity_by_ref(conn: sqlite3.Connection, run_id: int, vuln_id: str) -> dict[str, str]:
    """The highest severity the run reports for ``vuln_id`` in each image that has it, by ref."""
    rows = conn.execute(
        "SELECT DISTINCT r.ref, f.severity FROM image_result r CROSS JOIN finding f ON f.image_result_id = r.id"
        " WHERE r.run_id = ? AND f.vuln_id = ?",
        (run_id, vuln_id),
    )
    worst: dict[str, str] = {}
    for ref, severity in rows:
        if ref not in worst or _severity_order(severity) < _severity_order(worst[ref]):
            worst[ref] = severity
    return worst


def _severity_order(severity: str) -> int:
    """0 for Critical down to the last place for Unknown (and anything Trivy might add)."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def top_findings(conn: sqlite3.Connection, run_id: int, ref: str, limit: int = 10) -> list[dict]:
    """The image's worst finding units, in the findings page's severity order (severity, then CVE, then package)."""
    rows = conn.execute(
        f"WITH units AS ({REF_UNITS_SQL}) SELECT vuln_id, pkg_name, severity, fixed_version"  # noqa: S608
        " FROM units ORDER BY sev_rank DESC, vuln_id, pkg_name, installed_version LIMIT :limit",
        {"run": run_id, "refs": json.dumps([ref]), "limit": limit},
    )
    return [dict(row) for row in rows]


def top_workload_facts(conn: sqlite3.Connection, run_id: int, refs: list[str]) -> dict[str, WorkloadFacts | None]:
    """The facts of each of ``refs``' riskiest workload row in the run (the most ``risk_points``, then by namespace,
    kind, name and container), which the fix lists' scores counted. A ref with no workload row, or whose riskiest row
    has no facts, maps to None.
    """
    top = dict.fromkeys(refs)
    if not refs:
        return top
    rows = conn.execute(
        "SELECT ref, facts FROM (SELECT r.ref, w.facts, ROW_NUMBER() OVER (PARTITION BY r.ref"  # noqa: S608
        f" ORDER BY COALESCE(w.risk_points, {NO_FACTS_POINTS}) DESC, w.namespace, w.kind, w.name, w.container) AS rn"
        " FROM image_result r JOIN workload w ON w.image_result_id = r.id"
        " WHERE r.run_id = :run AND r.ref IN (SELECT value FROM json_each(:refs))) WHERE rn = 1",
        {"run": run_id, "refs": json.dumps(refs)},
    )
    for row in rows:
        top[row["ref"]] = parse_facts(row["facts"])
    return top
