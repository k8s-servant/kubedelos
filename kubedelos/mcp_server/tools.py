"""The query functions behind the MCP tools: plain functions over a read-only connection that return JSON-ready dicts.

They are kept apart from the SDK wiring in ``server.py`` so they can be tested, and reused by every tool, without a
protocol round trip. Errors that the agent should read are raised as ``ToolError``.
"""

import contextlib
import dataclasses
import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver.exceptions import ToolError

from kubedelos import analytics, risk
from kubedelos.models import WorkloadFacts
from kubedelos.risk import NO_INTEL, host_access
from kubedelos.store import accepted, diff, intel, queries, workloads
from kubedelos.store.db import MIGRATIONS, connect_readonly

DEFAULT_LIMIT = 25
MAX_LIMIT = 100
MAX_PAGE = 10**9  # as the UI's findings page: keeps the SQL offset within SQLite's 64-bit integer


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
        try:
            conn = connect_readonly(self.path)
            try:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
            except sqlite3.Error:
                conn.close()
                raise
        except sqlite3.Error as exc:
            raise ToolError(f"cannot read the database at {self.path}: {exc}") from exc
        if version < len(MIGRATIONS):
            conn.close()
            raise ToolError(
                f'the database at {self.path} was written by an older kubedelos; open "kubedelos ui" once to update it'
            )
        if version > len(MIGRATIONS):
            conn.close()
            raise ToolError(
                f"the database at {self.path} was written by a newer kubedelos; upgrade kubedelos or restart the MCP "
                "server"
            )
        return conn


def clamp(limit: int, default: int = DEFAULT_LIMIT) -> int:
    """``limit`` bounded to ``MAX_LIMIT``; zero or below means ``default``. Large values are clamped, not refused."""
    return default if limit <= 0 else min(limit, MAX_LIMIT)


def resolve_cluster(conn: sqlite3.Connection, db: Db, cluster: str | None) -> str:
    """The key of the cluster to query. ``cluster`` (else ``--context``) may be a key or a context name, which stands
    for the cluster of the newest run made through it, as in the UI; with neither, the cluster with the newest finished
    result run."""
    scans = queries.cluster_scans(conn)
    if not scans:
        raise ToolError(f'no scans yet in {db.path}; run "kubedelos ui" and start a scan first')
    wanted = cluster or db.default_cluster
    if wanted is None:
        finished = {s.cluster: s.finished_at for s in scans if s.finished_at is not None}
        key = max(finished, key=lambda k: finished[k]) if finished else None
    else:
        key = _match(conn, scans, wanted)
    if key is None:
        known = sorted(queries.listed_name(conn, s) for s in scans)
        raise ToolError(f"unknown cluster {wanted}; known: {', '.join(known)}")
    return key


def _match(conn: sqlite3.Connection, scans: list[queries.ClusterScan], wanted: str) -> str | None:
    """The key ``wanted`` names: a key, else the cluster of the newest run made through that context, as in the UI."""
    if any(wanted == scan.cluster for scan in scans):
        return wanted
    return queries.context_cluster(conn, wanted)


def cluster_name(conn: sqlite3.Connection, key: str) -> str:
    """What the payloads call the cluster ``key``: the name ``list_clusters`` lists it under, else the key."""
    return next((queries.listed_name(conn, s) for s in queries.cluster_scans(conn) if s.cluster == key), key)


def _dashboard_run(conn: sqlite3.Connection, cluster: str) -> queries.Run | None:
    """The run the dashboard shows: the newest whole-cluster result run, else the newest result run of any scope."""
    return queries.newest_run(conn, cluster, cluster_scope=True) or queries.newest_run(
        conn, cluster, cluster_scope=False
    )


def run_payload(run: queries.Run, now: datetime) -> dict:
    """The run every tool reports on, with what makes its picture incomplete: failed images and coverage gaps."""
    return {
        "number": run.number,
        "status": run.status,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "scope": analytics.describe_scope(run.scope),
        "stale": analytics.is_stale(run.finished_at, now),
        "images_failed": run.images_failed,
        "coverage_gaps": len(run.gaps),
        "fact_sources": run.fact_sources,
    }


def list_clusters(conn: sqlite3.Connection, db: Db, now: datetime) -> dict:
    """Every cluster with a run: its name, key, the contexts its runs went through, and how fresh its dashboard run is."""
    scans = queries.cluster_scans(conn)
    clusters = []
    for scan in scans:
        run = _dashboard_run(conn, scan.cluster)
        clusters.append(
            {
                "name": queries.listed_name(conn, scan),
                "key": scan.cluster,
                "contexts": list(scan.contexts),
                "last_scan": scan.finished_at.isoformat() if scan.finished_at else None,
                "status": run.status if run else None,
                "stale": analytics.is_stale(scan.finished_at, now),
                "newest_run": run.number if run else None,
            }
        )
    clusters.sort(key=lambda c: (c["name"], c["key"]))
    default = None
    if scans:
        with contextlib.suppress(ToolError):  # a --context with no scans leaves no default
            default = cluster_name(conn, resolve_cluster(conn, db, None))
    return {"clusters": clusters, "default": default}


def _jsonable(value: Any) -> Any:
    """``value`` with dates as ISO strings and tuples as lists, so it serialises as JSON."""
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(item) for item in value]
    return value


def select_run(conn: sqlite3.Connection, cluster: str, run: int | None) -> queries.Run:
    """The run a tool reports on: number ``run`` of the cluster, else the one the dashboard shows."""
    if run is not None:
        found = queries.run_by_number(conn, cluster, run)
        if found is None:
            raise ToolError(f"no run {run} for {cluster_name(conn, cluster)}")
        return found
    found = _dashboard_run(conn, cluster)
    if found is None:
        raise ToolError(f"{cluster_name(conn, cluster)} has no finished scan yet")
    return found


def run_summary(
    conn: sqlite3.Connection, db: Db, now: datetime, cluster: str | None = None, run: int | None = None
) -> dict:
    name = resolve_cluster(conn, db, cluster)
    selected = select_run(conn, name, run)
    previous = queries.previous_comparable(conn, selected)
    return {
        "cluster": cluster_name(conn, name),
        "run": run_payload(selected, now),
        "kpis": _jsonable(dataclasses.asdict(queries.kpis(conn, selected.id))),
        "coverage_gaps": selected.gaps,
        "failed": [{"kind": kind, "count": count} for kind, count in queries.failure_kinds(conn, selected.id)],
        "previous_run": previous.number if previous else None,
    }


def fix_first(
    conn: sqlite3.Connection,
    db: Db,
    now: datetime,
    cluster: str | None = None,
    run: int | None = None,
    view: Literal["fix", "image"] = "fix",
    limit: int = DEFAULT_LIMIT,
) -> dict:
    name = resolve_cluster(conn, db, cluster)
    selected = select_run(conn, name, run)
    shown = intel.risk_shown(conn, selected.id)
    fixes = (queries.fix_by_image if view == "image" else queries.fix_by_fix)(
        conn, selected.id, limit=clamp(limit), scored=shown
    )
    items = []
    for row in fixes.rows:
        item = _jsonable(dataclasses.asdict(row))
        item["factors"] = _factors_payload(row.factors)
        items.append(item)
    return {
        "cluster": cluster_name(conn, name),
        "run": run_payload(selected, now),
        "view": view,
        "items": items,
        "total": fixes.total,
        "truncated": fixes.total > len(items),
        "no_fix": fixes.no_fix,
        "no_fix_images": fixes.no_fix_images,
        "accepted": fixes.accepted,
        "risk": _risk_payload(conn, selected.id, shown),
    }


def _factors_payload(factors: Iterable[risk.Factor]) -> list[dict]:
    """The score's factors as JSON: the name as ``factor``, its points and the reason."""
    return [{"factor": f.name, "points": f.points, "detail": f.detail} for f in factors]


def _risk_payload(conn: sqlite3.Connection, run_id: int, shown: bool) -> dict:
    """Whether the run's scores are shown, whether it has facts, and when each threat feed was last fetched."""
    fetched = intel.feeds(conn)
    return {
        "shown": shown,
        "facts": intel.run_has_facts(conn, run_id),
        "feeds": {name: fetched[name].isoformat() if name in fetched else None for name in ("kev", "epss")},
    }


def _facts_payload(facts: WorkloadFacts | None) -> dict | None:
    """The facts as v1 JSON, or None; never a made-up default, so "not collected" stays distinguishable."""
    return facts.model_dump(mode="json") if facts else None


_EXPOSURE_RANK = {"external": 0, "unknown": 1, "cluster": 2, "none": 3}
_NO_FACTS_RANK = _EXPOSURE_RANK["unknown"]  # not collected is as exposed as could not be read, never less


def exposure_key(row: workloads.WorkloadRow) -> tuple:
    """The order the workload lists share: most exposed first (no facts with unknown), then Critical, then High.

    ``attack_surface`` sorts by it alone. ``find_vulnerability`` sorts by risk score first while ``risk.shown`` is
    true, and by it otherwise (and to break score ties).
    """
    return (
        _EXPOSURE_RANK[row.facts.exposure.level] if row.facts else _NO_FACTS_RANK,
        -row.counts["CRITICAL"],
        -row.counts["HIGH"],
        row.namespace,
        row.name,
        row.container,
    )


def normalise_vuln_id(vuln_id: str) -> str:
    """``vuln_id`` stripped, and upper-cased when it is a CVE id (Trivy writes those upper case); others stay as given."""
    vuln_id = vuln_id.strip()
    return vuln_id.upper() if vuln_id[:4].lower() == "cve-" else vuln_id


def find_vulnerability(
    conn: sqlite3.Connection,
    db: Db,
    now: datetime,
    vuln_id: str,
    cluster: str | None = None,
    run: int | None = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict:
    name = resolve_cluster(conn, db, cluster)
    selected = select_run(conn, name, run)
    vuln_id = normalise_vuln_id(vuln_id)
    found = intel.intel_for(conn, [vuln_id]).get(vuln_id, NO_INTEL)
    shown = intel.risk_shown(conn, selected.id)
    rows = workloads.workloads(conn, selected.id, vuln_id=vuln_id)
    scores: dict[int, risk.Score] = {}
    if shown:
        severities = workloads.cve_severity_by_ref(conn, selected.id, vuln_id)
        scores = {id(row): risk.score(severities.get(row.ref, "UNKNOWN"), found, row.facts) for row in rows}
        rows.sort(key=lambda row: (-scores[id(row)].points, *exposure_key(row)))
    else:
        rows.sort(key=exposure_key)
    start = max(offset, 0)
    page = rows[start : start + clamp(limit)]
    packages = workloads.cve_packages(conn, selected.id, vuln_id)
    images = workloads.cve_images(conn, selected.id, vuln_id)
    items = [
        {
            "namespace": row.namespace,
            "kind": row.kind,
            "name": row.name,
            "container": row.container,
            "image": row.ref,
            "facts": _facts_payload(row.facts),
            "score": scores[id(row)].points if shown else None,
            "factors": _factors_payload(scores[id(row)].factors) if shown else [],
        }
        for row in page
    ]
    active = [e for e in accepted.register(conn, name, selected.id, now.date(), vuln_id) if e.state == "active"]
    return {
        "cluster": cluster_name(conn, name),
        "run": run_payload(selected, now),
        "vuln_id": vuln_id,
        "kev": found.kev if "kev" in intel.feeds(conn) else None,  # no KEV copy: unknown, never "not listed"
        "kev_added": found.kev_added.isoformat() if found.kev_added else None,
        "epss": found.epss,
        "epss_percentile": found.percentile,
        "risk": _risk_payload(conn, selected.id, shown),
        "packages": packages[:MAX_LIMIT],
        "packages_total": len(packages),
        "images": images[:MAX_LIMIT],
        "images_total": len(images),
        "workloads": items,
        "total": len(rows),
        "truncated": start + len(page) < len(rows),
        "acceptance": [
            {
                "id": e.id,
                "namespace": e.namespace,
                "repo": e.repo,
                "pkg_name": e.pkg_name,
                "reason": e.reason,
                "owner": e.owner,
                "expires_at": e.expires.isoformat(),
            }
            for e in active
        ],
    }


def workload(
    conn: sqlite3.Connection,
    db: Db,
    now: datetime,
    namespace: str,
    name: str,
    kind: str | None = None,
    cluster: str | None = None,
    run: int | None = None,
) -> dict:
    key = resolve_cluster(conn, db, cluster)
    selected = select_run(conn, key, run)
    rows = workloads.workloads(conn, selected.id, namespace=namespace, name=name, kind=kind)
    if not rows:
        raise ToolError(f"no workload {namespace}/{name} in run {selected.number}")
    top = {ref: workloads.top_findings(conn, selected.id, ref) for ref in sorted({row.ref for row in rows})}
    return {
        "cluster": cluster_name(conn, key),
        "run": run_payload(selected, now),
        "containers": [
            {
                "kind": row.kind,
                "container": row.container,
                "image": row.ref,
                "counts": row.counts,
                "facts": _facts_payload(row.facts),
                "top_findings": top[row.ref],
            }
            for row in rows
        ],
    }


def _severity_names(names: list[str] | None) -> tuple[str, ...]:
    """``names`` upper-cased and checked against the severities; an unknown one is an error the agent can read."""
    wanted = tuple(name.strip().upper() for name in names or ())
    for given, upper in zip(names or (), wanted, strict=True):
        if upper not in workloads.SEVERITIES:
            raise ToolError(
                f"unknown severity {given}; use {', '.join(workloads.SEVERITIES[:-1])} or {workloads.SEVERITIES[-1]}"
            )
    return wanted


def list_findings(
    conn: sqlite3.Connection,
    db: Db,
    now: datetime,
    cluster: str | None = None,
    run: int | None = None,
    severity: list[str] | None = None,
    namespace: str | None = None,
    pkg_class: Literal["all", "os", "library"] = "all",
    q: str | None = None,
    fixable: Literal["any", "yes", "no"] = "any",
    accepted: Literal["hide", "only", "all"] = "hide",
    page: int = 1,
    per_page: int = DEFAULT_LIMIT,
) -> dict:
    name = resolve_cluster(conn, db, cluster)
    selected = select_run(conn, name, run)
    f = queries.FindingFilter(
        severities=_severity_names(severity),
        namespace=namespace or None,
        pkg=pkg_class,
        q=q or None,
        has_fix=fixable,
        accepted=accepted,
    )
    page, per_page = min(max(page, 1), MAX_PAGE), clamp(per_page)
    rows, total, left_out = queries.findings_page(conn, selected.id, f, page, per_page, today=now.date())
    return {
        "cluster": cluster_name(conn, name),
        "run": run_payload(selected, now),
        "items": [_finding_item(row) for row in rows],
        "total": total,
        "truncated": page * per_page < total,
        "page": page,
        "per_page": per_page,
        "accepted_left_out": left_out,
    }


def _finding_item(row: sqlite3.Row) -> dict:
    """One findings-page row as JSON: the unit's columns, its namespaces and targets as lists, ``accepted`` a bool."""
    item = {key: row[key] for key in row.keys() if key not in ("total", "left_out", "sev_rank")}  # noqa: SIM118
    item["namespaces"] = json.loads(row["namespaces"])
    item["targets"] = row["targets"].split(",") if row["targets"] else []
    item["accepted"] = bool(row["accepted"])
    return item


def _matches_facts(
    facts: WorkloadFacts | None,
    exposure: list[str] | None,
    privileged: bool | None,
    host: bool | None,
    rights: list[str] | None,
) -> bool:
    """Whether ``facts`` pass every facts filter given; a workload without facts passes only when none is given."""
    if exposure is None and privileged is None and host is None and not rights:
        return True
    if facts is None:
        return False
    return (
        (exposure is None or facts.exposure.level in exposure)
        and (privileged is None or facts.pod.privileged is privileged)
        and (host is None or host_access(facts) is host)
        # Rights that could not be worked out (not "ok") might include the one asked for, so they match.
        and (not rights or facts.rights.status != "ok" or any(getattr(facts.rights, flag) for flag in rights))
    )


def attack_surface(
    conn: sqlite3.Connection,
    db: Db,
    now: datetime,
    cluster: str | None = None,
    run: int | None = None,
    exposure: list[Literal["external", "cluster", "none", "unknown"]] | None = None,
    privileged: bool | None = None,
    host: bool | None = None,
    rights: list[Literal["cluster_admin", "reads_secrets", "creates_workloads", "pod_exec", "escalates", "wildcard"]]
    | None = None,
    min_severity: Literal["CRITICAL", "HIGH"] | None = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict:
    name = resolve_cluster(conn, db, cluster)
    selected = select_run(conn, name, run)
    rows = workloads.workloads(conn, selected.id)
    kept = [
        row
        for row in rows
        if _matches_facts(row.facts, exposure, privileged, host, rights)
        and (min_severity is None or row.counts["CRITICAL"] > 0 or (min_severity == "HIGH" and row.counts["HIGH"] > 0))
    ]
    kept.sort(key=exposure_key)
    start = max(offset, 0)
    page = kept[start : start + clamp(limit)]
    return {
        "cluster": cluster_name(conn, name),
        "run": run_payload(selected, now),
        "facts_collected": any(row.facts is not None for row in rows),
        "items": [
            {
                "namespace": row.namespace,
                "kind": row.kind,
                "name": row.name,
                "container": row.container,
                "image": row.ref,
                "critical": row.counts["CRITICAL"],
                "high": row.counts["HIGH"],
                "host_access": host_access(row.facts) if row.facts else None,
                "rights_status": row.facts.rights.status if row.facts else None,
                "facts": _facts_payload(row.facts),
            }
            for row in page
        ],
        "total": len(kept),
        "truncated": start + len(page) < len(kept),
    }


def compare_runs(
    conn: sqlite3.Connection,
    db: Db,
    now: datetime,
    cluster: str | None = None,
    from_run: int | None = None,
    to_run: int | None = None,
    limit: int = DEFAULT_LIMIT,
) -> dict:
    name = resolve_cluster(conn, db, cluster)
    new = select_run(conn, name, to_run)
    old = select_run(conn, name, from_run) if from_run is not None else queries.previous_comparable(conn, new)
    if old is None:
        raise ToolError("no earlier comparable run to compare with; pass from_run")
    result = _jsonable(dataclasses.asdict(diff.compare(conn, old.id, new.id, clamp(limit))))
    return {"cluster": cluster_name(conn, name), "from": run_payload(old, now), "to": run_payload(new, now), **result}


def accepted_risks(
    conn: sqlite3.Connection,
    db: Db,
    now: datetime,
    cluster: str | None = None,
    state: Literal["active", "all"] = "active",
) -> dict:
    name = resolve_cluster(conn, db, cluster)
    run = _dashboard_run(conn, name)
    entries = accepted.register(conn, name, run.id if run else None, now.date())
    return {
        "cluster": cluster_name(conn, name),
        "state": state,
        "entries": [
            _jsonable(dataclasses.asdict(entry)) for entry in entries if state == "all" or entry.state == "active"
        ],
    }
