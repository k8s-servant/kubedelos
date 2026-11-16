"""Read-only queries that pick which scan run a UI page shows, and describe it.

Only runs that finished with results (``ok`` or ``partial``) are ever shown as results; the run history lists every run
but links only those. Kept apart from ``Repo`` because these are
the reads the UI makes on a read-only connection, and the counting rules (an image is a distinct ref, not a platform
row) live in one place. The work lists (the fix lists and the findings page) leave accepted units out, matched on
read by ``kubedelos.store.accepted`` against ``today``; nothing that counts does.
"""

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Literal, get_args

from kubedelos.store.accepted import ACCEPTED_CTES
from kubedelos.store.repo import RETRY_NOTE_PREFIX
from kubedelos.trivy.runner import ErrorKind

RESULT_STATUSES = ("ok", "partial")
_STATUS_SQL = "(" + ", ".join(f"'{s}'" for s in RESULT_STATUSES) + ")"

# Whole-cluster runs: no namespace list and no selectors. Exclusions do not narrow a run. NULL scope (not recorded) never matches.
CLUSTER_SCOPE_SQL = (
    "scope IS NOT NULL AND json_array_length(scope, '$.namespaces') = 0"
    " AND json_extract(scope, '$.namespace_selector') IS NULL AND json_extract(scope, '$.selector') IS NULL"
)

_RUN_SQL = """
SELECT id, number, context, status, finished_at, pkg_types, scope, trivy_version,
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
    id: int  # the key, used in URLs
    number: int  # the run's number within its context, which the UI shows
    context: str | None
    status: str
    finished_at: datetime | None
    pkg_types: str | None
    scope: dict | None
    images: int
    images_failed: int
    trivy_version: str | None = None
    gaps: list[str] = field(default_factory=list)


def _build(conn: sqlite3.Connection, row: sqlite3.Row) -> Run:
    gaps = conn.execute("SELECT text FROM run_warning WHERE run_id = ? AND coverage = 1 ORDER BY id", (row["id"],))
    return Run(
        id=row["id"],
        number=row["number"],
        context=row["context"],
        status=row["status"],
        finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
        pkg_types=row["pkg_types"],
        scope=json.loads(row["scope"]) if row["scope"] else None,
        images=row["images"],
        images_failed=row["images_failed"],
        trivy_version=row["trivy_version"],
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
        raise RunNotShown(f"that run belongs to context {row['context']}, not {context}")
    if row["status"] not in RESULT_STATUSES:
        raise RunNotShown(f"run {row['number']} is {row['status']}, so it has no results to show")
    return _build(conn, row)


@dataclass(frozen=True)
class RunChoice:
    """One result run in a picker."""

    id: int
    number: int
    finished_at: datetime | None
    scope: dict | None
    pkg_types: str | None


def result_runs(conn: sqlite3.Connection, context: str, limit: int = 200) -> list[RunChoice]:
    """The context's newest result runs, newest first, for a picker."""
    rows = conn.execute(
        f"SELECT id, number, finished_at, scope, pkg_types FROM scan_run WHERE context = ? AND status IN {_STATUS_SQL}"  # noqa: S608
        " ORDER BY id DESC LIMIT ?",
        (context, limit),
    )
    return [
        RunChoice(
            id=r["id"],
            number=r["number"],
            finished_at=datetime.fromisoformat(r["finished_at"]) if r["finished_at"] else None,
            scope=json.loads(r["scope"]) if r["scope"] else None,
            pkg_types=r["pkg_types"],
        )
        for r in rows
    ]


def previous_comparable(conn: sqlite3.Connection, run: Run) -> Run | None:
    """The newest earlier result run with the same context, scope text and package types; NULL scope never matches."""
    row = conn.execute(
        f"{_RUN_SQL} WHERE id < :id AND context = :context AND status IN {_STATUS_SQL}"  # noqa: S608 - only module constants are interpolated
        " AND scope IS NOT NULL AND scope = (SELECT scope FROM scan_run WHERE id = :id)"
        " AND pkg_types IS (SELECT pkg_types FROM scan_run WHERE id = :id) ORDER BY id DESC LIMIT 1",
        {"id": run.id, "context": run.context},
    ).fetchone()
    return _build(conn, row) if row else None


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _today(today: date | None) -> str:
    """The ``:today`` parameter of ``ACCEPTED_CTES``: the given day, or today in UTC."""
    return (today or datetime.now(UTC).date()).isoformat()


# Whether the unit ``{u}`` (a row with ref, vuln_id, pkg_name, installed_version) is in ``accepted``.
_IS_ACCEPTED_SQL = (
    "EXISTS (SELECT 1 FROM accepted a WHERE a.ref = {u}.ref AND a.vuln_id = {u}.vuln_id"
    " AND a.pkg_name IS {u}.pkg_name AND a.installed_version IS {u}.installed_version)"
)

# The severity rank of a finding row; shared so the counts and the units agree.
_RANK_SQL = (
    "CASE f.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END"
)
_SEVERITY_OF_RANK_SQL = (
    "CASE {rank} WHEN 4 THEN 'CRITICAL' WHEN 3 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' WHEN 1 THEN 'LOW' ELSE 'UNKNOWN' END"
)
_UNIT_KEY_SQL = "r.ref, f.vuln_id, f.pkg_name, f.installed_version"

# One row per finding unit: a distinct (ref, vuln_id, pkg_name, installed_version) within the run, so a second platform
# or a second target never counts twice. Disagreeing duplicates take the highest severity. Use as
# ``WITH units AS (<this>)`` with the parameter ``:run``.
FINDING_UNITS_SQL = f"""
SELECT r.ref, MAX(r.repo) AS repo, MAX(r.tag) AS tag, MAX(r.digest) AS digest,
       f.vuln_id, f.pkg_name, f.installed_version,
       MAX(f.fixed_version) AS fixed_version,
       MAX({_RANK_SQL}) AS sev_rank,
       {_SEVERITY_OF_RANK_SQL.format(rank=f"MAX({_RANK_SQL})")} AS severity,
       MAX(f.pkg_class) AS pkg_class,
       MAX(f.title) AS title,
       MAX(f.primary_url) AS primary_url,
       group_concat(DISTINCT f.target) AS targets
FROM image_result r
JOIN finding f ON f.image_result_id = r.id
WHERE r.run_id = :run
GROUP BY {_UNIT_KEY_SQL}
"""  # noqa: S608 - only module constants are interpolated

# The counting-only form of the units: no text columns, so it is several times cheaper on a large run.
_UNIT_COUNTS_SQL = f"""
SELECT r.ref, MAX({_RANK_SQL}) AS sev_rank
FROM image_result r
JOIN finding f ON f.image_result_id = r.id
WHERE r.run_id = :run
GROUP BY {_UNIT_KEY_SQL}
"""  # noqa: S608 - only module constants are interpolated


@dataclass(frozen=True)
class Kpis:
    critical: int
    high: int
    images_with_critical: int
    images: int
    findings: int
    images_failed: int
    by_severity: dict[str, int]


def kpis(conn: sqlite3.Connection, run_id: int) -> Kpis:
    """The dashboard numbers for one run, in the counting units of ``FINDING_UNITS_SQL``."""
    by_severity = dict.fromkeys(_SEVERITIES, 0)
    critical_images = 0
    rows = conn.execute(
        f"WITH units AS ({_UNIT_COUNTS_SQL}) SELECT sev_rank, COUNT(*) AS n, COUNT(DISTINCT ref) AS images"  # noqa: S608
        " FROM units GROUP BY sev_rank",
        {"run": run_id},
    )
    for row in rows:
        severity = _SEVERITIES[4 - row["sev_rank"]]
        by_severity[severity] = row["n"]
        if severity == "CRITICAL":
            critical_images = row["images"]
    counts = conn.execute(
        "SELECT COUNT(DISTINCT ref) AS images, COUNT(DISTINCT CASE WHEN status = 'error' THEN ref END) AS failed"
        " FROM image_result WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    return Kpis(
        critical=by_severity["CRITICAL"],
        high=by_severity["HIGH"],
        images_with_critical=critical_images,
        images=counts["images"],
        findings=sum(by_severity.values()),
        images_failed=counts["failed"],
        by_severity=by_severity,
    )


SAMPLE_CAP = 20

# The units the fix lists need: Critical and High rows only, with the fix a unit has (MAX picks a version over an empty
# one when platforms disagree). Only columns idx_finding_unit holds, so a run's units come from the index alone; the
# CVE link is fetched for the page's groups. ``{columns}`` adds columns and ``{source}`` lets a caller narrow the rows
# early. ``:run`` as above.
_FIX_UNITS_TEMPLATE = f"""
SELECT r.ref, f.vuln_id, f.pkg_name, f.installed_version,
       MAX(COALESCE(f.fixed_version, '')) AS fixed_version,
       MAX({_RANK_SQL}) AS sev_rank{{columns}}
FROM {{source}}
WHERE r.run_id = :run AND f.severity IN ('CRITICAL', 'HIGH')
GROUP BY {_UNIT_KEY_SQL}
"""  # noqa: S608 - only module constants are interpolated
_FIX_UNITS_SQL = _FIX_UNITS_TEMPLATE.format(
    columns="", source="image_result r JOIN finding f ON f.image_result_id = r.id"
)

# The distinct namespaces each image runs in within the run (a second platform repeats its workloads). Every ref has a
# row, with a NULL namespace when it has no workload, so an inner JOIN on ref never drops an image.
_NAMESPACES_SQL = """
SELECT DISTINCT r.ref, w.namespace
FROM image_result r
LEFT JOIN workload w ON w.image_result_id = r.id
WHERE r.run_id = :run
"""

# Only the rows of the CVE and package pairs on the page, so the sample query groups a few rows, not the whole run.
# CROSS JOIN fixes the loop order: the run's image rows first, then each wanted pair by (image row, CVE) in
# idx_finding_unit. Left to itself the planner looks the CVEs up in idx_finding_vuln, which reads them in every run
# kept, and the top fix groups are exactly the CVEs found in the most images.
_SAMPLE_UNITS_SQL = _FIX_UNITS_TEMPLATE.format(
    columns=",\n       MAX(f.primary_url) AS primary_url",
    source="image_result r CROSS JOIN wanted wa CROSS JOIN finding f"
    " ON f.image_result_id = r.id AND f.vuln_id = wa.vuln_id AND f.pkg_name IS wa.pkg_name",
)


@dataclass(frozen=True)
class FixRow:
    vuln_id: str
    pkg_name: str | None
    fixed_version: str
    severity: str
    installed: list[str]
    primary_url: str | None
    images: int
    namespaces: int
    sample: list[tuple[str, list[str]]]


@dataclass(frozen=True)
class ImageFixRow:
    ref: str
    namespaces: list[str]
    critical: int
    high: int
    fixable: int


@dataclass(frozen=True)
class FixList[T]:
    """One capped fix list, how many rows it has in all, the Critical/High units that have no fix (and images), and
    how many Critical/High units the list left out as accepted.
    """

    rows: list[T]
    total: int
    no_fix: int
    no_fix_images: int
    accepted: int


def _fix_list(
    conn: sqlite3.Connection, run_id: int, listing: str, order: str, limit: int, today: date | None
) -> list[sqlite3.Row]:
    """``listing`` (a SELECT over ``units`` and ``ns`` with a ``total`` column) in ``order``, capped at ``limit``, beside
    the no-fix numbers of the same units, so one pass over the run's Critical/High units serves the list and the no-fix
    line. ``units`` holds the units that are not accepted; ``accepted`` is how many were left out. There is always one
    row: an empty list leaves the listing's columns NULL.
    """
    return conn.execute(
        f"WITH every AS MATERIALIZED ({_FIX_UNITS_SQL}), ns AS MATERIALIZED ({_NAMESPACES_SQL}), {ACCEPTED_CTES},"  # noqa: S608
        f" units AS MATERIALIZED (SELECT * FROM every x WHERE NOT {_IS_ACCEPTED_SQL.format(u='x')})"
        " SELECT s.no_fix, s.no_fix_images, s.accepted, l.* FROM"
        " (SELECT COUNT(*) AS no_fix, COUNT(DISTINCT ref) AS no_fix_images,"
        "   (SELECT COUNT(*) FROM every) - (SELECT COUNT(*) FROM units) AS accepted"
        "  FROM units WHERE fixed_version = '') s"
        f" LEFT JOIN (SELECT * FROM ({listing}) ORDER BY {order} LIMIT :limit) l ON 1 ORDER BY {order}",
        {"run": run_id, "limit": limit, "today": _today(today)},
    ).fetchall()


def fix_by_fix(conn: sqlite3.Connection, run_id: int, limit: int = 25, *, today: date | None = None) -> FixList[FixRow]:
    """The first ``limit`` fixes (CVE, package, fixed version) that clear Critical/High findings, and how many there are."""
    found = _fix_list(
        conn,
        run_id,
        "SELECT u.vuln_id, u.pkg_name, u.fixed_version, MAX(u.sev_rank) AS sev_rank,"
        " json_group_array(DISTINCT u.installed_version) AS installed,"
        " COUNT(DISTINCT u.ref) AS images, COUNT(DISTINCT ns.namespace) AS namespaces, COUNT(*) OVER () AS total"
        " FROM units u JOIN ns ON ns.ref = u.ref WHERE u.fixed_version <> ''"
        " GROUP BY u.vuln_id, u.pkg_name, u.fixed_version",
        "sev_rank DESC, images DESC, namespaces DESC, vuln_id, pkg_name, fixed_version",
        limit,
        today,
    )
    groups = [g for g in found if g["vuln_id"] is not None]
    samples = _samples(conn, run_id, groups, today) if groups else {}
    rows = [
        FixRow(
            vuln_id=g["vuln_id"],
            pkg_name=g["pkg_name"],
            fixed_version=g["fixed_version"],
            severity=_SEVERITIES[4 - g["sev_rank"]],
            installed=sorted(v for v in json.loads(g["installed"]) if v is not None),
            primary_url=samples[(g["vuln_id"], g["pkg_name"], g["fixed_version"])][1],
            images=g["images"],
            namespaces=g["namespaces"],
            sample=samples[(g["vuln_id"], g["pkg_name"], g["fixed_version"])][0],
        )
        for g in groups
    ]
    return FixList(
        rows, groups[0]["total"] if groups else 0, found[0]["no_fix"], found[0]["no_fix_images"], found[0]["accepted"]
    )


def _samples(
    conn: sqlite3.Connection, run_id: int, groups: list[sqlite3.Row], today: date | None
) -> dict[tuple, tuple[list, str | None]]:
    """For each of the page's groups, up to ``SAMPLE_CAP`` (ref, namespaces) pairs and the group's CVE link, in one
    query. Accepted units are left out, as the groups left them out.
    """
    params: dict[str, object] = {"run": run_id, "cap": SAMPLE_CAP, "today": _today(today)}
    values = []
    for i, g in enumerate(groups):
        params.update({f"v{i}": g["vuln_id"], f"p{i}": g["pkg_name"], f"f{i}": g["fixed_version"]})
        values.append(f"(:v{i}, :p{i}, :f{i})")
    rows = conn.execute(
        f"WITH wanted(vuln_id, pkg_name, fixed_version) AS (VALUES {', '.join(values)}),"  # noqa: S608
        f" every AS MATERIALIZED ({_SAMPLE_UNITS_SQL}), ns AS MATERIALIZED ({_NAMESPACES_SQL}), {ACCEPTED_CTES},"
        f" units AS MATERIALIZED (SELECT * FROM every x WHERE NOT {_IS_ACCEPTED_SQL.format(u='x')}),"
        " ranked AS (SELECT g.vuln_id, g.pkg_name, g.fixed_version, g.ref,"
        "   MAX(g.primary_url) OVER (PARTITION BY g.vuln_id, g.pkg_name, g.fixed_version) AS group_url,"
        "   ROW_NUMBER() OVER (PARTITION BY g.vuln_id, g.pkg_name, g.fixed_version ORDER BY g.ref) AS rn"
        "   FROM (SELECT u.vuln_id, u.pkg_name, u.fixed_version, u.ref, MAX(u.primary_url) AS primary_url FROM units u"
        "     JOIN wanted wa ON wa.vuln_id = u.vuln_id AND wa.pkg_name IS u.pkg_name"
        "     AND wa.fixed_version = u.fixed_version GROUP BY u.vuln_id, u.pkg_name, u.fixed_version, u.ref"
        "   ) g)"
        " SELECT k.vuln_id, k.pkg_name, k.fixed_version, k.ref, k.group_url, ns.namespace"
        " FROM ranked k JOIN ns ON ns.ref = k.ref WHERE k.rn <= :cap ORDER BY k.ref, ns.namespace",
        params,
    )
    refs_of: dict[tuple, dict[str, list[str]]] = {}
    urls: dict[tuple, str | None] = {}
    for row in rows:
        key = (row["vuln_id"], row["pkg_name"], row["fixed_version"])
        urls[key] = row["group_url"]
        namespaces = refs_of.setdefault(key, {}).setdefault(row["ref"], [])
        if row["namespace"] is not None:
            namespaces.append(row["namespace"])
    return {key: (list(refs.items()), urls[key]) for key, refs in refs_of.items()}


def fix_by_image(
    conn: sqlite3.Connection, run_id: int, limit: int = 25, *, today: date | None = None
) -> FixList[ImageFixRow]:
    """The first ``limit`` images with a fixable Critical/High finding, worst first, and how many there are."""
    found = _fix_list(
        conn,
        run_id,
        "SELECT ref, SUM(sev_rank = 4) AS critical, SUM(sev_rank = 3) AS high, SUM(fixed_version <> '') AS fixable,"
        " COUNT(*) OVER () AS total FROM units GROUP BY ref HAVING fixable > 0",
        "critical DESC, high DESC, ref",
        limit,
        today,
    )
    rows = [r for r in found if r["ref"] is not None]
    namespaces: dict[str, list[str]] = {}
    if rows:
        for row in conn.execute(
            f"WITH ns AS MATERIALIZED ({_NAMESPACES_SQL}) SELECT ref, namespace FROM ns"  # noqa: S608
            " WHERE namespace IS NOT NULL AND ref IN (SELECT value FROM json_each(:refs)) ORDER BY namespace",
            {"run": run_id, "refs": json.dumps([r["ref"] for r in rows])},
        ):
            namespaces.setdefault(row["ref"], []).append(row["namespace"])
    result = [ImageFixRow(r["ref"], namespaces.get(r["ref"], []), r["critical"], r["high"], r["fixable"]) for r in rows]
    return FixList(
        result, rows[0]["total"] if rows else 0, found[0]["no_fix"], found[0]["no_fix_images"], found[0]["accepted"]
    )


@dataclass(frozen=True)
class WorstImage:
    """One image on the dashboard's worst images panel: its Critical and High counts."""

    ref: str
    critical: int
    high: int


def worst_images(conn: sqlite3.Connection, run_id: int, limit: int = 5) -> list[WorstImage]:
    """The ``limit`` images with the most Critical plus High findings, fixable or not, worst first."""
    rows = conn.execute(
        f"WITH units AS MATERIALIZED ({_FIX_UNITS_SQL})"  # noqa: S608 - only module constants are interpolated
        " SELECT ref, SUM(sev_rank = 4) AS critical, SUM(sev_rank = 3) AS high FROM units GROUP BY ref"
        " ORDER BY critical + high DESC, critical DESC, ref LIMIT :limit",
        {"run": run_id, "limit": limit},
    )
    return [WorstImage(r["ref"], r["critical"], r["high"]) for r in rows]


def failed_images(conn: sqlite3.Connection, run_id: int, limit: int = 25) -> tuple[list[sqlite3.Row], int]:
    """The images of a run that failed to scan, ordered by ref and platform, and how many failed in all."""
    rows = conn.execute(
        "SELECT ref, platform, error_kind, error FROM image_result WHERE run_id = ? AND status = 'error'"
        " ORDER BY ref, platform LIMIT ?",
        (run_id, limit),
    ).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) FROM image_result WHERE run_id = ? AND status = 'error'", (run_id,)
    ).fetchone()[0]
    return rows, total


@dataclass(frozen=True)
class RunLabel:
    """What a page needs to name any run, whatever its status."""

    id: int
    number: int
    context: str | None
    status: str


def run_label(conn: sqlite3.Connection, context: str, run_id: int) -> RunLabel:
    """The run ``run_id`` of ``context``, in any status; raises RunNotShown for a missing or another context's run."""
    row = conn.execute("SELECT id, number, context, status FROM scan_run WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        raise RunNotShown(f"no run {run_id}")
    if row["context"] != context:
        raise RunNotShown(f"that run belongs to context {row['context']}, not {context}")
    return RunLabel(row["id"], row["number"], row["context"], row["status"])


# A failure's error kind as the UI groups it: one of the kinds this version knows, and anything else (no kind, or a kind
# a newer version wrote) as "unknown".
_KIND_SQL = (
    "CASE WHEN {col} IN ("
    + ", ".join(f"'{k}'" for k in get_args(ErrorKind) if k != "unknown")
    + ") THEN {col} ELSE 'unknown' END"
)


def run_failures(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    limit: int,
    offset: int = 0,
    newest_first: bool = False,
    kind: str | None = None,
) -> tuple[list[sqlite3.Row], int]:
    """The run's failed (image, platform) rows with the namespaces the image runs in (a JSON array), by ref then
    platform or newest first, and how many there are in all. ``kind`` narrows both to one error kind (``unknown``
    also matches a row without a kind this version knows).
    """
    order = "r.id DESC" if newest_first else "r.ref, r.platform"
    narrow = f" AND {_KIND_SQL.format(col='r.error_kind')} = :kind" if kind else ""
    params = {"run": run_id, "kind": kind, "limit": limit, "offset": offset}
    rows = conn.execute(
        "SELECT r.ref, r.repo, r.tag, r.digest, r.platform, r.error_kind, r.error,"  # noqa: S608 - only constants
        " (SELECT json_group_array(namespace) FROM (SELECT DISTINCT w.namespace FROM image_result o"
        "   JOIN workload w ON w.image_result_id = o.id WHERE o.run_id = r.run_id AND o.ref = r.ref"
        "   ORDER BY w.namespace)) AS namespaces"
        f" FROM image_result r WHERE r.run_id = :run AND r.status = 'error'{narrow}"
        f" ORDER BY {order} LIMIT :limit OFFSET :offset",
        params,
    ).fetchall()
    total = conn.execute(
        f"SELECT COUNT(*) FROM image_result r WHERE r.run_id = :run AND r.status = 'error'{narrow}",  # noqa: S608
        params,
    ).fetchone()[0]
    return rows, total


def failure_kinds(conn: sqlite3.Connection, run_id: int) -> list[tuple[str, int]]:
    """How many of the run's images failed with each error kind, most first; a row without a kind this version knows
    counts as ``unknown``.
    """
    rows = conn.execute(
        f"SELECT {_KIND_SQL.format(col='error_kind')} AS kind, COUNT(*) AS n FROM image_result"  # noqa: S608 - constant
        " WHERE run_id = ? AND status = 'error' GROUP BY kind ORDER BY n DESC, kind",
        (run_id,),
    )
    return [(row["kind"], row["n"]) for row in rows]


def retry_notes(conn: sqlite3.Connection, run_id: int) -> list[str]:
    """The notes the retries of ``run_id``'s failed images left, oldest first."""
    rows = conn.execute(
        "SELECT text FROM run_warning WHERE run_id = ? AND coverage = 0 AND text LIKE ? ORDER BY id",
        (run_id, RETRY_NOTE_PREFIX + "%"),
    )
    return [row["text"] for row in rows]


def auth_failed_refs(conn: sqlite3.Connection, run_id: int) -> list[str]:
    """Every distinct ref of a run that failed with an authentication error, uncapped, for the login hints."""
    rows = conn.execute(
        "SELECT DISTINCT ref FROM image_result WHERE run_id = ? AND status = 'error' AND error_kind = 'auth'"
        " ORDER BY ref",
        (run_id,),
    )
    return [row["ref"] for row in rows]


@dataclass(frozen=True)
class FindingFilter:
    """What the findings page narrows to and how it orders the result. Empty values mean "no filter"."""

    severities: tuple[str, ...] = ()
    namespace: str | None = None
    cve: str | None = None
    package: str | None = None
    has_fix: Literal["any", "yes", "no"] = "any"
    pkg: Literal["all", "os", "library"] = "all"
    q: str | None = None
    sort: Literal["severity", "cve", "package", "image", "namespace", "fixed"] = "severity"
    desc: bool = True
    accepted: Literal["hide", "only", "all"] = "hide"


# The distinct namespaces of each image in the run, as a sorted JSON array plus the smallest one (for sorting). Inner
# JOIN: an image with no workload simply has no row here, and the page joins it back with a LEFT JOIN on a CTE of at
# most one row per image, which stays cheap where a LEFT JOIN on ``workload`` itself did not.
_REF_NAMESPACES_SQL = """
SELECT ref, MIN(namespace) AS first_ns, json_group_array(namespace) AS namespaces
FROM (SELECT DISTINCT r.ref, w.namespace FROM image_result r JOIN workload w ON w.image_result_id = r.id
      WHERE r.run_id = :run ORDER BY r.ref, w.namespace)
GROUP BY ref
"""

# The ORDER BY terms of each sort key: (expression, follows the requested direction). The NULL guards always sort
# NULLs last, and the tie-breaks (CVE, then image, then the rest of the unit key) always ascend, so paging is stable.
_SORT_TERMS = {
    "severity": (("{p}sev_rank", True),),
    "cve": (("{p}vuln_id", True),),
    "package": (("{p}pkg_name", True),),
    "image": (("{p}ref", True),),
    "namespace": (("{p}first_ns IS NULL", False), ("{p}first_ns", True)),
    "fixed": (("NULLIF({p}fixed_version, '') IS NULL", False), ("{p}fixed_version", True)),
}
_TIE_BREAK_TERMS = tuple((f"{{p}}{c}", False) for c in ("vuln_id", "ref", "pkg_name", "installed_version"))


def _order_sql(f: FindingFilter, prefix: str = "", *, reverse: bool = False) -> str:
    """The ORDER BY list for ``f``; ``reverse`` gives the exact opposite order, to read a deep page from the far end."""
    terms = []
    for expr, follows in _SORT_TERMS[f.sort] + _TIE_BREAK_TERMS:
        descending = (follows and f.desc) != reverse
        terms.append(f"{expr.format(p=prefix)} {'DESC' if descending else 'ASC'}")
    return ", ".join(terms)


def _like_pattern(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# The lean form of the units the filter, sort and count work on: only the columns they read. Grouping the text columns
# (title, URL, targets) of 100,000 findings costs several times more, so those are fetched for the page's rows alone.
_LEAN_UNITS_SQL = f"""
SELECT r.ref, f.vuln_id, f.pkg_name, f.installed_version,
       MAX(f.fixed_version) AS fixed_version,
       MAX({_RANK_SQL}) AS sev_rank,
       MAX(f.pkg_class) AS pkg_class
FROM image_result r
JOIN finding f ON f.image_result_id = r.id
WHERE r.run_id = :run
GROUP BY {_UNIT_KEY_SQL}
"""  # noqa: S608 - only module constants are interpolated

# The text columns of the units on the page, grouped exactly as ``FINDING_UNITS_SQL`` groups them. ``page`` holds the keys.
_PAGE_DETAIL_SQL = """
SELECT p.ref AS d_ref, p.vuln_id AS d_vuln, p.pkg_name AS d_pkg, p.installed_version AS d_ver,
       MAX(r.repo) AS repo, MAX(r.tag) AS tag, MAX(r.digest) AS digest, MAX(f.title) AS title,
       MAX(f.primary_url) AS primary_url, group_concat(DISTINCT f.target) AS targets
FROM page p
JOIN image_result r ON r.run_id = :run AND r.ref = p.ref
JOIN finding f ON f.image_result_id = r.id AND f.vuln_id = p.vuln_id AND f.pkg_name IS p.pkg_name
  AND f.installed_version IS p.installed_version
GROUP BY p.ref, p.vuln_id, p.pkg_name, p.installed_version
"""


# Which units of ``kept`` the findings page shows, by ``FindingFilter.accepted``.
_KEEP_SQL = {"hide": "accepted = 0", "only": "accepted = 1", "all": "1"}


def _filtered_cte(
    f: FindingFilter, run_id: int, today: date | None, units_sql: str = _LEAN_UNITS_SQL
) -> tuple[str, dict[str, object]]:
    """``WITH ... filtered AS (...)``: the lean units of the run that pass the filter, each with ``accepted`` (0 or 1).

    ``kept`` holds the units that pass every filter but the accepted one, so the page can say how many it left out.

    ``units_sql`` is the lean units by default; the export passes ``FINDING_UNITS_SQL`` for the text columns too.
    ``filtered`` stays a plain CTE over the materialized units: the count and the page read it again more cheaply than
    a third copy of 100,000 rows is written. The namespaces are joined in only when the filter or the sort reads them;
    the page fetches them for its own rows.
    """
    where: list[str] = []
    params: dict[str, object] = {"run": run_id, "today": _today(today)}
    if f.severities:
        ranks = {f"rank{i}": 4 - _SEVERITIES.index(name) for i, name in enumerate(f.severities)}
        where.append("u.sev_rank IN (" + ", ".join(f":{k}" for k in ranks) + ")")
        params.update(ranks)
    if f.namespace:
        where.append("EXISTS (SELECT 1 FROM json_each(ns.namespaces) WHERE value = :namespace)")
        params["namespace"] = f.namespace
    if f.cve:
        where.append("u.vuln_id = :cve")
        params["cve"] = f.cve
    if f.package:
        where.append("u.pkg_name = :package")
        params["package"] = f.package
    if f.has_fix != "any":
        where.append("COALESCE(u.fixed_version, '') " + ("<> ''" if f.has_fix == "yes" else "= ''"))
    if f.pkg != "all":
        where.append("u.pkg_class = :pkg_class")
        params["pkg_class"] = f.pkg
    if f.q:
        where.append("(u.ref LIKE :q ESCAPE '\\' OR u.vuln_id LIKE :q ESCAPE '\\' OR u.pkg_name LIKE :q ESCAPE '\\')")
        params["q"] = _like_pattern(f.q)
    clause = " WHERE " + " AND ".join(where) if where else ""
    by_namespace = bool(f.namespace) or f.sort == "namespace"
    source = "units u LEFT JOIN ns ON ns.ref = u.ref" if by_namespace else "units u"
    first_ns = ", ns.first_ns" if by_namespace else ""
    cte = (
        f"WITH units AS MATERIALIZED ({units_sql}), ns AS MATERIALIZED ({_REF_NAMESPACES_SQL}),"  # noqa: S608
        f" {ACCEPTED_CTES},"
        f" kept AS (SELECT u.*{first_ns}, {_IS_ACCEPTED_SQL.format(u='u')} AS accepted FROM {source}{clause}),"
        f" filtered AS (SELECT * FROM kept WHERE {_KEEP_SQL[f.accepted]})"
    )
    return cte, params


def _page_sql(cte: str, f: FindingFilter) -> str:
    """Count and page in one statement: one row per unit on the page, each with ``total``, or one row of NULLs and
    ``total`` when the page is empty, so a page past the end still reports the count.

    A LIMIT/OFFSET sorter holds offset + limit rows, so a page past the middle is read from the far end in the reverse
    order instead: only one of the two halves has a non-zero LIMIT, and SQLite skips the other without sorting.
    """
    forward, backward = _order_sql(f), _order_sql(f, reverse=True)
    severity = _SEVERITY_OF_RANK_SQL.format(rank="p.sev_rank")
    return (
        f"{cte}, n AS (SELECT COALESCE(SUM({_KEEP_SQL[f.accepted]}), 0) AS total,"  # noqa: S608
        " COALESCE(SUM(accepted), 0) AS left_out FROM kept),"
        f" page AS MATERIALIZED (SELECT * FROM (SELECT * FROM filtered ORDER BY {forward}"
        "   LIMIT (SELECT CASE WHEN :offset <= total / 2 THEN :limit ELSE 0 END FROM n) OFFSET :offset)"
        f" UNION ALL SELECT * FROM (SELECT * FROM filtered ORDER BY {backward}"
        "   LIMIT (SELECT CASE WHEN :offset > total / 2 THEN MAX(0, MIN(:limit, total - :offset)) ELSE 0 END FROM n)"
        "   OFFSET (SELECT MAX(0, total - :offset - :limit) FROM n))),"
        f" detail AS ({_PAGE_DETAIL_SQL})"
        " SELECT n.total, n.left_out, p.ref, p.vuln_id, p.pkg_name, p.installed_version, p.fixed_version, p.sev_rank,"
        " p.pkg_class, p.accepted,"
        f" {severity} AS severity, COALESCE(ns.namespaces, '[]') AS namespaces,"
        " d.repo, d.tag, d.digest, d.title, d.primary_url, d.targets"
        " FROM n LEFT JOIN page p ON 1 LEFT JOIN ns ON ns.ref = p.ref"
        " LEFT JOIN detail d ON d.d_ref = p.ref AND d.d_vuln = p.vuln_id AND d.d_pkg IS p.pkg_name"
        f" AND d.d_ver IS p.installed_version ORDER BY {_order_sql(f, 'p.')}"
    )


def findings_page(
    conn: sqlite3.Connection,
    run_id: int,
    f: FindingFilter,
    page: int,
    per_page: int = 100,
    *,
    today: date | None = None,
) -> tuple[list[sqlite3.Row], int, int]:
    """One page of the run's finding units that pass ``f``, how many pass in all (also for a page past the end), and how
    many accepted units pass every filter but the accepted one (those ``accepted="hide"`` leaves out).
    """
    cte, params = _filtered_cte(f, run_id, today)
    rows = conn.execute(_page_sql(cte, f), params | {"limit": per_page, "offset": (page - 1) * per_page}).fetchall()
    return [r for r in rows if r["ref"] is not None], rows[0]["total"], rows[0]["left_out"]


def findings_export(
    conn: sqlite3.Connection, run_id: int, f: FindingFilter, *, today: date | None = None
) -> sqlite3.Cursor:
    """Every finding unit of the run that passes ``f``, in the page's order, with its text columns and namespaces (a
    JSON array). A cursor, so a caller can stream a large run in batches; it groups the run's findings once.
    """
    cte, params = _filtered_cte(f, run_id, today, FINDING_UNITS_SQL)
    return conn.execute(
        f"{cte} SELECT x.*, COALESCE(ns.namespaces, '[]') AS namespaces"  # noqa: S608 - only module constants
        f" FROM filtered x LEFT JOIN ns ON ns.ref = x.ref ORDER BY {_order_sql(f, 'x.')}",
        params,
    )


def run_namespaces(conn: sqlite3.Connection, run_id: int) -> list[str]:
    """Every distinct namespace that has a workload in the run, sorted."""
    rows = conn.execute(
        "SELECT DISTINCT w.namespace FROM image_result r JOIN workload w ON w.image_result_id = r.id"
        " WHERE r.run_id = ? ORDER BY w.namespace",
        (run_id,),
    )
    return [row["namespace"] for row in rows]


@dataclass(frozen=True)
class HistoryRow:
    """One run in the scans page's history, whatever its status. ``images`` and ``failed`` count distinct refs."""

    id: int
    number: int
    status: str
    scope: dict | None
    pkg_types: str | None
    images: int
    failed: int
    started_at: datetime
    finished_at: datetime | None
    owner: str | None


def run_history(conn: sqlite3.Connection, context: str, page: int, per_page: int = 25) -> tuple[list[HistoryRow], int]:
    """One page of the context's runs of every status, newest first, and how many runs the context has in all."""
    total = conn.execute("SELECT COUNT(*) FROM scan_run WHERE context = ?", (context,)).fetchone()[0]
    rows = conn.execute(
        "SELECT id, number, status, scope, pkg_types, started_at, finished_at, owner,"
        " (SELECT COUNT(DISTINCT ref) FROM image_result WHERE run_id = scan_run.id) AS images,"
        " (SELECT COUNT(DISTINCT ref) FROM image_result WHERE run_id = scan_run.id AND status = 'error') AS failed"
        " FROM scan_run WHERE context = ? ORDER BY id DESC LIMIT ? OFFSET ?",
        (context, per_page, (page - 1) * per_page),
    ).fetchall()
    history = [
        HistoryRow(
            id=r["id"],
            number=r["number"],
            status=r["status"],
            scope=json.loads(r["scope"]) if r["scope"] else None,
            pkg_types=r["pkg_types"],
            images=r["images"],
            failed=r["failed"],
            started_at=datetime.fromisoformat(r["started_at"]),
            finished_at=datetime.fromisoformat(r["finished_at"]) if r["finished_at"] else None,
            owner=r["owner"],
        )
        for r in rows
    ]
    return history, total


def run_number(conn: sqlite3.Connection, run_id: int) -> int | None:
    """The run's number within its context, or None when there is no such run."""
    row = conn.execute("SELECT number FROM scan_run WHERE id = ?", (run_id,)).fetchone()
    return row["number"] if row else None


def context_scans(conn: sqlite3.Connection) -> dict[str, datetime | None]:
    """Every context with a run, by name, mapped to when its newest result run finished (None when it has none)."""
    rows = conn.execute(
        f"SELECT context, MAX(CASE WHEN status IN {_STATUS_SQL} THEN finished_at END) AS finished"  # noqa: S608 - only module constants are interpolated
        " FROM scan_run WHERE context IS NOT NULL GROUP BY context ORDER BY context"
    ).fetchall()
    return {r["context"]: datetime.fromisoformat(r["finished"]) if r["finished"] else None for r in rows}


@dataclass(frozen=True)
class NamespaceRow:
    """One namespace of a run: its finding units by severity, and its images (distinct refs, failed ones included)."""

    namespace: str
    owner: str | None
    team: str | None
    counts: dict[str, int]
    total: int
    images: int


# A namespace counts a unit when the unit's image runs in it, the rule the findings page's namespace filter applies,
# so each count equals the findings its link opens. ``ns`` holds each (image, namespace) once, however many workloads
# and platforms repeat it.
_NAMESPACE_COUNTS_SQL = f"""
WITH units AS MATERIALIZED ({_UNIT_COUNTS_SQL}),
ns AS MATERIALIZED (
    SELECT r.ref, w.namespace, MAX(w.owner) AS owner, MAX(w.team) AS team
    FROM image_result r JOIN workload w ON w.image_result_id = r.id
    WHERE r.run_id = :run
    GROUP BY r.ref, w.namespace
),
info AS (SELECT namespace, COUNT(*) AS images, MAX(owner) AS owner, MAX(team) AS team FROM ns GROUP BY namespace),
per AS (
    SELECT ns.namespace, u.sev_rank, COUNT(*) AS n
    FROM ns JOIN units u ON u.ref = ns.ref
    GROUP BY ns.namespace, u.sev_rank
)
SELECT i.namespace, i.images, i.owner, i.team, p.sev_rank, p.n
FROM info i LEFT JOIN per p ON p.namespace = i.namespace
"""  # noqa: S608 - only module constants are interpolated


def namespace_counts(conn: sqlite3.Connection, run_id: int) -> list[NamespaceRow]:
    """Every namespace with a workload in the run, unordered; the page sorts and filters them."""
    found: dict[str, dict] = {}
    for r in conn.execute(_NAMESPACE_COUNTS_SQL, {"run": run_id}):
        row = found.setdefault(
            r["namespace"],
            {"owner": r["owner"], "team": r["team"], "images": r["images"], "counts": dict.fromkeys(_SEVERITIES, 0)},
        )
        if r["sev_rank"] is not None:
            row["counts"][_SEVERITIES[4 - r["sev_rank"]]] = r["n"]
    return [
        NamespaceRow(name, v["owner"], v["team"], v["counts"], sum(v["counts"].values()), v["images"])
        for name, v in found.items()
    ]
