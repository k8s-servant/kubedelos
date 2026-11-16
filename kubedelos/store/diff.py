"""Compare two runs: which findings are new, which are fixed or gone, and which images were added, gone or changed.

Images are matched by repository, not by ref, so a tag bump or a rebuild reads as a changed image whose findings stay
open where the CVE is still there, never as every finding fixed and every finding new. A finding is keyed by
(repository, CVE, package); a repository running under several tags is compared as the union of its tags, and a
second platform counts once. A finding of an image that is gone from the newer run is marked ``image_gone``.

One pass groups both runs' finding rows by that key through ``idx_finding_unit``, so the work is one read of each run.
Acceptances play no part: this counts, and counts never change for an acceptance.
"""

import sqlite3
from dataclasses import dataclass

_SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")  # by rank, 0 to 4
_RANK_SQL = (
    "CASE f.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END"
)

# One row per (repository, CVE, package) found in either run, with the side(s) it is on, its severity and fix on each
# side, and how many distinct refs carry it there. Parameters ``:old`` and ``:new``.
_KEYS_SQL = f"""
SELECT r.repo, f.vuln_id, f.pkg_name,
       MAX(r.run_id = :old) AS in_old, MAX(r.run_id = :new) AS in_new,
       MAX(CASE WHEN r.run_id = :old THEN {_RANK_SQL} END) AS rank_old,
       MAX(CASE WHEN r.run_id = :new THEN {_RANK_SQL} END) AS rank_new,
       MAX(CASE WHEN r.run_id = :old THEN COALESCE(f.fixed_version, '') END) AS fixed_old,
       MAX(CASE WHEN r.run_id = :new THEN COALESCE(f.fixed_version, '') END) AS fixed_new,
       COUNT(DISTINCT CASE WHEN r.run_id = :old THEN r.ref END) AS images_old,
       COUNT(DISTINCT CASE WHEN r.run_id = :new THEN r.ref END) AS images_new
FROM image_result r JOIN finding f ON f.image_result_id = r.id
WHERE r.run_id IN (:old, :new)
GROUP BY r.repo, f.vuln_id, f.pkg_name
"""  # noqa: S608 - only module constants are interpolated

# The newer run's repositories, to tell a finding of a gone image from one fixed in an image still running.
_NEW_REPOS_SQL = "SELECT DISTINCT repo FROM image_result WHERE run_id = :new"


@dataclass(frozen=True)
class DiffFinding:
    repo: str
    vuln_id: str
    pkg_name: str | None
    severity: str
    fixed_version: str  # '' when there is no fix
    images: int  # distinct refs of the repository carrying it, in the run it is in
    image_gone: bool  # a "fixed or gone" finding whose repository is not in the newer run


@dataclass(frozen=True)
class ImageChange:
    repo: str
    refs_from: list[str]
    refs_to: list[str]


@dataclass(frozen=True)
class Diff:
    new_total: int
    gone_total: int
    still_open: int
    new: list[DiffFinding]  # worst first, at most ``limit``
    gone: list[DiffFinding]
    images_added: list[ImageChange]
    images_gone: list[ImageChange]
    images_changed: list[ImageChange]
    images_added_total: int
    images_gone_total: int
    images_changed_total: int
    images_unchanged: int


# Both one-sided lists in one statement over one grouping: each side's rows worst first, numbered and counted per side,
# beside the count of keys on both sides. The LEFT JOIN keeps one row when neither side has any.
_SIDES_SQL = f"""
WITH k AS MATERIALIZED ({_KEYS_SQL}), nr AS MATERIALIZED ({_NEW_REPOS_SQL}),
s AS (
  SELECT side, repo, vuln_id, pkg_name, rank, fixed, images, image_gone,
         ROW_NUMBER() OVER (PARTITION BY side ORDER BY rank DESC, images DESC, vuln_id, repo, pkg_name) AS rn,
         COUNT(*) OVER (PARTITION BY side) AS total
  FROM (SELECT CASE WHEN in_new THEN 'new' ELSE 'old' END AS side, repo, vuln_id, pkg_name,
               CASE WHEN in_new THEN rank_new ELSE rank_old END AS rank,
               CASE WHEN in_new THEN fixed_new ELSE fixed_old END AS fixed,
               CASE WHEN in_new THEN images_new ELSE images_old END AS images,
               repo NOT IN (SELECT repo FROM nr) AS image_gone
        FROM k WHERE in_new <> in_old))
SELECT c.still_open, s.* FROM (SELECT COUNT(*) AS still_open FROM k WHERE in_old AND in_new) c
LEFT JOIN s ON s.rn <= :limit ORDER BY s.side, s.rn
"""  # noqa: S608 - only module constants are interpolated


def _finding(row: sqlite3.Row, *, gone: bool) -> DiffFinding:
    return DiffFinding(
        repo=row["repo"],
        vuln_id=row["vuln_id"],
        pkg_name=row["pkg_name"],
        severity=_SEVERITIES[row["rank"]],
        fixed_version=row["fixed"] or "",
        images=row["images"],
        image_gone=gone and bool(row["image_gone"]),
    )


def _images(conn: sqlite3.Connection, old: int, new: int) -> dict[str, tuple[list[str], list[str]]]:
    refs: dict[str, tuple[list[str], list[str]]] = {}
    for row in conn.execute(
        "SELECT DISTINCT run_id, repo, ref FROM image_result WHERE run_id IN (?, ?) ORDER BY repo, ref", (old, new)
    ):
        refs.setdefault(row["repo"], ([], []))[0 if row["run_id"] == old else 1].append(row["ref"])
    return refs


def compare(conn: sqlite3.Connection, old: int, new: int, limit: int = 100) -> Diff:
    """What changed from run ``old`` to run ``new``; each list is capped at ``limit`` with its total kept."""
    rows = conn.execute(_SIDES_SQL, {"old": old, "new": new, "limit": limit}).fetchall()
    sides = {side: [r for r in rows if r["side"] == side] for side in ("new", "old")}
    images: dict[str, list[ImageChange]] = {"added": [], "gone": [], "changed": []}
    unchanged = 0
    for repo, (refs_from, refs_to) in _images(conn, old, new).items():
        kind = "added" if not refs_from else "gone" if not refs_to else "changed" if refs_from != refs_to else None
        if kind is None:
            unchanged += 1
        else:
            images[kind].append(ImageChange(repo, refs_from, refs_to))
    return Diff(
        new_total=sides["new"][0]["total"] if sides["new"] else 0,
        gone_total=sides["old"][0]["total"] if sides["old"] else 0,
        still_open=rows[0]["still_open"],
        new=[_finding(r, gone=False) for r in sides["new"]],
        gone=[_finding(r, gone=True) for r in sides["old"]],
        images_added=images["added"][:limit],
        images_gone=images["gone"][:limit],
        images_changed=images["changed"][:limit],
        images_added_total=len(images["added"]),
        images_gone_total=len(images["gone"]),
        images_changed_total=len(images["changed"]),
        images_unchanged=unchanged,
    )
