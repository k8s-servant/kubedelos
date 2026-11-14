"""Reads and writes of scan runs, results and the scan cache."""

import re
import sqlite3
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from kubedelos.kube.inventory import InventoryWarning
from kubedelos.models import ImageResult, InventoryItem
from kubedelos.trivy.pins import TRIVY_VERSION

# Cached reports are scoped by Trivy version and by the shape of kubedelos' own models: bump the "+cN" suffix when
# ImageResult or Finding change, so old rows are ignored instead of failing validation.
CACHE_VERSION = f"{TRIVY_VERSION}+c1"

# A cache key is either a bare digest or "<repo>@<digest>"; anything else is a mutable tag ref.
_DIGEST_KEY_RE = re.compile(r"(?:^|@)sha256:[0-9a-f]{64}\Z")  # \Z: unlike $, no match before a trailing newline
_FINAL_STATUSES = frozenset({"ok", "partial", "cancelled", "failed"})

_RUN_FINDINGS_SQL = """
SELECT w.namespace, w.kind, w.name AS workload, w.container, w.owner, w.team,
       r.ref AS image, r.repo, r.tag, r.digest, r.platform,
       f.vuln_id, f.severity, f.pkg_name, f.installed_version, f.fixed_version,
       f.title, f.primary_url, f.target, f.pkg_type, f.pkg_class
FROM image_result r
JOIN finding f ON f.image_result_id = r.id
JOIN workload w ON w.image_result_id = r.id
WHERE r.run_id = ?
ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
         w.namespace, w.name, f.vuln_id
"""


def _is_digest_key(key: str) -> bool:
    return _DIGEST_KEY_RE.search(key) is not None


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Repo:
    def __init__(self, conn: sqlite3.Connection, clock: Callable[[], datetime] = _utcnow) -> None:
        self._conn = conn
        self._clock = clock

    def _now(self) -> str:
        return self._clock().isoformat()

    def start_run(
        self, context: str | None, trigger: str | None, trivy_version: str, *, scan_level: str, scope: str | None = None
    ) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO scan_run (started_at, status, context, trigger, trivy_version, pkg_types, scope)"
                " VALUES (?, 'running', ?, ?, ?, ?, ?)",
                (self._now(), context, trigger, trivy_version, scan_level, scope),
            )
        return int(cur.lastrowid)  # type: ignore[arg-type]

    def add_warnings(self, run_id: int, warnings: Sequence[InventoryWarning]) -> None:
        with self._conn:
            self._conn.executemany(
                "INSERT INTO run_warning (run_id, text, coverage) VALUES (?, ?, ?)",
                [(run_id, w.text, int(w.coverage)) for w in warnings],
            )

    def run_warnings(self, run_id: int) -> list[sqlite3.Row]:
        """The inventory warnings recorded for a run, in the order they were raised."""
        return self._conn.execute(
            "SELECT text, coverage FROM run_warning WHERE run_id = ? ORDER BY id", (run_id,)
        ).fetchall()

    def add_result(self, run_id: int, item: InventoryItem, result: ImageResult) -> None:
        image = result.image
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO image_result (run_id, image_key, ref, repo, tag, digest, platform, status, error_kind, error, os_family)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id, image.key, image.ref, image.repo, image.tag, image.digest, result.platform,
                    result.status, result.error_kind, result.error, result.os_family,
                ),
            )  # fmt: skip
            result_id = cur.lastrowid
            self._conn.executemany(
                "INSERT INTO workload (image_result_id, namespace, kind, name, container, owner, team) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(result_id, w.namespace, w.kind, w.name, w.container, w.owner, w.team) for w in item.workloads],
            )
            self._conn.executemany(
                "INSERT INTO finding (image_result_id, vuln_id, pkg_name, installed_version, fixed_version, severity,"
                " title, primary_url, target, pkg_type, pkg_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        result_id, f.vuln_id, f.pkg_name, f.installed_version, f.fixed_version, f.severity.value,
                        f.title, f.primary_url, f.target, f.pkg_type, f.pkg_class,
                    )
                    for f in result.findings
                ],
            )  # fmt: skip

    def finish_run(self, run_id: int, status: str) -> None:
        if status not in _FINAL_STATUSES:
            raise ValueError(f"invalid final run status: {status!r}")
        with self._conn:
            self._conn.execute(
                "UPDATE scan_run SET status = :status, finished_at = :now,"
                " images_total = (SELECT COUNT(*) FROM image_result WHERE run_id = :id),"
                " images_error = (SELECT COUNT(*) FROM image_result WHERE run_id = :id AND status = 'error')"
                " WHERE id = :id",
                {"status": status, "now": self._now(), "id": run_id},
            )

    def get_run(self, run_id: int) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM scan_run WHERE id = ?", (run_id,)).fetchone()

    def latest_run_id(self) -> int | None:
        row = self._conn.execute("SELECT MAX(id) FROM scan_run").fetchone()
        return row[0]

    def get_cached(self, image_key: str, platform: str, max_age: timedelta, *, scan_level: str) -> ImageResult | None:
        """A fresh cached result scanned at ``scan_level``, or None. A row that no longer validates is deleted."""
        if not _is_digest_key(image_key):
            return None
        row = self._conn.execute(
            "SELECT scanned_at, report_json FROM image_cache WHERE image_key = ? AND platform = ?"
            " AND scan_level = ? AND trivy_db_version = ?",
            (image_key, platform, scan_level, CACHE_VERSION),
        ).fetchone()
        if row is None:
            return None
        if self._clock() - datetime.fromisoformat(row["scanned_at"]) > max_age:
            return None
        try:
            return ImageResult.model_validate_json(row["report_json"])
        except ValidationError:  # covers invalid JSON too
            with self._conn:
                self._conn.execute(
                    "DELETE FROM image_cache WHERE image_key = ? AND platform = ? AND scan_level = ?",
                    (image_key, platform, scan_level),
                )
            return None

    def put_cache(self, image_key: str, platform: str, result: ImageResult, *, scan_level: str) -> None:
        if not _is_digest_key(image_key):
            return
        with self._conn:
            self._conn.execute(
                "INSERT INTO image_cache (image_key, platform, scan_level, trivy_db_version, scanned_at, report_json)"
                " VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(image_key, platform, scan_level) DO UPDATE SET"
                " trivy_db_version = excluded.trivy_db_version, scanned_at = excluded.scanned_at,"
                " report_json = excluded.report_json",
                (image_key, platform, scan_level, CACHE_VERSION, self._now(), result.model_dump_json()),
            )

    def run_errors(self, run_id: int) -> list[sqlite3.Row]:
        """The images of a run that failed to scan, with Trivy's (token-masked) error."""
        return self._conn.execute(
            "SELECT ref, platform, error_kind, error FROM image_result WHERE run_id = ? AND status = 'error' ORDER BY ref",
            (run_id,),
        ).fetchall()

    def run_findings(self, run_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(_RUN_FINDINGS_SQL, (run_id,)).fetchall()
