"""Reads and writes of scan runs, results and the scan cache."""

import json
import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from kubedelos.models import ImageResult, InventoryItem
from kubedelos.trivy.pins import TRIVY_VERSION

# A cache key is either a bare digest or "<repo>@<digest>"; anything else is a mutable tag ref.
_DIGEST_KEY_RE = re.compile(r"(?:^|@)sha256:[0-9a-f]{64}\Z")  # \Z: unlike $, no match before a trailing newline
_FINAL_STATUSES = frozenset({"ok", "partial", "cancelled", "failed"})

_RUN_FINDINGS_SQL = """
SELECT w.namespace, w.kind, w.name AS workload, w.container, w.owner, w.team,
       r.ref AS image, r.digest, r.platform,
       f.vuln_id, f.severity, f.pkg_name, f.installed_version, f.fixed_version,
       f.title, f.primary_url, f.target, f.pkg_type
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

    def start_run(self, context: str | None, trigger: str | None, trivy_version: str) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO scan_run (started_at, status, context, trigger, trivy_version) VALUES (?, 'running', ?, ?, ?)",
                (self._now(), context, trigger, trivy_version),
            )
        return int(cur.lastrowid)  # type: ignore[arg-type]

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
                " title, primary_url, target, pkg_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        result_id, f.vuln_id, f.pkg_name, f.installed_version, f.fixed_version, f.severity.value,
                        f.title, f.primary_url, f.target, f.pkg_type,
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

    def get_cached(self, image_key: str, platform: str, max_age: timedelta) -> dict | None:
        if not _is_digest_key(image_key):
            return None
        row = self._conn.execute(
            "SELECT scanned_at, report_json FROM image_cache WHERE image_key = ? AND platform = ?"
            " AND trivy_db_version = ?",
            (image_key, platform, TRIVY_VERSION),
        ).fetchone()
        if row is None:
            return None
        if self._clock() - datetime.fromisoformat(row["scanned_at"]) > max_age:
            return None
        return json.loads(row["report_json"])

    def put_cache(self, image_key: str, platform: str, report: dict) -> None:
        if not _is_digest_key(image_key):
            return
        with self._conn:
            self._conn.execute(
                "INSERT INTO image_cache (image_key, platform, trivy_db_version, scanned_at, report_json)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(image_key, platform) DO UPDATE SET"
                " trivy_db_version = excluded.trivy_db_version, scanned_at = excluded.scanned_at,"
                " report_json = excluded.report_json",
                (image_key, platform, TRIVY_VERSION, self._now(), json.dumps(report)),
            )

    def run_findings(self, run_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(_RUN_FINDINGS_SQL, (run_id,)).fetchall()
