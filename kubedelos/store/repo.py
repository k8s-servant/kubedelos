"""Reads and writes of scan runs, results and the scan cache."""

import re
import sqlite3
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from kubedelos.kube.inventory import InventoryWarning
from kubedelos.models import ImageRef, ImageResult, InventoryItem, Workload
from kubedelos.trivy.pins import TRIVY_VERSION

# Cached reports are scoped by Trivy version and by the shape of kubedelos' own models: bump the "+cN" suffix when
# ImageResult or Finding change, so old rows are ignored instead of failing validation.
CACHE_VERSION = f"{TRIVY_VERSION}+c1"

# A cache key is either a bare digest or "<repo>@<digest>"; anything else is a mutable tag ref.
_DIGEST_KEY_RE = re.compile(r"(?:^|@)sha256:[0-9a-f]{64}\Z")  # \Z: unlike $, no match before a trailing newline
RETRY_NOTE_PREFIX = "retried "  # starts the run note a retry of failed images leaves
_FINAL_STATUSES = frozenset({"ok", "partial", "cancelled", "failed"})

_FINISH_RUN_SQL = (
    "UPDATE scan_run SET status = :status, finished_at = :now,"
    " images_total = (SELECT COUNT(*) FROM image_result WHERE run_id = :id),"
    " images_error = (SELECT COUNT(*) FROM image_result WHERE run_id = :id AND status = 'error')"
    " WHERE id = :id"
)


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
        self,
        context: str | None,
        trigger: str | None,
        trivy_version: str,
        *,
        scan_level: str,
        scope: str | None = None,
        owner: str | None = None,
    ) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO scan_run (started_at, status, context, trigger, trivy_version, pkg_types, scope, owner,"
                " number) VALUES (?, 'running', ?, ?, ?, ?, ?, ?,"
                " (SELECT COALESCE(MAX(number), 0) + 1 FROM scan_run WHERE context IS ?))",
                (self._now(), context, trigger, trivy_version, scan_level, scope, owner, context),
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
            self._add_findings(result_id, result)

    def _add_findings(self, result_id: int, result: ImageResult) -> None:
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

    def failed_items(self, run_id: int) -> list[tuple[int, InventoryItem]]:
        """The run's failed images as ``(image_result id, item)``, by ref, rebuilt from the stored refs and workloads."""
        rows = self._conn.execute(
            "SELECT id, ref, repo, tag, digest, platform FROM image_result"
            " WHERE run_id = ? AND status = 'error' ORDER BY ref, platform",
            (run_id,),
        ).fetchall()
        failed = []
        for row in rows:
            workloads = self._conn.execute(
                "SELECT namespace, kind, name, container, owner, team FROM workload WHERE image_result_id = ?"
                " ORDER BY id",
                (row["id"],),
            ).fetchall()
            image = ImageRef(ref=row["ref"], repo=row["repo"], tag=row["tag"], digest=row["digest"])
            item = InventoryItem(
                image=image, platform=row["platform"], workloads=[Workload(**dict(w)) for w in workloads]
            )
            failed.append((row["id"], item))
        return failed

    def replace_result(self, result_id: int, result: ImageResult) -> None:
        """Put ``result`` in place of the failure stored as ``result_id``; a row that is no longer a failure is kept."""
        with self._conn:
            cur = self._conn.execute(
                "UPDATE image_result SET status = ?, error_kind = ?, error = ?, os_family = ?"
                " WHERE id = ? AND status = 'error'",
                (result.status, result.error_kind, result.error, result.os_family, result_id),
            )
            if cur.rowcount == 1:
                self._add_findings(result_id, result)

    def settle_retry(self, run_id: int, *, retried: int) -> str:
        """Recount the run after a retry of its ``retried`` failed images, note the retry and return the run's status.

        Images a cancel left untried count as still failing.

        The status becomes ``ok`` once nothing fails and stays ``partial`` otherwise; ``finished_at`` is kept.
        """
        with self._conn:
            failing = self._conn.execute(
                "SELECT COUNT(*) FROM image_result WHERE run_id = ? AND status = 'error'", (run_id,)
            ).fetchone()[0]
            status = "partial" if failing else "ok"
            self._conn.execute(
                "UPDATE scan_run SET status = ?, images_error = ? WHERE id = ?", (status, failing, run_id)
            )
            at = self._clock().astimezone(UTC).strftime("%H:%M UTC")
            note = (
                f"{RETRY_NOTE_PREFIX}{retried} failed {'image' if retried == 1 else 'images'} at {at}: "
                f"{retried - failing} scanned, {failing} still failing"
            )
            self._conn.execute("INSERT INTO run_warning (run_id, text, coverage) VALUES (?, ?, 0)", (run_id, note))
        return status

    def finish_run(self, run_id: int, status: str) -> None:
        if status not in _FINAL_STATUSES:
            raise ValueError(f"invalid final run status: {status!r}")
        with self._conn:
            self._conn.execute(_FINISH_RUN_SQL, {"status": status, "now": self._now(), "id": run_id})

    def close_stale(self, run_id: int, note: str) -> bool:
        """Mark a run ``failed`` and record ``note``, only if it is still running. Returns whether it was closed."""
        # One transaction, conditional on status: a run whose owner finished it meanwhile keeps its real result.
        with self._conn:
            cur = self._conn.execute(
                _FINISH_RUN_SQL + " AND status = 'running'", {"status": "failed", "now": self._now(), "id": run_id}
            )
            if cur.rowcount != 1:
                return False
            self._conn.execute("INSERT INTO run_warning (run_id, text, coverage) VALUES (?, ?, 0)", (run_id, note))
        return True

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
