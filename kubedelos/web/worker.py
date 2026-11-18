"""The queue worker of ``kubedelos serve``: one thread that runs queued scan requests, oldest first, in the one slot.

The scheduler and the UI only add requests to the SQLite queue (``store/queue.py``); this thread is the only thing
that starts a scan in ``serve``, through the app's :class:`~kubedelos.web.jobs.ScanRunner`, so a sweep and a click
never race for the slot. Each pass, once no scan is active, it records the run the last started request produced,
prunes old runs after a finished sweep, and starts the next request. A request's overrides are validated against
``Settings`` again before it runs: one that no longer validates is skipped, never fatal. Each thread opens its own
SQLite connection, so none crosses threads. A failing pass is logged and the loop goes on; only :meth:`stop` or a
shut-down runner ends it.

The worker settles a request only from the view of the job it launched (matched by job id), so another scan's run is
never recorded against it, nor a sweep's pruning triggered by it. A busy runner puts the claimed request back in the
queue for a later pass; only a closed runner ends the loop.
"""

import logging
import sqlite3
import threading
from collections.abc import Callable
from datetime import datetime

from pydantic import ValidationError

from kubedelos.config import Settings
from kubedelos.store import db, queue, retention
from kubedelos.web.jobs import ACTIVE, FIELDS, JobView, ScanBusy, ScanRunner

logger = logging.getLogger("kubedelos.web")

_NOT_SETTINGS = ("rescan", "kinds")  # override keys that steer the run, not Settings fields
_RETRY_FIELDS = ("scan_timeout_s", "parallelism")


class QueueWorker:
    """Runs the queue's requests one at a time on a daemon thread, until stopped."""

    def __init__(
        self, settings: Settings, runner: ScanRunner, *, clock: Callable[[], datetime], poll_s: float = 2.0
    ) -> None:
        self._settings = settings
        self._runner = runner
        self._clock = clock
        self._poll_s = poll_s
        self._wake = threading.Event()
        self._stopped = threading.Event()
        self._thread: threading.Thread | None = None
        self._current: tuple[queue.Request, int] | None = None  # the request last started and its runner job id

    def enqueue_sweep(self) -> None:
        """Queue a sweep of the configured scope (skipping the result cache) and wake the worker.

        Called from the scheduler's thread. A full queue or a database error (locked past the busy timeout, say) drops
        this sweep with a warning: the next one comes on schedule.
        """
        try:
            conn = db.connect(self._settings.db_path)
            try:
                queue.enqueue(conn, kind="scan", trigger="schedule", overrides={"rescan": True}, now=self._clock())
            finally:
                conn.close()
        except queue.QueueFull:
            logger.warning("scheduled sweep skipped: the scan queue is full")
            return
        except sqlite3.Error as exc:  # the type only: the message may name paths
            logger.warning("scheduled sweep skipped (%s)", type(exc).__name__)
            return
        self.wake()

    def wake(self) -> None:
        """Look at the queue now instead of at the next poll."""
        self._wake.set()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="kubedelos-queue-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """End the loop and wait briefly for the thread; a running scan is the runner's to cancel."""
        self._stopped.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(5)

    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        conn = db.connect(self._settings.db_path)
        try:
            while not self._stopped.is_set():
                try:
                    if not self._pass(conn):
                        return
                except Exception as exc:
                    # Type only: a message could carry a registry or API detail, and the next pass retries anyway.
                    logger.warning("queue worker pass failed (%s)", type(exc).__name__)
                self._wake.wait(self._poll_s)
                self._wake.clear()
        finally:
            conn.close()

    def _pass(self, conn: sqlite3.Connection) -> bool:
        """Settle the request this worker last started and start the next one; False once the runner is closed."""
        if self._runner.closed:
            return False
        view = self._runner.view()
        if view is not None and view.state in ACTIVE:  # this worker's scan or another's: the slot is taken
            return True
        if self._current is not None:
            self._settle(conn, view)
        req = queue.claim_next(conn)
        if req is None:
            return True
        settings_overrides = {k: v for k, v in req.overrides.items() if k not in _NOT_SETTINGS}
        try:
            valid = Settings.model_validate({**self._settings.model_dump(), **settings_overrides})
        except ValidationError as exc:
            queue.attach_run(conn, req.id, None)
            logger.debug("queued request %d skipped: %d invalid override(s)", req.id, exc.error_count())
            return True
        try:
            job_id = self._launch(req, valid)
        except ScanBusy:
            # The slot was taken between the view and the launch, or the runner is shutting down: either way the
            # request waits in the queue, for a later pass or the next start.
            queue.requeue(conn, req.id)
            return not self._runner.closed
        except Exception:
            queue.attach_run(conn, req.id, None)  # settled as run-less, never left looking in flight
            raise
        self._current = (req, job_id)
        return True

    def _settle(self, conn: sqlite3.Connection, view: JobView | None) -> None:
        """Record the run the last started request produced, and prune after a finished sweep."""
        req, job_id = self._current
        if view is None or view.job_id != job_id:
            # Another job replaced this one's view before a pass saw it end: its run is unknown here, so none is
            # attached rather than someone else's.
            queue.attach_run(conn, req.id, None)
            self._current = None
            logger.warning("queued request %d ended unseen; no run recorded for it", req.id)
            return
        queue.attach_run(conn, req.id, view.run_id)  # None when the scan raised
        self._current = None
        if req.trigger == "schedule" and view.status in ("ok", "partial"):
            retention.prune(conn, now=self._clock(), retention_days=self._settings.retention_days)

    def _launch(self, req: queue.Request, valid: Settings) -> int:
        if req.kind == "retry":
            kinds = req.overrides.get("kinds")
            return self._runner.retry(
                req.target_run_id,
                {name: getattr(valid, name) for name in _RETRY_FIELDS},
                kinds=set(kinds) if kinds is not None else None,
            )
        return self._runner.start(
            {name: getattr(valid, name) for name in FIELDS},
            rescan=bool(req.overrides.get("rescan", False)),
            trigger=req.trigger,
            requested_by=req.requested_by,
        )
