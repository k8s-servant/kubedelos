"""The UI's in-process scan runner: at most one scan at a time, on a background thread, with cancel and live progress.

A scan started from the UI runs :func:`kubedelos.scan.service.run_scan` on a daemon thread (a retry of a run's
failed images runs :func:`kubedelos.scan.service.retry_failed` in the same single slot), so the request that
started it returns at once and the page polls :meth:`ScanRunner.view` for progress. ``run_scan`` opens its own kube
API client and SQLite connection on that thread, so no sqlite object crosses threads. The scan always targets the
UI's context, never the kubeconfig's current context at click time. Errors are shown through
:func:`kubedelos.trivy.runner.error_cause`, which redacts credentials and keeps them to one line; a Kubernetes API
error shows only its status and reason, never the response headers or body it carries.
"""

import dataclasses
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from kubernetes.client.exceptions import ApiException
from kubernetes.config import ConfigException

from kubedelos.config import Settings
from kubedelos.scan.service import Progress, ScanOutcome, retry_failed, run_scan
from kubedelos.trivy.runner import error_cause, kill_all_running

logger = logging.getLogger("kubedelos.web")

State = Literal["starting", "running", "stopping", "finished", "error"]
_ACTIVE: frozenset[str] = frozenset({"starting", "running", "stopping"})
_ETA_MIN_DONE = 5
_ERROR_LIMIT = 300
_AFTER_KILL_S = 5.0  # how long shutdown waits, once Trivy is killed, for the scan to record its run


class ScanBusy(Exception):
    """A UI scan is already starting, running or stopping."""


@dataclass(frozen=True)
class JobView:
    """A snapshot of the current or last UI scan, safe to render: the error text is already redacted."""

    state: State
    run_id: int | None  # known only once the scan has returned
    progress: Progress | None
    status: str | None  # the run's final status once finished
    error: str | None
    eta: timedelta | None
    context: str  # the kube-context this scan targets
    retry_of: int | None = None  # the run whose failed images this job scans again; None for a scan


def _utcnow() -> datetime:
    return datetime.now(UTC)


def describe_error(exc: BaseException) -> str:
    """One redacted, printable line for ``exc``, safe to show on a page."""
    if isinstance(exc, ApiException):  # its str() dumps the response headers and body: show neither
        status = f" {exc.status}" if exc.status else ""
        reason = f": {exc.reason}" if exc.reason else ""
        if not (status or reason):  # raised before any response, e.g. by the client itself
            return f"Kubernetes API error ({type(exc).__name__})"
        return error_cause(f"Kubernetes API error{status}{reason}", limit=_ERROR_LIMIT)
    if isinstance(exc, ConfigException):
        return error_cause(str(exc), limit=_ERROR_LIMIT) or type(exc).__name__
    prefix = f"{type(exc).__name__}: "
    message = error_cause(str(exc), limit=_ERROR_LIMIT - len(prefix))
    return prefix + message if message else type(exc).__name__


def eta(started: datetime, now: datetime, done: int, total: int) -> timedelta | None:
    """The time left at the average pace since ``started``, or None while fewer than five images are done."""
    if done < _ETA_MIN_DONE:
        return None
    return (now - started) / done * max(total - done, 0)


@dataclass
class _Job:
    cancel: threading.Event
    context: str
    thread: threading.Thread | None = None
    state: State = "starting"
    run_id: int | None = None
    progress: Progress | None = None
    status: str | None = None
    error: str | None = None
    last_phase: str | None = None
    paced_from: datetime | None = None  # when image scanning began, after inventory and the Trivy DB download
    paced_base: int = 0  # images already done (cached or rejected) at that moment
    retry_of: int | None = None


class ScanRunner:
    """Runs at most one UI scan at a time, of any context. All job state is guarded by one lock."""

    def __init__(
        self,
        settings: Settings,
        context: str,
        *,
        scan: Callable[..., ScanOutcome] = run_scan,
        retry: Callable[..., ScanOutcome] = retry_failed,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._settings = settings
        self._context = context
        self._scan = scan
        self._retry = retry
        self._clock = clock
        self._lock = threading.Lock()
        self._job: _Job | None = None
        self._closed = False  # set by shutdown: the app is going away, so no new daemon scan may start

    def start(self, overrides: dict, context: str | None = None) -> None:
        """Start a scan of ``context`` (the UI's startup context by default) with ``overrides`` applied. The caller
        checks that ``context`` is one the kubeconfig has.

        Raises :class:`ScanBusy` if a scan is active or the runner has been shut down.
        """
        target = context or self._context
        # The context goes last so an override can never point the scan at another cluster.
        scan_settings = self._settings.model_copy(update={**overrides, "context": target})

        def work(on_progress: Callable[[Progress], None], cancel: threading.Event) -> ScanOutcome:
            return self._scan(scan_settings, trigger="ui", on_progress=on_progress, cancel=cancel)

        self._launch(target, work)

    def retry(self, run_id: int, overrides: dict, context: str | None = None) -> None:
        """Scan the failed images of run ``run_id`` of ``context`` again, with ``overrides`` (the time limit and
        parallelism) applied. The caller checks that the run is the context's newest; ``retry_failed`` checks the rest.

        Raises :class:`ScanBusy` if a scan is active or the runner has been shut down.
        """
        target = context or self._context
        retry_settings = self._settings.model_copy(update={**overrides, "context": target})

        def work(on_progress: Callable[[Progress], None], cancel: threading.Event) -> ScanOutcome:
            return self._retry(retry_settings, run_id=run_id, on_progress=on_progress, cancel=cancel)

        self._launch(target, work, retry_of=run_id)

    def _launch(
        self,
        target: str,
        work: Callable[[Callable[[Progress], None], threading.Event], ScanOutcome],
        retry_of: int | None = None,
    ) -> None:
        with self._lock:
            if self._closed:
                raise ScanBusy("the UI is shutting down")
            if self._job is not None and self._job.state in _ACTIVE:
                raise ScanBusy("a scan is already running")
            job = _Job(cancel=threading.Event(), context=target, retry_of=retry_of)
            job.thread = threading.Thread(target=self._run, args=(job, work), name="kubedelos-ui-scan", daemon=True)
            # Start before publishing: if the thread can't start, no job is left stuck at "starting". The worker
            # touches job state only under this lock, so it waits until the job is published.
            job.thread.start()
            self._job = job

    def cancel(self) -> None:
        """Ask the active scan to stop after the images in flight; the view says ``stopping`` at once."""
        with self._lock:
            job = self._job
            if job is not None and job.state in ("starting", "running"):
                job.cancel.set()
                job.state = "stopping"

    def view(self) -> JobView | None:
        """A snapshot of the current or last job, or None before the first one."""
        with self._lock:
            job = self._job
            if job is None:
                return None
            left = None
            if job.state in _ACTIVE and job.progress is not None and job.paced_from is not None:
                p = job.progress
                left = eta(job.paced_from, self._clock(), p.done - job.paced_base, p.total - job.paced_base)
            progress = dataclasses.replace(job.progress) if job.progress is not None else None
            return JobView(job.state, job.run_id, progress, job.status, job.error, left, job.context, job.retry_of)

    def shutdown(self, timeout: float = 10.0) -> None:
        """Refuse new scans, cancel the active one, if any, and wait up to ``timeout`` seconds for its thread to end.

        Cancel lets the images in flight finish, which can take minutes, and Trivy, in its own session, never sees the
        terminal's Ctrl-C. So once ``timeout`` passes, every Trivy process still running is killed, and the thread gets
        a few more seconds to record its run as cancelled.
        """
        with self._lock:
            self._closed = True
            job = self._job
            if job is None:
                return
            job.cancel.set()
            if job.state in ("starting", "running"):
                job.state = "stopping"
        if job.thread is not None:
            job.thread.join(timeout)
            if job.thread.is_alive():
                kill_all_running()
                job.thread.join(_AFTER_KILL_S)

    def _run(self, job: _Job, work: Callable[[Callable[[Progress], None], threading.Event], ScanOutcome]) -> None:
        def on_progress(progress: Progress) -> None:
            with self._lock:
                job.progress = progress
                if job.state == "starting":
                    job.state = "running"
                # Pace the ETA from the scanning phase that follows the Trivy DB download, not from the click.
                if progress.phase == "scanning" and job.last_phase == "trivy-db":
                    job.paced_from = self._clock()
                    job.paced_base = progress.done
                job.last_phase = progress.phase

        try:
            outcome = work(on_progress, job.cancel)
        except BaseException as exc:  # anything, including a failure before the run row exists: never stuck
            described = describe_error(exc)
            with self._lock:
                job.state = "error"
                job.error = described
            # Only the described text: redaction is best effort, so raw messages, headers and bodies stay out of logs.
            logger.debug("ui scan failed (%s): %s", type(exc).__name__, described)
            return
        with self._lock:
            job.run_id = outcome.run_id
            job.status = outcome.status
            job.state = "finished"
