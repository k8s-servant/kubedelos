"""The sweep schedule of ``kubedelos serve``: an APScheduler cron job that fires ``on_fire`` in the configured zone.

A sweep does not scan by itself: ``on_fire`` only adds a ``schedule`` request to the scan queue, and the queue worker
runs it in the one scan slot. The job coalesces missed fires into one, never overlaps itself and still fires up to an
hour late when the process was busy or briefly stalled, so such a sweep is neither lost nor doubled. The job store is
in memory, so a restarted process schedules from now: a pod that was down at the sweep time skips that day's sweep.
``cron_error`` checks the schedule up front, so ``serve`` can refuse a bad one with a message naming the setting to fix.
"""

from collections.abc import Callable
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from kubedelos.config import Settings

JOB_ID = "sweep"
MISFIRE_GRACE_S = 3600


def cron_error(expr: str, timezone: str) -> str | None:
    """None when ``expr`` is a valid 5-field cron in ``timezone``, else one line naming the setting to fix."""
    try:
        zone = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        return f"KUBEDELOS_SWEEP_TIMEZONE: unknown time zone {timezone!r}"
    try:
        CronTrigger.from_crontab(expr, timezone=zone)
    except ValueError as exc:
        reason = " ".join(str(exc).split())
        return f"KUBEDELOS_SWEEP_SCHEDULE: {expr!r} is not a valid 5-field cron expression ({reason})"
    return None


class Sweeper:
    """Calls ``on_fire`` on the sweep schedule, on a background thread, while started and sweeps are enabled."""

    def __init__(self, settings: Settings, on_fire: Callable[[], None]) -> None:
        self._settings = settings
        self._on_fire = on_fire
        zone = ZoneInfo(settings.sweep_timezone)
        self._zone = zone
        self._scheduler = BackgroundScheduler(timezone=zone)

    def start(self) -> None:
        """Start the scheduler with the sweep job; with sweeps disabled, schedule nothing."""
        if not self._settings.sweep_enabled or self._scheduler.running:
            return
        self._scheduler.add_job(
            self._on_fire,
            CronTrigger.from_crontab(self._settings.sweep_schedule, timezone=self._zone),
            id=JOB_ID,
            coalesce=True,
            max_instances=1,
            misfire_grace_time=MISFIRE_GRACE_S,
        )
        self._scheduler.start()

    def stop(self) -> None:
        """Stop the scheduler without waiting for a fire in progress (it only queues a request)."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)

    def next_run(self) -> datetime | None:
        """When the next sweep fires, in the configured zone; None when sweeps are disabled or the scheduler stopped."""
        if not self._scheduler.running:
            return None
        job = self._scheduler.get_job(JOB_ID)
        return job.next_run_time if job is not None else None
