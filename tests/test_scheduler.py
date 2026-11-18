"""Tests for the sweep scheduler: cron validation, the configured time zone, the master switch and the job options."""

import pytest

from kubedelos.config import Settings
from kubedelos.scheduler import Sweeper, cron_error


@pytest.fixture
def sweepers():
    made: list[Sweeper] = []
    yield made
    for sweeper in made:
        sweeper.stop()


def _sweeper(sweepers, tmp_path, **kw):
    settings = Settings(data_dir=tmp_path / "data", cache_dir=tmp_path / "cache", **kw)
    sweeper = Sweeper(settings, on_fire=lambda: None)
    sweepers.append(sweeper)
    return sweeper


def test_cron_error_names_the_setting():
    error = cron_error("61 * * * *", "UTC")
    assert error is not None and "KUBEDELOS_SWEEP_SCHEDULE" in error and "\n" not in error
    assert cron_error("0 3 * * *", "UTC") is None


def test_cron_error_names_a_bad_time_zone():
    error = cron_error("0 3 * * *", "Mars/Olympus")
    assert error is not None and "KUBEDELOS_SWEEP_TIMEZONE" in error


def test_next_run_in_the_configured_zone(sweepers, tmp_path):
    sweeper = _sweeper(sweepers, tmp_path, sweep_schedule="0 3 * * *", sweep_timezone="Europe/Vilnius")
    sweeper.start()
    nxt = sweeper.next_run()
    assert nxt.hour == 3 and nxt.minute == 0
    assert nxt.tzinfo.key == "Europe/Vilnius"


def test_disabled_sweeps_schedule_nothing(sweepers, tmp_path):
    sweeper = _sweeper(sweepers, tmp_path, sweep_enabled=False)
    sweeper.start()
    assert sweeper.next_run() is None


def test_next_run_is_none_once_stopped(sweepers, tmp_path):
    sweeper = _sweeper(sweepers, tmp_path)
    assert sweeper.next_run() is None  # not started yet
    sweeper.start()
    assert sweeper.next_run() is not None
    sweeper.stop()
    assert sweeper.next_run() is None
    sweeper.stop()  # twice is fine


def test_job_options(sweepers, tmp_path):
    sweeper = _sweeper(sweepers, tmp_path)
    sweeper.start()
    job = sweeper._scheduler.get_job("sweep")
    assert job.coalesce is True and job.max_instances == 1 and job.misfire_grace_time == 3600
