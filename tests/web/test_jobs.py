"""Tests for the in-process UI scan runner: one job at a time, cancel, pinned context, redacted errors and the ETA."""

import logging
import threading
from datetime import UTC, datetime, timedelta

import pytest
from kubernetes.client.exceptions import ApiException
from kubernetes.config import ConfigException

from kubedelos.config import Settings
from kubedelos.scan.service import Progress, ScanOutcome
from kubedelos.web.jobs import ScanBusy, ScanRunner, eta

T0 = datetime(2026, 1, 1, tzinfo=UTC)


class FakeScan:
    """A stand-in for ``run_scan`` that blocks until released, so each test controls the timing."""

    def __init__(self, *, raises: BaseException | None = None, status: str = "ok", honour_cancel: bool = True) -> None:
        self.release = threading.Event()
        self.honour_cancel = honour_cancel
        self.entered = threading.Event()
        self.raises = raises
        self.status = status
        self.calls: list[dict] = []
        self.on_progress = None

    def __call__(self, settings, **kw):
        self.calls.append({"settings": settings, **kw})
        self.on_progress = kw["on_progress"]
        self.entered.set()
        if self.raises is not None:
            raise self.raises
        # Released by the test, or by a cancel: the real run_scan stops after the current image too.
        while not self.release.wait(0.01):
            if self.honour_cancel and kw["cancel"].is_set():
                return ScanOutcome(run_id=7, warnings=[], status="cancelled")
        return ScanOutcome(run_id=7, warnings=[], status=self.status)


@pytest.fixture
def settings(tmp_path):
    return Settings(context="other-context", data_dir=tmp_path / "data", cache_dir=tmp_path / "cache")


_RUNNERS: list[ScanRunner] = []


@pytest.fixture(autouse=True)
def _join_workers():
    """Shut down every runner a test made, so no worker thread outlives its test."""
    yield
    while _RUNNERS:
        _RUNNERS.pop().shutdown(timeout=5)


def _runner(settings, scan, clock=lambda: T0):
    runner = ScanRunner(settings, "my-cluster", scan=scan, clock=clock)
    _RUNNERS.append(runner)
    return runner


def _wait_for(runner, state):
    for _ in range(500):
        view = runner.view()
        if view is not None and view.state == state:
            return view
        threading.Event().wait(0.01)
    raise AssertionError(f"runner never reached {state!r}: {runner.view()}")


def test_view_is_none_before_any_job(settings):
    assert _runner(settings, FakeScan()).view() is None


def test_second_start_while_running_raises_busy(settings):
    scan = FakeScan()
    runner = _runner(settings, scan)
    runner.start({})
    assert scan.entered.wait(5)
    with pytest.raises(ScanBusy):
        runner.start({})
    scan.release.set()
    view = _wait_for(runner, "finished")
    assert len(scan.calls) == 1
    assert (view.run_id, view.status, view.error) == (7, "ok", None)
    runner.start({})  # a finished job no longer blocks a new one
    runner.shutdown()


def test_concurrent_starts_make_exactly_one_job(settings):
    scan = FakeScan()
    runner = _runner(settings, scan)
    barrier = threading.Barrier(8)
    busy = []

    def click():
        barrier.wait()
        try:
            runner.start({})
        except ScanBusy:
            busy.append(True)

    threads = [threading.Thread(target=click) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert scan.entered.wait(5)
    assert len(busy) == 7
    scan.release.set()
    _wait_for(runner, "finished")
    assert len(scan.calls) == 1


def test_run_id_is_none_while_running_and_progress_is_shown(settings):
    scan = FakeScan()
    runner = _runner(settings, scan)
    runner.start({})
    assert scan.entered.wait(5)
    assert runner.view().state == "starting"
    scan.on_progress(Progress(total=3, done=1, errors=0, current="example.com/app:1"))
    view = runner.view()
    assert (view.state, view.run_id, view.progress.done, view.progress.current) == (
        "running",
        None,
        1,
        "example.com/app:1",
    )
    scan.release.set()
    _wait_for(runner, "finished")


def test_cancel_sets_the_event_and_view_says_stopping(settings):
    scan = FakeScan(honour_cancel=False)  # held until released, so the test can look at the "stopping" view
    runner = _runner(settings, scan)
    runner.start({})
    assert scan.entered.wait(5)
    runner.cancel()
    assert scan.calls[0]["cancel"].is_set()
    assert runner.view().state == "stopping"
    scan.on_progress(Progress(total=3, done=2, errors=0, current="example.com/app:2"))
    assert runner.view().state == "stopping"  # progress after the click does not flip it back to running
    scan.release.set()
    view = _wait_for(runner, "finished")
    assert view.run_id == 7


def test_cancelled_run_reports_its_final_status(settings):
    scan = FakeScan()
    runner = _runner(settings, scan)
    runner.start({})
    assert scan.entered.wait(5)
    runner.cancel()
    view = _wait_for(runner, "finished")
    assert view.status == "cancelled"


def test_scan_settings_pin_the_ui_context(settings):
    scan = FakeScan()
    runner = _runner(settings, scan)
    runner.start({"namespaces": ["team-a"], "selector": "app=web"})
    assert scan.entered.wait(5)
    call = scan.calls[0]
    assert call["settings"].context == "my-cluster"
    assert call["settings"].namespaces == ["team-a"] and call["settings"].selector == "app=web"
    assert call["trigger"] == "ui" and isinstance(call["cancel"], threading.Event)
    assert settings.context == "other-context" and settings.namespaces != ["team-a"]  # the UI's settings are untouched
    runner.shutdown()


def test_overrides_cannot_change_the_context(settings):
    scan = FakeScan()
    runner = _runner(settings, scan)
    runner.start({"context": "someone-else"})
    assert scan.entered.wait(5)
    assert scan.calls[0]["settings"].context == "my-cluster"
    runner.shutdown()


def test_failure_before_run_row_is_reported(settings):
    scan = FakeScan(raises=ConfigException("no cluster"))
    runner = _runner(settings, scan)
    runner.start({})
    view = _wait_for(runner, "error")
    assert "no cluster" in view.error and view.run_id is None and view.status is None
    scan.raises = None
    runner.start({})  # an error leaves the runner free for another try
    assert len(scan.calls) == 2
    runner.shutdown()


def test_error_text_is_redacted(settings):
    scan = FakeScan(raises=RuntimeError("GET https://example.com/x?sig=SECRET\nAuthorization: Bearer tok123"))
    runner = _runner(settings, scan)
    runner.start({})
    view = _wait_for(runner, "error")
    assert "SECRET" not in view.error and "tok123" not in view.error
    assert "\n" not in view.error


JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLXZhbHVl"


def test_api_error_shows_only_status_and_reason(settings, caplog):
    exc = ApiException(status=401, reason="Unauthorized")
    exc.headers = {"WWW-Authenticate": "Bearer tok123"}
    exc.body = '{"message": "Bearer tok123 rejected"}'
    runner = _runner(settings, FakeScan(raises=exc))
    with caplog.at_level(logging.DEBUG, logger="kubedelos.web"):
        runner.start({})
        view = _wait_for(runner, "error")
    assert view.error == "Kubernetes API error 401: Unauthorized"
    assert "tok123" not in caplog.text


def test_config_error_shows_the_redacted_message(settings):
    runner = _runner(settings, FakeScan(raises=ConfigException("no context my-cluster, token: tok123")))
    runner.start({})
    assert _wait_for(runner, "error").error == "no context my-cluster, token: <redacted>"


def test_other_errors_show_their_type_and_a_redacted_message(settings, caplog):
    runner = _runner(settings, FakeScan(raises=RuntimeError(f"login failed for {JWT}\nretry later")))
    with caplog.at_level(logging.DEBUG, logger="kubedelos.web"):
        runner.start({})
        view = _wait_for(runner, "error")
    assert view.error == "RuntimeError: login failed for <redacted> retry later"
    assert JWT not in caplog.text and "<redacted>" in caplog.text  # logged in full, but redacted


def test_a_long_error_is_capped(settings):
    runner = _runner(settings, FakeScan(raises=RuntimeError("x" * 1000)))
    runner.start({})
    error = _wait_for(runner, "error").error
    assert error.startswith("RuntimeError: ") and len(error) <= 300


def test_an_error_without_a_message_shows_its_type(settings):
    runner = _runner(settings, FakeScan(raises=RuntimeError()))
    runner.start({})
    assert _wait_for(runner, "error").error == "RuntimeError"


def test_shutdown_cancels_and_joins(settings):
    scan = FakeScan()
    runner = _runner(settings, scan)
    runner.start({})
    assert scan.entered.wait(5)
    cancel = scan.calls[0]["cancel"]
    worker = runner._job.thread
    runner.shutdown(timeout=5)
    assert cancel.is_set()
    assert runner.view().state == "finished"
    assert not worker.is_alive()  # joined: the thread has ended, not just been asked to


def test_start_after_shutdown_is_refused(settings):
    scan = FakeScan()
    runner = _runner(settings, scan)
    runner.shutdown()
    with pytest.raises(ScanBusy, match="shutting down"):
        runner.start({})
    assert scan.calls == [] and runner.view() is None


def test_start_after_a_finished_job_and_shutdown_is_refused(settings):
    scan = FakeScan()
    scan.release.set()
    runner = _runner(settings, scan)
    runner.start({})
    _wait_for(runner, "finished")
    runner.shutdown()
    with pytest.raises(ScanBusy):
        runner.start({})
    assert len(scan.calls) == 1


def test_a_thread_that_fails_to_start_leaves_the_runner_usable(settings, monkeypatch):
    scan = FakeScan()
    scan.release.set()
    runner = _runner(settings, scan)

    def boom(self):
        raise RuntimeError("can't start new thread")

    with monkeypatch.context() as m:
        m.setattr(threading.Thread, "start", boom)
        with pytest.raises(RuntimeError):
            runner.start({})
    assert runner.view() is None  # no job stuck at "starting"
    runner.start({})  # and the next click works
    assert _wait_for(runner, "finished").status == "ok"


def test_shutdown_without_a_job_is_a_no_op(settings):
    _runner(settings, FakeScan()).shutdown()


def test_eta_needs_five_images():
    assert eta(T0, T0 + timedelta(seconds=50), 5, 10) == timedelta(seconds=50)
    assert eta(T0, T0 + timedelta(seconds=50), 4, 10) is None
    assert eta(T0, T0 + timedelta(seconds=50), 10, 10) == timedelta(0)


def test_view_eta_counts_from_the_first_scanned_image_not_the_click(settings):
    now = [T0]
    scan = FakeScan()
    runner = _runner(settings, scan, clock=lambda: now[0])
    runner.start({})
    assert scan.entered.wait(5)
    scan.on_progress(Progress(total=0, done=0, errors=0, current=None, phase="inventory"))
    now[0] = T0 + timedelta(minutes=10)  # a slow inventory and Trivy DB download must not count
    scan.on_progress(Progress(total=12, done=0, errors=0, current=None, phase="trivy-db"))
    scan.on_progress(Progress(total=12, done=0, errors=0, current=None, phase="scanning"))
    for done in range(1, 7):
        now[0] += timedelta(seconds=10)
        scan.on_progress(Progress(total=12, done=done, errors=0, current=f"example.com/app:{done}"))
    assert runner.view().eta == timedelta(seconds=60)  # 6 images in 60 s, 6 left
    scan.release.set()
    view = _wait_for(runner, "finished")
    assert view.eta is None
