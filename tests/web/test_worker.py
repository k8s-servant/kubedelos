"""Tests for the queue worker: sweeps and UI requests run one at a time, in order, and a finished sweep prunes."""

import sqlite3
import threading
import time
from datetime import UTC, datetime

import pytest

from kubedelos.config import Settings
from kubedelos.scan.service import ScanOutcome
from kubedelos.store import db, queue, retention
from kubedelos.store.repo import Repo
from kubedelos.web.jobs import JobView, ScanBusy, ScanRunner
from kubedelos.web.worker import QueueWorker

NOW = datetime(2026, 11, 18, 3, 0, tzinfo=UTC)


class FakeScan:
    """Records each call, stores a real run row (the request's run_id is a foreign key) and returns at once."""

    def __init__(self, status: str = "ok") -> None:
        self.status = status
        self.calls: list[dict] = []
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def __call__(self, settings, **kw):
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            conn = db.connect(settings.db_path)
            try:
                run_id = Repo(conn).start_run("my-cluster", kw.get("trigger"), "0.76.1", scan_level="library,os")
            finally:
                conn.close()
            self.calls.append({"settings": settings, "run_id": run_id, **kw})
            return ScanOutcome(run_id=run_id, warnings=[], status=self.status)
        finally:
            with self._lock:
                self.active -= 1


def wait_until(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition never became true"
        threading.Event().wait(0.01)


@pytest.fixture
def settings(tmp_path):
    return Settings(cluster_name="my-cluster", data_dir=tmp_path / "data", cache_dir=tmp_path / "cache")


@pytest.fixture
def conn(settings):
    c = db.connect(settings.db_path)
    yield c
    c.close()


@pytest.fixture
def make(settings):
    """Build a runner and worker around a fake scan; both are stopped when the test ends."""
    made: list[tuple[ScanRunner, QueueWorker]] = []

    def build(scan):
        runner = ScanRunner(settings, "my-cluster", fixed_cluster=True, scan=scan)
        worker = QueueWorker(settings, runner, clock=lambda: NOW, poll_s=0.01)
        made.append((runner, worker))
        return worker

    yield build
    for runner, worker in made:
        worker.stop()
        runner.shutdown(timeout=5)


def _request(conn, request_id):
    return conn.execute("SELECT state, run_id FROM scan_request WHERE id = ?", (request_id,)).fetchone()


def _ui(conn, **overrides):
    return queue.enqueue(conn, kind="scan", trigger="ui", overrides=overrides, requested_by="a@example.com", now=NOW)


def test_sweep_runs_and_records_its_run(make, conn):
    scan = FakeScan()
    worker = make(scan)
    worker.start()
    worker.enqueue_sweep()
    wait_until(lambda: _request(conn, 1) is not None and _request(conn, 1)["run_id"] is not None)
    call = scan.calls[0]
    assert (call["trigger"], call["rescan"], call["requested_by"]) == ("schedule", True, None)
    row = _request(conn, 1)
    assert (row["state"], row["run_id"]) == ("started", call["run_id"])


def test_requests_run_one_at_a_time_in_order(make, conn):
    scan = FakeScan()
    worker = make(scan)
    ids = [_ui(conn, namespaces=[name]).id for name in ("team-a", "team-b", "team-c")]
    worker.start()
    wait_until(lambda: all(_request(conn, i)["run_id"] is not None for i in ids))
    assert [c["settings"].namespaces for c in scan.calls] == [["team-a"], ["team-b"], ["team-c"]]
    assert [c["requested_by"] for c in scan.calls] == ["a@example.com"] * 3
    assert all(c["trigger"] == "ui" and c["rescan"] is False for c in scan.calls)
    assert scan.max_active == 1
    assert [_request(conn, i)["run_id"] for i in ids] == [c["run_id"] for c in scan.calls]


@pytest.fixture
def pruned(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(retention, "prune", lambda conn, **kw: calls.append(kw) or [])
    return calls


def test_finished_sweep_prunes(make, conn, settings, pruned):
    worker = make(FakeScan(status="partial"))
    worker.start()
    worker.enqueue_sweep()
    wait_until(lambda: pruned)
    assert pruned == [{"now": NOW, "retention_days": settings.retention_days}]


def test_ui_scan_does_not_prune(make, conn, pruned):
    worker = make(FakeScan())
    first = _ui(conn, namespaces=["team-a"]).id
    second = _ui(conn, namespaces=["team-b"]).id
    worker.start()
    # The second request is attached only after the first has been settled, pruning or not.
    wait_until(lambda: _request(conn, second)["run_id"] is not None)
    assert _request(conn, first)["run_id"] is not None
    assert pruned == []


def test_cancelled_sweep_does_not_prune(make, conn, pruned):
    worker = make(FakeScan(status="cancelled"))
    worker.start()
    worker.enqueue_sweep()
    later = _ui(conn, namespaces=["team-a"]).id
    wait_until(lambda: _request(conn, later)["run_id"] is not None)
    assert pruned == []


def test_invalid_overrides_are_skipped_not_fatal(make, conn):
    scan = FakeScan()
    worker = make(scan)
    bad = _ui(conn, parallelism=999).id
    good = _ui(conn, namespaces=["team-a"]).id
    worker.start()
    wait_until(lambda: _request(conn, good)["run_id"] is not None)
    assert len(scan.calls) == 1 and scan.calls[0]["settings"].namespaces == ["team-a"]
    assert _request(conn, bad)["run_id"] is None


def test_retry_request_runs_the_retry(settings, conn):
    retries: list[dict] = []

    def retry(retry_settings, **kw):
        retries.append({"settings": retry_settings, **kw})
        return ScanOutcome(run_id=kw["run_id"], warnings=[], status="ok")

    target = Repo(conn).start_run("my-cluster", "schedule", "0.76.1", scan_level="library,os")
    runner = ScanRunner(settings, "my-cluster", fixed_cluster=True, scan=FakeScan(), retry=retry)
    worker = QueueWorker(settings, runner, clock=lambda: NOW, poll_s=0.01)
    try:
        req = queue.enqueue(
            conn,
            kind="retry",
            trigger="ui",
            overrides={"kinds": ["timeout"], "parallelism": 2, "scan_timeout_s": 1800},
            target_run_id=target,
            now=NOW,
        ).id
        worker.start()
        wait_until(lambda: _request(conn, req)["run_id"] is not None)
        call = retries[0]
        assert call["run_id"] == target and set(call["kinds"]) == {"timeout"}
        assert (call["settings"].parallelism, call["settings"].scan_timeout_s) == (2, 1800)
    finally:
        worker.stop()
        runner.shutdown(timeout=5)


def test_a_failing_pass_does_not_end_the_worker(make, conn, monkeypatch):
    scan = FakeScan()
    worker = make(scan)
    real = queue.claim_next
    failures = []

    def flaky(c):
        if not failures:
            failures.append(True)
            raise RuntimeError("database is locked")
        return real(c)

    monkeypatch.setattr(queue, "claim_next", flaky)
    req = _ui(conn, namespaces=["team-a"]).id
    worker.start()
    wait_until(lambda: _request(conn, req)["run_id"] is not None)
    assert failures and worker.alive()


def test_a_full_queue_drops_the_sweep(make, conn, caplog):
    worker = make(FakeScan())
    for i in range(queue.MAX_QUEUED):
        _ui(conn, namespaces=[f"team-{i}"])
    worker.enqueue_sweep()  # not started, so nothing drains the queue: the sweep is dropped with a warning
    assert all(r.trigger == "ui" for r in queue.queued(conn))
    assert "queue is full" in caplog.text


def test_a_locked_database_drops_the_sweep_with_a_warning(make, monkeypatch, caplog):
    worker = make(FakeScan())

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(queue, "enqueue", locked)
    worker.enqueue_sweep()  # must not raise on the scheduler's thread
    assert "scheduled sweep skipped (OperationalError)" in caplog.text


def test_stop_ends_the_thread(make):
    worker = make(FakeScan())
    worker.start()
    assert worker.alive()
    worker.stop()
    wait_until(lambda: not worker.alive(), timeout=2)


def test_a_shut_down_runner_ends_the_worker(make, conn, settings):
    worker = make(FakeScan())
    worker._runner.shutdown()
    _ui(conn, namespaces=["team-a"])
    worker.start()
    wait_until(lambda: not worker.alive(), timeout=2)


class StubRunner:
    """A runner whose view and launches the test sets by hand, to drive the worker's passes one at a time."""

    def __init__(self) -> None:
        self.current: JobView | None = None
        self.closed = False
        self.launch_error: BaseException | None = None
        self.launches: list[dict] = []
        self._ids = 0

    def view(self) -> JobView | None:
        return self.current

    def start(self, overrides, **kw) -> int:
        return self._launch(overrides, **kw)

    def retry(self, run_id, overrides, **kw) -> int:
        return self._launch(overrides, run_id=run_id, **kw)

    def _launch(self, overrides, **kw) -> int:
        if self.launch_error is not None:
            raise self.launch_error
        self._ids += 1
        self.launches.append({"overrides": overrides, **kw})
        self.current = _view("starting", job_id=self._ids)
        return self._ids


def _view(state, *, job_id, run_id=None, status=None):
    return JobView(state, run_id, None, status, None, None, "my-cluster", job_id=job_id)


@pytest.fixture
def stub(settings):
    runner = StubRunner()
    return runner, QueueWorker(settings, runner, clock=lambda: NOW, poll_s=0.01)


def test_a_foreign_job_is_never_attributed_to_the_worker_request(stub, conn, pruned):
    runner, worker = stub
    mine = queue.enqueue(conn, kind="scan", trigger="schedule", overrides={"rescan": True}, now=NOW).id
    assert worker._pass(conn) is True
    assert runner.launches and runner.current.job_id == 1
    # Someone else's scan ran and finished before this pass saw ours end.
    runner.current = _view("running", job_id=2)
    worker._pass(conn)
    assert _request(conn, mine)["run_id"] is None and _request(conn, mine)["state"] == "started"
    foreign_run = Repo(conn).start_run("my-cluster", "ui", "0.76.1", scan_level="library,os")
    runner.current = _view("finished", job_id=2, run_id=foreign_run, status="ok")
    later = _ui(conn, namespaces=["team-a"]).id
    worker._pass(conn)
    assert _request(conn, mine)["run_id"] is None  # not the foreign run
    assert pruned == []  # and the foreign "ok" does not count as a finished sweep
    assert len(runner.launches) == 2 and _request(conn, later)["state"] == "started"  # and the worker moved on


def test_the_worker_settles_its_own_job_by_id(stub, conn, pruned):
    runner, worker = stub
    mine = queue.enqueue(conn, kind="scan", trigger="schedule", overrides={"rescan": True}, now=NOW).id
    worker._pass(conn)
    run = Repo(conn).start_run("my-cluster", "schedule", "0.76.1", scan_level="library,os")
    runner.current = _view("finished", job_id=1, run_id=run, status="ok")
    worker._pass(conn)
    assert _request(conn, mine)["run_id"] == run and len(pruned) == 1


def test_a_transient_busy_runner_requeues_and_runs_later(stub, conn):
    runner, worker = stub
    req = _ui(conn, namespaces=["team-a"]).id
    runner.launch_error = ScanBusy("a scan is already running")
    assert worker._pass(conn) is True  # busy, not closed: keep going
    assert _request(conn, req)["state"] == "queued" and runner.launches == []
    runner.launch_error = None
    worker._pass(conn)
    assert _request(conn, req)["state"] == "started" and len(runner.launches) == 1


def test_a_launch_that_raises_leaves_no_orphan(stub, conn):
    runner, worker = stub
    bad = _ui(conn, namespaces=["team-a"]).id
    good = _ui(conn, namespaces=["team-b"]).id
    runner.launch_error = RuntimeError("can't start new thread")
    with pytest.raises(RuntimeError):
        worker._pass(conn)
    row = _request(conn, bad)
    assert (row["state"], row["run_id"]) == ("started", None)  # settled as run-less, not left in flight
    runner.launch_error = None
    worker._pass(conn)
    assert _request(conn, good)["state"] == "started" and len(runner.launches) == 1


def test_a_closed_runner_ends_the_loop_and_keeps_the_request_queued(stub, conn):
    runner, worker = stub
    req = _ui(conn, namespaces=["team-a"]).id
    runner.launch_error = ScanBusy("the UI is shutting down")
    runner.closed = True
    worker.start()
    wait_until(lambda: not worker.alive(), timeout=2)
    assert _request(conn, req)["state"] == "queued"  # for the next start
