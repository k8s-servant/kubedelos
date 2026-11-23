import threading
from datetime import UTC, datetime

import pytest

from kubedelos.store import queue
from kubedelos.store.db import connect
from kubedelos.store.queue import MAX_QUEUED, QueueFull
from kubedelos.store.repo import Repo

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "k.db")
    yield c
    c.close()


def _ui(conn, **overrides):
    return queue.enqueue(conn, kind="scan", trigger="ui", overrides=overrides, requested_by="a@example.com", now=NOW)


def _schedule(conn):
    return queue.enqueue(conn, kind="scan", trigger="schedule", overrides={}, now=NOW)


def _run(conn):
    return Repo(conn).start_run("my-cluster", "my-cluster", "cli", "0.76.1", scan_level="os", owner="o")


def test_schedule_requests_coalesce_while_queued(conn):
    first = _schedule(conn)
    second = _schedule(conn)
    assert first.added is True
    assert second.added is False
    assert second.id == first.id
    assert len(queue.queued(conn)) == 1


def test_schedule_is_queued_again_once_the_first_started(conn):
    _schedule(conn)
    queue.claim_next(conn)
    assert _schedule(conn).added is True


def test_ui_requests_coalesce_on_equal_overrides(conn):
    first = _ui(conn, namespaces=["a", "b"], rescan=True)
    same = _ui(conn, rescan=True, namespaces=["a", "b"])
    other = _ui(conn, namespaces=["a"])
    assert same.added is False and same.id == first.id
    assert other.added is True and other.id != first.id


def test_retries_coalesce_per_run(conn):
    run_a, run_b = _run(conn), _run(conn)

    def retry(run_id):
        return queue.enqueue(conn, kind="retry", trigger="ui", overrides={}, target_run_id=run_id, now=NOW)

    first = retry(run_a)
    assert retry(run_a) == queue.Enqueued(id=first.id, added=False)
    assert retry(run_b).added is True


def test_queue_is_bounded(conn):
    for i in range(MAX_QUEUED):
        assert _ui(conn, namespaces=[f"ns-{i}"]).added is True
    with pytest.raises(QueueFull):
        _ui(conn, namespaces=["one-too-many"])
    assert _ui(conn, namespaces=["ns-0"]).added is False
    assert len(queue.queued(conn)) == MAX_QUEUED


def test_claim_next_is_fifo_and_skips_cancelled(conn):
    ids = [_ui(conn, namespaces=[n]).id for n in "abc"]
    assert queue.cancel(conn, ids[0]) is True
    assert queue.claim_next(conn).id == ids[1]
    assert queue.claim_next(conn).id == ids[2]
    assert queue.claim_next(conn) is None


def test_claim_from_two_threads_never_returns_the_same_request(conn, tmp_path):
    for i in range(10):
        _ui(conn, namespaces=[f"first-{i}"])
    claimed: list[list[int]] = [[], []]

    def work(slot):
        own = connect(tmp_path / "k.db")
        try:
            while (request := queue.claim_next(own)) is not None:
                claimed[slot].append(request.id)
        finally:
            own.close()

    def run_threads():
        threads = [threading.Thread(target=work, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    run_threads()
    for i in range(10):
        _ui(conn, namespaces=[f"second-{i}"])
    run_threads()
    everything = claimed[0] + claimed[1]
    assert len(everything) == 20
    assert len(set(everything)) == 20


def test_cancel_only_queued(conn):
    request = _schedule(conn)
    queue.claim_next(conn)
    assert queue.cancel(conn, request.id) is False
    assert conn.execute("SELECT state FROM scan_request WHERE id = ?", (request.id,)).fetchone()[0] == "started"


def test_abandon_started_cancels_orphans_only(conn):
    orphan = _ui(conn, namespaces=["a"]).id
    running = _ui(conn, namespaces=["b"]).id
    queue.claim_next(conn)
    queue.claim_next(conn)
    queue.attach_run(conn, running, _run(conn))
    assert queue.abandon_started(conn) == 1
    states = dict(conn.execute("SELECT id, state FROM scan_request").fetchall())
    assert states == {orphan: "cancelled", running: "started"}


def test_requeue_puts_back_only_a_started_request_without_a_run(conn):
    first = _ui(conn, namespaces=["a"]).id
    second = _ui(conn, namespaces=["b"]).id
    waiting = _ui(conn, namespaces=["c"]).id
    queue.claim_next(conn)
    queue.claim_next(conn)
    queue.attach_run(conn, second, _run(conn))
    assert queue.requeue(conn, first) is True
    assert queue.requeue(conn, second) is False  # it already has its run
    assert queue.requeue(conn, waiting) is False  # still queued
    assert [r.id for r in queue.queued(conn)] == [first, waiting]  # back at the front: it keeps its id
    assert queue.claim_next(conn).id == first


def test_overrides_round_trip(conn):
    queue.enqueue(
        conn,
        kind="scan",
        trigger="ui",
        overrides={"pkg_types": ("os",), "rescan": True},
        requested_by="a@example.com",
        now=NOW,
    )
    request = queue.claim_next(conn)
    assert request.overrides == {"pkg_types": ["os"], "rescan": True}
    assert request.state == "started"
    assert request.requested_by == "a@example.com"
    assert request.requested_at == NOW.isoformat()
