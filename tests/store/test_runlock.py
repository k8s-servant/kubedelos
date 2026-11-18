import subprocess
import sys
import time

import pytest

from kubedelos.store import runlock
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo

NOTE = "closed by kubedelos: no live process owned this run"


@pytest.fixture
def repo(tmp_path):
    conn = connect(tmp_path / "k.db")
    yield Repo(conn)
    conn.close()


def _start(repo, owner):
    return repo.start_run("my-cluster", "cli", "0.76.1", scan_level="os", owner=owner)


def test_hold_makes_the_owner_live_until_it_exits(tmp_path):
    with runlock.hold(tmp_path) as owner:
        assert runlock.is_owned(tmp_path, owner)
    assert not runlock.is_owned(tmp_path, owner)
    assert not (tmp_path / "runs" / f"{owner}.lock").exists()


def test_hold_releases_the_lock_when_the_body_raises(tmp_path):
    with pytest.raises(RuntimeError), runlock.hold(tmp_path) as owner:
        raise RuntimeError("boom")
    assert not runlock.is_owned(tmp_path, owner)
    assert not (tmp_path / "runs" / f"{owner}.lock").exists()


@pytest.mark.parametrize("owner", ["", "../k", "deadbeef/../x", "DEADBEEF"])
def test_is_owned_rejects_owners_that_are_not_tokens(tmp_path, owner):
    assert not runlock.is_owned(tmp_path, owner)


def test_a_lock_file_nobody_holds_is_not_owned_and_is_removed(tmp_path):
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / "deadbeef.lock").touch()  # left behind by a process that was killed
    assert not runlock.is_owned(tmp_path, "deadbeef")
    assert not (tmp_path / "runs" / "deadbeef.lock").exists()


def test_sweep_leaves_a_live_cli_run_alone(tmp_path, repo):  # spec: never mark another terminal's scan failed
    with runlock.hold(tmp_path) as owner:
        run_id = _start(repo, owner)
        assert runlock.close_stale_runs(repo._conn, tmp_path) == []
        row = repo.get_run(run_id)
        assert row["status"] == "running" and row["finished_at"] is None
        assert repo.run_warnings(run_id) == []


def test_sweep_closes_a_run_whose_owner_died(tmp_path, repo):
    run_id = _start(repo, "deadbeef" * 4)
    assert runlock.close_stale_runs(repo._conn, tmp_path) == [run_id]
    row = repo.get_run(run_id)
    assert row["status"] == "failed" and row["finished_at"] is not None
    assert [r["text"] for r in repo.run_warnings(run_id)] == [NOTE]


def test_sweep_closes_pre_migration_running_rows(tmp_path, repo):
    run_id = _start(repo, None)
    assert runlock.close_stale_runs(repo._conn, tmp_path) == [run_id]
    assert repo.get_run(run_id)["status"] == "failed"


def test_sweep_leaves_finished_runs_alone(tmp_path, repo):
    run_id = _start(repo, "deadbeef" * 4)
    repo.finish_run(run_id, "ok")
    assert runlock.close_stale_runs(repo._conn, tmp_path) == []
    assert repo.get_run(run_id)["status"] == "ok"
    assert repo.run_warnings(run_id) == []


def test_sweep_keeps_a_run_that_finished_while_it_was_checked(tmp_path, repo, monkeypatch):
    run_id = _start(repo, "deadbeef" * 4)

    def finished_meanwhile(data_dir, owner):  # the owner writes its result, then releases the lock
        repo.finish_run(run_id, "ok")
        return False

    monkeypatch.setattr(runlock, "is_owned", finished_meanwhile)
    assert runlock.close_stale_runs(repo._conn, tmp_path) == []
    assert repo.get_run(run_id)["status"] == "ok"
    assert repo.run_warnings(run_id) == []


def test_hold_cleanup_errors_never_mask_the_run(tmp_path, monkeypatch):
    def unlink(self, missing_ok=False):
        raise PermissionError("read-only runs dir")

    with runlock.hold(tmp_path) as owner:
        monkeypatch.setattr(runlock.Path, "unlink", unlink)
        result = owner
    monkeypatch.undo()
    assert result == owner
    with pytest.raises(RuntimeError, match="boom"), runlock.hold(tmp_path):
        monkeypatch.setattr(runlock.Path, "unlink", unlink)
        raise RuntimeError("boom")


_HOLDER = """
import sys, time
from pathlib import Path
from kubedelos.store import runlock
with runlock.hold(Path(sys.argv[1])) as owner:
    tmp = Path(sys.argv[2] + '.tmp')
    tmp.write_text(owner)
    tmp.replace(sys.argv[2])  # whole or absent, never half written
    time.sleep(60)
"""


def _wait(condition, seconds=10):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.05)
    return condition()


def test_lock_held_by_another_process_counts_as_live(tmp_path):
    # The holder reports its owner through a file, never a pipe, so no read here can block: every wait has a deadline.
    out = tmp_path / "owner.txt"
    proc = subprocess.Popen([sys.executable, "-c", _HOLDER, str(tmp_path), str(out)])
    try:
        assert _wait(lambda: out.exists() or proc.poll() is not None)
        assert proc.poll() is None, "the holder process exited early"
        owner = out.read_text()
        assert runlock.is_owned(tmp_path, owner)
    finally:
        proc.kill()
        proc.wait(timeout=10)
    assert (tmp_path / "runs" / f"{owner}.lock").exists()  # killed: its lock file is left behind
    assert _wait(lambda: not runlock.is_owned(tmp_path, owner))  # but nobody holds it


def test_second_serve_lock_is_refused(tmp_path):
    with (
        runlock.hold_serve(tmp_path),
        pytest.raises(runlock.AlreadyServing, match="another kubedelos serve uses"),
        runlock.hold_serve(tmp_path),
    ):
        pass


def test_serve_lock_is_released_on_exit(tmp_path):
    with runlock.hold_serve(tmp_path):
        pass
    with runlock.hold_serve(tmp_path):
        pass
    assert (tmp_path / "serve.lock").exists()  # never deleted


_SERVE_HOLDER = """
import sys, time
from pathlib import Path
from kubedelos.store import runlock
with runlock.hold_serve(Path(sys.argv[1])):
    Path(sys.argv[2]).write_text('held')
    time.sleep(60)
"""


def test_serve_lock_held_by_another_process(tmp_path):
    # Like the run-lock test above, the holder signals through a file so no wait can block without a deadline.
    out = tmp_path / "held.txt"
    proc = subprocess.Popen([sys.executable, "-c", _SERVE_HOLDER, str(tmp_path), str(out)])
    try:
        assert _wait(lambda: out.exists() or proc.poll() is not None)
        assert proc.poll() is None, "the holder process exited early"
        with pytest.raises(runlock.AlreadyServing), runlock.hold_serve(tmp_path):
            pass
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    with runlock.hold_serve(tmp_path):  # the OS freed the lock with the process
        pass
