import fcntl
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from kubedelos.trivy.cache import TrivyCache

FAKE_TRIVY = Path(__file__).parent / "fake_trivy.py"


def _lock_path(tmp_path: Path) -> Path:
    path = tmp_path / "trivy-cache" / ".kubedelos.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _fake_dbs(tmp_path: Path) -> None:
    """Leave the files a finished Trivy DB download leaves behind."""
    for sub in ("db", "java-db"):
        (tmp_path / "trivy-cache" / sub).mkdir(parents=True, exist_ok=True)
        (tmp_path / "trivy-cache" / sub / "metadata.json").write_text("{}")


def _try_exclusive(tmp_path: Path) -> bool:
    with open(_lock_path(tmp_path), "a") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True


def test_downloads_both_dbs_into_trivy_cache(tmp_path, monkeypatch):
    log = tmp_path / "downloads.jsonl"
    monkeypatch.setenv("FAKE_TRIVY_DOWNLOAD_LOG", str(log))
    with TrivyCache(FAKE_TRIVY, tmp_path) as cache:
        assert cache.dir == tmp_path / "trivy-cache"
        assert cache.updated is True
    cache_dir = str(tmp_path / "trivy-cache")
    assert [json.loads(line) for line in log.read_text().splitlines()] == [
        ["image", "--download-db-only", "--cache-dir", cache_dir],
        ["image", "--download-java-db-only", "--cache-dir", cache_dir],
    ]


def test_lock_file_is_private(tmp_path):
    with TrivyCache(FAKE_TRIVY, tmp_path):
        pass
    assert stat.S_IMODE((tmp_path / "trivy-cache" / ".kubedelos.lock").stat().st_mode) == 0o600


def test_holds_a_shared_lock_while_open(tmp_path):
    with TrivyCache(FAKE_TRIVY, tmp_path):
        assert not _try_exclusive(tmp_path)  # a concurrent run cannot update the DB under the scans


def test_busy_cache_skips_update_and_shares(tmp_path, monkeypatch):
    log = tmp_path / "downloads.jsonl"
    monkeypatch.setenv("FAKE_TRIVY_DOWNLOAD_LOG", str(log))
    _fake_dbs(tmp_path)
    with open(_lock_path(tmp_path), "a") as other:
        fcntl.flock(other, fcntl.LOCK_SH)  # another run is scanning
        start = time.monotonic()
        with TrivyCache(FAKE_TRIVY, tmp_path) as cache:
            assert cache.updated is False
        assert time.monotonic() - start < 2
    assert not log.exists()


def test_waits_while_another_process_downloads(tmp_path):
    entered = threading.Event()
    seen: list[bool] = []

    def run() -> None:
        with TrivyCache(FAKE_TRIVY, tmp_path) as cache:
            seen.append(cache.updated)
            entered.set()

    with open(_lock_path(tmp_path), "a") as other:
        fcntl.flock(other, fcntl.LOCK_EX)  # another run is downloading
        worker = threading.Thread(target=run)
        worker.start()
        assert not entered.wait(0.3)
        _fake_dbs(tmp_path)  # its download finishes
    assert entered.wait(2)
    worker.join(2)
    assert seen == [False]


def test_takes_over_when_another_run_left_no_db(tmp_path, monkeypatch):
    log = tmp_path / "downloads.jsonl"
    monkeypatch.setenv("FAKE_TRIVY_DOWNLOAD_LOG", str(log))
    seen: list[bool] = []

    def run() -> None:
        with TrivyCache(FAKE_TRIVY, tmp_path) as cache:
            seen.append(cache.updated)

    with open(_lock_path(tmp_path), "a") as other:
        fcntl.flock(other, fcntl.LOCK_EX)  # another run is downloading...
        worker = threading.Thread(target=run)
        worker.start()
        time.sleep(0.3)
    # ...and dies or fails without leaving a DB: never scan against a missing DB, download it instead
    worker.join(5)
    assert seen == [True]
    assert len(log.read_text().splitlines()) == 2


def test_download_failure_releases_lock(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_TRIVY_DOWNLOAD_FAIL", "FATAL db download failed")
    with pytest.raises(RuntimeError, match="--download-db-only failed with exit code 1: FATAL db download failed"):
        TrivyCache(FAKE_TRIVY, tmp_path).__enter__()
    assert _try_exclusive(tmp_path)


def test_releases_lock_on_exit(tmp_path):
    with TrivyCache(FAKE_TRIVY, tmp_path):
        pass
    assert _try_exclusive(tmp_path)


_SIGTERM_WHILE_WAITING = """
import fcntl, os, signal, sys, threading
from pathlib import Path
from kubedelos import cli
from kubedelos.trivy.cache import TrivyCache
trivy, cache_dir = Path(sys.argv[1]), Path(sys.argv[2])
(cache_dir / "trivy-cache").mkdir(parents=True, exist_ok=True)
holder = open(cache_dir / "trivy-cache" / ".kubedelos.lock", "a")
fcntl.flock(holder, fcntl.LOCK_EX)  # a second open file description: TrivyCache must wait for it
threading.Timer(0.3, os.kill, (os.getpid(), signal.SIGTERM)).start()
try:
    with cli._signals_as_interrupt(), TrivyCache(trivy, cache_dir):
        sys.exit(0)
except KeyboardInterrupt:
    sys.exit(130)
"""


def test_sigterm_while_waiting_for_lock_exits(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-c", _SIGTERM_WHILE_WAITING, str(FAKE_TRIVY), str(tmp_path)],
        env=dict(os.environ),
        timeout=10,
        check=False,
    )
    assert proc.returncode == 130


def _downloads(log: Path) -> list[str]:
    return [json.loads(line)[1] for line in log.read_text().splitlines()] if log.exists() else []


def test_os_only_skips_java_db(tmp_path, monkeypatch):
    log = tmp_path / "downloads.jsonl"
    monkeypatch.setenv("FAKE_TRIVY_DOWNLOAD_LOG", str(log))
    with TrivyCache(FAKE_TRIVY, tmp_path, java_db=False):
        pass
    assert _downloads(log) == ["--download-db-only"]


def test_library_run_downloads_java_db_after_os_only(tmp_path, monkeypatch):
    log = tmp_path / "downloads.jsonl"
    monkeypatch.setenv("FAKE_TRIVY_DOWNLOAD_LOG", str(log))
    with TrivyCache(FAKE_TRIVY, tmp_path, java_db=False):
        pass
    with TrivyCache(FAKE_TRIVY, tmp_path, java_db=True):
        pass
    assert _downloads(log) == ["--download-db-only", "--download-db-only", "--download-java-db-only"]


def test_busy_os_only_cache_does_not_need_java_db(tmp_path, monkeypatch):
    log = tmp_path / "downloads.jsonl"
    monkeypatch.setenv("FAKE_TRIVY_DOWNLOAD_LOG", str(log))
    (tmp_path / "trivy-cache" / "db").mkdir(parents=True)
    (tmp_path / "trivy-cache" / "db" / "metadata.json").write_text("{}")  # no java-db: an OS-only cache
    with open(_lock_path(tmp_path), "a") as other:
        fcntl.flock(other, fcntl.LOCK_SH)
        with TrivyCache(FAKE_TRIVY, tmp_path, java_db=False) as cache:
            assert cache.updated is False
    assert _downloads(log) == []
