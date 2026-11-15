"""Run ownership locks, and the sweep that closes runs no live process owns.

A scan that is killed (SIGKILL, a crash, a closed laptop) leaves its ``scan_run`` row as ``running`` for ever. The UI
must close such rows, but must never close a scan still going on in another terminal. So every run is owned by a
lock file, ``<data_dir>/runs/<owner>.lock``, holding an exclusive OS lock for the whole run, and its token is stored on
the row. The OS drops the lock when the process dies, however it dies, so "nobody holds the lock" means "no live
process owns this run".
"""

import contextlib
import os
import re
import secrets
import sqlite3
import sys
from collections.abc import Iterator
from pathlib import Path

from kubedelos.store.repo import Repo

STALE_NOTE = "closed by kubedelos: no live process owned this run"

_OWNER_RE = re.compile(r"[0-9a-f]+")  # tokens are hex; anything else (a path, say) never names a lock file

if sys.platform == "win32":  # pragma: no cover - not exercised on the POSIX CI
    import msvcrt

    def _try_lock(fd: int) -> bool:
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    def _unlock(fd: int) -> None:
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


def _lock_path(data_dir: Path, owner: str) -> Path:
    return Path(data_dir) / "runs" / f"{owner}.lock"


@contextlib.contextmanager
def hold(data_dir: Path) -> Iterator[str]:
    """Create and lock a fresh lock file, yield its owner token, then unlock and delete it."""
    runs = Path(data_dir) / "runs"
    runs.mkdir(mode=0o700, parents=True, exist_ok=True)
    owner = secrets.token_hex(16)
    path = _lock_path(data_dir, owner)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        if not _try_lock(fd):
            raise OSError(f"could not lock the new run lock file {path}")
        try:
            yield owner
        finally:
            # Cleanup must never mask the run's own result or exception, so its errors are ignored.
            if sys.platform != "win32":
                # Delete while still locked, so a checker can never lock the file in the gap and see a dead owner.
                with contextlib.suppress(OSError):
                    path.unlink(missing_ok=True)
            _unlock(fd)
    finally:
        os.close(fd)
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)  # Windows cannot delete an open file: do it once closed


def is_owned(data_dir: Path, owner: str) -> bool:
    """True when some open handle, in this process or another, holds the lock of ``owner``.

    A lock file nobody holds was left by a process that died; it is deleted while locked, so files don't pile up.
    That can't hit a run that is starting: an owner reaches the database only after its file is locked.
    """
    if not _OWNER_RE.fullmatch(owner):
        return False
    try:
        fd = os.open(_lock_path(data_dir, owner), os.O_RDWR)  # never O_CREAT: a missing file means no owner
    except FileNotFoundError:
        return False
    try:
        if not _try_lock(fd):
            return True
        with contextlib.suppress(OSError):  # on Windows an open file can't be deleted: it is left in place
            _lock_path(data_dir, owner).unlink()
        _unlock(fd)
        return False
    finally:
        os.close(fd)


def close_stale_runs(conn: sqlite3.Connection, data_dir: Path) -> list[int]:
    """Mark ``failed`` every running run no live process owns, note why, and return their ids."""
    repo = Repo(conn)
    closed = []
    for row in conn.execute("SELECT id, owner FROM scan_run WHERE status = 'running' ORDER BY id").fetchall():
        if row["owner"] is not None and is_owned(data_dir, row["owner"]):
            continue
        # close_stale only closes a row still "running", so a run that ended since the SELECT keeps its result.
        if repo.close_stale(row["id"], STALE_NOTE):
            closed.append(row["id"])
    return closed
