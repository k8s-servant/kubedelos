"""The shared Trivy cache dir, with its vulnerability and Java DBs guarded by a file lock.

Every scan is a standalone ``trivy image`` that keeps its layer cache in memory, so parallel scans and concurrent
``kubedelos scan`` runs only share the two DBs, which Trivy opens read-only. A run takes an exclusive ``flock`` to
download or update them, then holds a shared one while it scans, so no run replaces a DB another run is reading.
If another run is already scanning, the update is skipped rather than waiting for that run to finish. The kernel
drops a ``flock`` when its process dies, so a killed run never leaves a stale lock behind.
"""

import contextlib
import fcntl
import os
import subprocess
from pathlib import Path
from types import TracebackType
from typing import Self

from kubedelos.trivy.runner import _run_group, _short

_DB_DOWNLOAD_TIMEOUT_S = 1800
_LOCK_FILE = ".kubedelos.lock"


class TrivyCache:
    """``<cache_dir>/trivy-cache`` with up-to-date DBs, share-locked for the lifetime of a ``with`` block."""

    def __init__(self, trivy: Path, cache_dir: Path) -> None:
        self.trivy = trivy
        self.dir = cache_dir / "trivy-cache"
        self.updated = False
        self._fd: int | None = None

    def __enter__(self) -> Self:
        self.dir.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(self.dir / _LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                # Another run holds the lock. A shared lock waits only while that run downloads.
                fcntl.flock(self._fd, fcntl.LOCK_SH)
            else:
                for flag in ("--download-db-only", "--download-java-db-only"):
                    self._download(flag)
                fcntl.flock(self._fd, fcntl.LOCK_SH)
                self.updated = True
        except BaseException:
            self._close()
            raise
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self._close()

    def _download(self, flag: str) -> None:
        argv = [str(self.trivy), "image", flag, "--cache-dir", str(self.dir)]
        try:
            code, _, stderr = _run_group(argv, dict(os.environ), _DB_DOWNLOAD_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"trivy image {flag} did not finish within {_DB_DOWNLOAD_TIMEOUT_S}s") from None
        if code != 0:
            raise RuntimeError(f"trivy image {flag} failed with exit code {code}: {_short(stderr)}")

    def _close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)  # closing the last descriptor releases the flock
