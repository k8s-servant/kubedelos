"""The shared Trivy cache dir, with its vulnerability and Java DBs guarded by a file lock.

Every scan is a standalone ``trivy image`` that keeps its layer cache in memory, so parallel scans and concurrent
``kubedelos scan`` runs only share the two DBs, which Trivy opens read-only. A run takes an exclusive ``flock`` to
download or update them, then holds a shared one while it scans, so no run replaces a DB another run is reading.
If another run is already scanning, the update is skipped rather than waiting for that run to finish. The kernel
drops a ``flock`` when its process dies, so a killed run never leaves a stale lock behind; a run whose download
failed or was killed leaves no usable DB, so the next run to get the lock downloads it instead of scanning without.
"""

import contextlib
import fcntl
import os
import subprocess
import sys
from pathlib import Path
from types import TracebackType
from typing import Self

from kubedelos.trivy.runner import _run_group, _short

_DB_DOWNLOAD_TIMEOUT_S = 1800
_LOCK_FILE = ".kubedelos.lock"
_DB_METADATA = "db/metadata.json"  # written by Trivy once a download finished
_JAVA_DB_METADATA = "java-db/metadata.json"


class TrivyCache:
    """``<cache_dir>/trivy-cache`` with up-to-date DBs, share-locked for the lifetime of a ``with`` block."""

    def __init__(self, trivy: Path, cache_dir: Path, *, java_db: bool = True) -> None:
        self.trivy = trivy
        self.java_db = java_db  # the Java DB (about 1.5 GB) is only needed when libraries are scanned
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
                if self._dbs_present():
                    return self
                # That run's download failed, it was killed, or it scans OS packages only and never fetched the Java
                # DB: wait for the readers to finish, then download. Say so, since the wait can last a whole scan.
                sys.stderr.write("waiting for another kubedelos run to finish with the Trivy DB cache...\n")
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                fcntl.flock(self._fd, fcntl.LOCK_EX)
            for flag in ("--download-db-only", "--download-java-db-only")[: 2 if self.java_db else 1]:
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

    def _dbs_present(self) -> bool:
        needed = (_DB_METADATA, _JAVA_DB_METADATA) if self.java_db else (_DB_METADATA,)
        return all((self.dir / name).is_file() for name in needed)

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
