"""Run one local ``trivy server`` and parallel ``trivy image --server`` clients against it.

The server owns the vulnerability DB, so it is downloaded once and parallel clients never fight over its BoltDB lock.
Every Trivy process runs in its own process group so that a stop or a timeout also reaches its children.
"""

import contextlib
import json
import os
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from types import TracebackType
from typing import IO, Literal, Self

import httpx

from kubedelos.config import Settings
from kubedelos.models import ImageRef, ImageResult, InventoryItem
from kubedelos.trivy.parse import parse_report

ErrorKind = Literal["auth", "not_found", "timeout", "trivy", "unknown"]

_READY_TIMEOUT_S = 30.0
_STOP_GRACE_S = 5.0
_DB_DOWNLOAD_TIMEOUT_S = 1800
_TIMEOUT_GRACE_S = 30  # Trivy's own --timeout should fire first; the subprocess limit is the backstop
_MAX_ERROR_CHARS = 2000

# Checked in order, case-insensitively, against a failed client's stderr.
_ERROR_PATTERNS: tuple[tuple[ErrorKind, tuple[str, ...]], ...] = (
    ("auth", ("unauthorized", "denied", "authentication required")),
    ("not_found", ("manifest unknown", "not found", "name unknown")),
    ("timeout", ("context deadline exceeded",)),  # Trivy's own --timeout expiring
)


def _kill_group(pgid: int, sig: signal.Signals) -> None:
    # Already gone is fine. macOS answers EPERM when only zombies are left in the group.
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, sig)


class _ClientGroups:
    """Process groups of the client scans still running, so an aborted :func:`scan_many` can kill them."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pgids: set[int] = set()
        self._closed = False

    def add(self, pgid: int) -> None:
        with self._lock:
            if not self._closed:
                self._pgids.add(pgid)
                return
        _kill_group(pgid, signal.SIGKILL)  # started after kill_all: stop it straight away

    def discard(self, pgid: int) -> None:
        with self._lock:
            self._pgids.discard(pgid)

    def kill_all(self) -> None:
        with self._lock:
            self._closed = True
            pgids = list(self._pgids)
        for pgid in pgids:
            _kill_group(pgid, signal.SIGKILL)


def _run_group(
    argv: list[str], env: dict[str, str], timeout_s: float, groups: _ClientGroups | None = None
) -> tuple[int, str, str]:
    """Run ``argv`` in a new process group and return ``(returncode, stdout, stderr)``.

    On timeout, or if the caller is interrupted, the whole group is killed; a timeout then raises
    :class:`subprocess.TimeoutExpired`.
    """
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        errors="replace",
        start_new_session=True,
    )
    if groups is not None:
        groups.add(proc.pid)
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except BaseException:
        _kill_group(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise
    finally:
        if groups is not None:
            groups.discard(proc.pid)
    return proc.returncode, stdout, stderr


def _short(text: str, token: str | None) -> str:
    """Trim ``text`` to its last :data:`_MAX_ERROR_CHARS` characters, with the server token masked."""
    if token:
        text = text.replace(token, "***")
    text = text.strip()
    return text[-_MAX_ERROR_CHARS:]


def _classify(stderr: str) -> ErrorKind:
    lowered = stderr.lower()
    for kind, patterns in _ERROR_PATTERNS:
        if any(p in lowered for p in patterns):
            return kind
    return "trivy"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _tail(stream: IO[bytes]) -> str:
    stream.seek(0)
    return stream.read().decode(errors="replace")[-_MAX_ERROR_CHARS:].strip()


class TrivyServer:
    """``trivy server`` on 127.0.0.1, guarded by a random token, for the lifetime of a ``with`` block."""

    def __init__(self, trivy: Path, cache_dir: Path) -> None:
        self.trivy = trivy
        self.cache_dir = cache_dir / "trivy-cache"  # shared by the server and its clients
        self.token = secrets.token_urlsafe(32)
        self._url: str | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._stderr: IO[bytes] | None = None

    @property
    def url(self) -> str:
        if self._url is None:
            raise RuntimeError("the Trivy server is not running")
        return self._url

    def __enter__(self) -> Self:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        for flag in ("--download-db-only", "--download-java-db-only"):
            self._download(flag)
        try:
            self._start()
            self._wait_ready()
        except BaseException:
            self._stop()
            raise
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self._stop()

    def _download(self, flag: str) -> None:
        argv = [str(self.trivy), "image", flag, "--cache-dir", str(self.cache_dir)]
        try:
            code, _, stderr = _run_group(argv, dict(os.environ), _DB_DOWNLOAD_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"trivy image {flag} did not finish within {_DB_DOWNLOAD_TIMEOUT_S}s") from None
        if code != 0:
            raise RuntimeError(f"trivy image {flag} failed with exit code {code}: {_short(stderr, None)}")

    def _start(self) -> None:
        port = _free_port()
        env = {**os.environ, "TRIVY_TOKEN": self.token}  # through the environment, so ps does not show it
        # A file, not a pipe: nobody drains it while the server runs. Closed in _stop.
        self._stderr = tempfile.TemporaryFile()  # noqa: SIM115
        self._proc = subprocess.Popen(
            [str(self.trivy), "server", "--listen", f"127.0.0.1:{port}", "--cache-dir", str(self.cache_dir)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=self._stderr,
            env=env,
            start_new_session=True,
        )
        self._url = f"http://127.0.0.1:{port}"

    def _wait_ready(self) -> None:
        if self._proc is None or self._stderr is None or self._url is None:
            raise RuntimeError("the Trivy server was not started")
        deadline = time.monotonic() + _READY_TIMEOUT_S
        with httpx.Client(trust_env=False, timeout=httpx.Timeout(1.0)) as client:
            while True:
                code = self._proc.poll()
                if code is not None:
                    raise RuntimeError(
                        f"trivy server exited with code {code} before it was ready: "
                        f"{_short(_tail(self._stderr), self.token)}"
                    )
                try:
                    if client.get(f"{self._url}/healthz").status_code == 200:
                        return
                except httpx.HTTPError:
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError(f"trivy server did not become ready within {_READY_TIMEOUT_S:.0f}s")
                time.sleep(0.1)

    def _stop(self) -> None:
        proc, self._proc, self._url = self._proc, None, None
        if proc is not None:
            _kill_group(proc.pid, signal.SIGTERM)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=_STOP_GRACE_S)
            # The leader may have exited on SIGTERM while children it started linger in the group.
            _kill_group(proc.pid, signal.SIGKILL)
            proc.wait()
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None


def scan_image(
    trivy: Path,
    server_url: str,
    item_ref: ImageRef,
    platform: str,
    timeout_s: int,
    docker_config: Path | None = None,
    *,
    token: str | None = None,
    cache_dir: Path | None = None,
    _groups: _ClientGroups | None = None,
) -> ImageResult:
    """Scan one image through the Trivy server. Failures come back as ``status="error"``; this never raises."""
    argv = [
        str(trivy),
        "image",
        "--server",
        server_url,
        "--format",
        "json",
        "--scanners",
        "vuln",
        "--image-src",
        "remote",
        "--platform",
        platform,
        "--quiet",
        "--timeout",
        f"{timeout_s}s",
    ]
    if cache_dir is not None:
        argv += ["--cache-dir", str(cache_dir)]
    argv += ["--skip-db-update", "--skip-java-db-update", item_ref.ref]

    env = dict(os.environ)
    if token is not None:
        env["TRIVY_TOKEN"] = token
    if docker_config is not None:
        env["DOCKER_CONFIG"] = str(docker_config)

    def error(kind: ErrorKind, message: str) -> ImageResult:
        return ImageResult(
            image=item_ref, platform=platform, status="error", error_kind=kind, error=_short(message, token)
        )

    limit = timeout_s + _TIMEOUT_GRACE_S
    try:
        code, stdout, stderr = _run_group(argv, env, limit, _groups)
    except subprocess.TimeoutExpired:
        return error("timeout", f"trivy did not finish within {limit}s")
    except OSError as exc:
        return error("trivy", f"could not run trivy: {exc}")

    if code != 0:
        return error(_classify(stderr), stderr or f"trivy exited with code {code}")
    try:
        findings, os_family = parse_report(json.loads(stdout))
    except json.JSONDecodeError as exc:
        return error("trivy", f"trivy printed invalid JSON: {exc}")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return error("trivy", f"unexpected trivy report shape: {type(exc).__name__}: {exc}")
    return ImageResult(image=item_ref, platform=platform, status="ok", findings=findings, os_family=os_family)


def scan_many(
    items: list[InventoryItem],
    *,
    server: TrivyServer,
    trivy: Path,
    settings: Settings,
    on_result: Callable[[ImageResult], None],
    cancel: threading.Event,
) -> None:
    """Scan ``items`` with ``settings.parallelism`` workers, handing each result to ``on_result`` on this thread.

    Once ``cancel`` is set no new image starts; scans already running finish and are reported. An exception from
    ``on_result`` (or an interrupt) kills the running scans and propagates.
    """
    workers = settings.parallelism
    groups = _ClientGroups()
    url, token, cache_dir = server.url, server.token, server.cache_dir

    def work(item: InventoryItem) -> ImageResult:
        try:
            return scan_image(
                trivy,
                url,
                item.image,
                item.platform,
                settings.scan_timeout_s,
                token=token,
                cache_dir=cache_dir,
                _groups=groups,
            )
        except Exception as exc:
            return ImageResult(
                image=item.image,
                platform=item.platform,
                status="error",
                error_kind="unknown",
                error=_short(f"{type(exc).__name__}: {exc}", token),
            )

    remaining = iter(items)
    exhausted = False
    pending: set[Future[ImageResult]] = set()
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="trivy-scan") as pool:
        try:
            while True:
                # Submit only as many as can run, so a cancel leaves nothing queued.
                while not exhausted and not cancel.is_set() and len(pending) < workers:
                    item = next(remaining, None)
                    if item is None:
                        exhausted = True
                    else:
                        pending.add(pool.submit(work, item))
                if not pending:
                    return
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    on_result(future.result())
        except BaseException:
            for future in pending:
                future.cancel()
            groups.kill_all()
            raise
