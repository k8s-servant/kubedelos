"""Scan images in parallel, each with its own standalone ``trivy image`` process.

Parallel Trivy processes fight over the BoltDB lock of the on-disk layer cache, so every scan keeps that cache in
memory (``--cache-backend memory``) and only reads the shared vulnerability and Java DBs, which
:class:`kubedelos.trivy.cache.TrivyCache` keeps up to date under a file lock. Every Trivy process runs in its own
process group so that a stop or a timeout also reaches its children.
"""

import contextlib
import json
import os
import signal
import subprocess
import threading
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Literal

from kubedelos.config import Settings
from kubedelos.models import ImageRef, ImageResult, InventoryItem
from kubedelos.trivy.parse import parse_report

ErrorKind = Literal["auth", "not_found", "timeout", "trivy", "unknown"]

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


def _short(text: str) -> str:
    """Trim ``text`` to its last :data:`_MAX_ERROR_CHARS` characters."""
    return text.strip()[-_MAX_ERROR_CHARS:]


def _classify(stderr: str) -> ErrorKind:
    lowered = stderr.lower()
    for kind, patterns in _ERROR_PATTERNS:
        if any(p in lowered for p in patterns):
            return kind
    return "trivy"


def scan_image(
    trivy: Path,
    item_ref: ImageRef,
    platform: str,
    timeout_s: int,
    docker_config: Path | None = None,
    *,
    cache_dir: Path | None = None,
    _groups: _ClientGroups | None = None,
) -> ImageResult:
    """Scan one image with a standalone Trivy. Failures come back as ``status="error"``; this never raises."""
    argv = [
        str(trivy),
        "image",
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
        "--cache-backend",
        "memory",  # the on-disk layer cache is a BoltDB file that parallel scans would lock each other out of
    ]
    if cache_dir is not None:
        argv += ["--cache-dir", str(cache_dir)]
    # "--" ends flag parsing, so a ref from a pod spec can never be read as a flag.
    argv += ["--skip-db-update", "--skip-java-db-update", "--", item_ref.ref]

    env = dict(os.environ)
    if docker_config is not None:
        env["DOCKER_CONFIG"] = str(docker_config)

    def error(kind: ErrorKind, message: str) -> ImageResult:
        return ImageResult(image=item_ref, platform=platform, status="error", error_kind=kind, error=_short(message))

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
    cache_dir: Path,
    trivy: Path,
    settings: Settings,
    on_result: Callable[[ImageResult], None],
    cancel: threading.Event,
) -> None:
    """Scan ``items`` with ``settings.parallelism`` workers, handing each result to ``on_result`` on this thread.

    Once ``cancel`` is set no new image starts; scans already running finish and are reported. An exception from
    ``on_result`` (or an interrupt) kills the running scans and propagates.
    """
    if not items:
        return
    workers = settings.parallelism
    groups = _ClientGroups()

    def work(item: InventoryItem) -> ImageResult:
        try:
            return scan_image(
                trivy,
                item.image,
                item.platform,
                settings.scan_timeout_s,
                cache_dir=cache_dir,
                _groups=groups,
            )
        except Exception as exc:
            return ImageResult(
                image=item.image,
                platform=item.platform,
                status="error",
                error_kind="unknown",
                error=_short(f"{type(exc).__name__}: {exc}"),
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
