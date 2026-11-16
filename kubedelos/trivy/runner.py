"""Scan images in parallel, each with its own standalone ``trivy image`` process.

Parallel Trivy processes fight over the BoltDB lock of the on-disk layer cache, so every scan keeps that cache in
memory (``--cache-backend memory``) and only reads the shared vulnerability and Java DBs, which
:class:`kubedelos.trivy.cache.TrivyCache` keeps up to date under a file lock. Every Trivy process runs in its own
process group so that a stop or a timeout also reaches its children. Being in its own session, a Trivy process never
gets the terminal's Ctrl-C, so every group this process starts is also kept in a process-wide registry, and
:func:`kill_all_running` stops them all when the UI shuts down mid-scan.
"""

import contextlib
import json
import os
import re
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Literal

from kubedelos.config import Settings
from kubedelos.models import ImageRef, ImageResult, InventoryItem, is_digest
from kubedelos.trivy.parse import parse_report

ErrorKind = Literal["auth", "not_found", "timeout", "trivy", "unknown"]

_TIMEOUT_GRACE_S = 30  # Trivy's own --timeout should fire first; the subprocess limit is the backstop
_MAX_ERROR_CHARS = 2000

# Checked in order, case-insensitively, against a failed client's stderr.
_ERROR_PATTERNS: tuple[tuple[ErrorKind, tuple[str, ...]], ...] = (
    # A missing or failing credential helper: "error getting credentials - err: exec: ...: executable file not found".
    ("auth", ("unauthorized", "denied", "authentication required", "error getting credentials")),
    ("not_found", ("manifest unknown", "not found", "name unknown")),
    ("timeout", ("context deadline exceeded",)),  # Trivy's own --timeout expiring
)


# Errors a second attempt usually gets past: a registry or network hiccup mid-download. Matched case-insensitively on a
# failed result's error. Timeouts (Trivy's own deadline), auth and not-found errors are never retried.
_PASSING_ERRORS = (
    "unexpected eof",
    "connection reset",
    "broken pipe",
    "i/o timeout",
    "tls handshake timeout",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
    "too many requests",
)
_RETRY_DELAY_S = 2.0
RETRIED_PREFIX = "failed twice: "


def _passing(result: ImageResult) -> bool:
    """Whether ``result`` failed in a way one more attempt is likely to get past."""
    if result.status != "error" or result.error_kind not in ("trivy", "unknown"):
        return False
    lowered = (result.error or "").lower()
    return any(p in lowered for p in _PASSING_ERRORS)


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

    def pgids(self) -> list[int]:
        with self._lock:
            return list(self._pgids)

    def kill_all(self, *, close: bool = True) -> None:
        """SIGKILL every group; with ``close``, also any group added later."""
        with self._lock:
            self._closed = close
            pgids = list(self._pgids)
        for pgid in pgids:
            _kill_group(pgid, signal.SIGKILL)


# Every Trivy process group this process started that is still running, whoever started it.
_RUNNING = _ClientGroups()


def running_groups() -> list[int]:
    """The process groups of the Trivy processes still running."""
    return _RUNNING.pgids()


def kill_all_running() -> None:
    """SIGKILL every Trivy process group still running in this process: scans and DB downloads alike."""
    _RUNNING.kill_all(close=False)


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
    _RUNNING.add(proc.pid)
    if groups is not None:
        groups.add(proc.pid)
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except BaseException:
        _kill_group(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise
    finally:
        _RUNNING.discard(proc.pid)
        if groups is not None:
            groups.discard(proc.pid)
    return proc.returncode, stdout, stderr


# Signed storage URLs (Azure Blob ``sig=``, S3 ``X-Amz-Signature``) carry credentials in the query string, and
# ``user:password@`` carries them in the authority; Trivy prints request URLs in its errors. Authorization header
# values, bearer tokens, JWTs and ``token=`` / ``token: ``-style pairs are redacted wherever they appear, including
# JSON-quoted keys. Best effort: other shapes are not recognised.
#
# Every pattern runs in linear time: a scheme starts only where a run of scheme characters starts (or right at a bare
# ``://``) and is taken whole (possessive), a URL's host and path stop at the next ``://``, where the next attempt
# picks up, and JWTs are found per run of base64url characters, so no attempt rescans text an earlier one already
# read. Every pattern stays on one line, except that a credential marker ending a line (``token:``, ``Authorization:``,
# ``Bearer``) also redacts the next line's first word when that is token-shaped, so a Trivy bullet such as ``* GET``
# stays.
_SCHEME = r"(?<![a-z0-9+.-])[a-z0-9+.-]*+://"
_URL_QUERY = re.compile(rf"({_SCHEME}(?:(?!://)[^\s\"'?#])*+)\?(?:[^\s\"']*[^\s\"':])?", re.IGNORECASE)
_URL_USERINFO = re.compile(rf"({_SCHEME})[^\s\"'/@]++@", re.IGNORECASE)
_B64_RUN = re.compile(r"[A-Za-z0-9_.-]{5,}+")  # a run that may hold a JWT: base64url segments and their dots
_JWT_START = re.compile(r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]")
_AUTH_SCHEMES = r"(?:Basic|Bearer|Digest|Negotiate|Token)"
# A scheme word alone at a line end is not the value: its token is on the next line, for _NEXT_LINE.
_AUTH_HEADER = re.compile(
    rf"\b(Authorization\"?[ \t]*:[ \t]*\"?)({_AUTH_SCHEMES}[ \t]+)?(?!{_AUTH_SCHEMES}[ \t]*+(?:\r?\n|$))[^\s,;\"']+",
    re.IGNORECASE,
)
_BEARER = re.compile(r"\b(Bearer[ \t]+)[^\s,;\"']+", re.IGNORECASE)
_CREDENTIAL_NAMES = r"(?:access_|refresh_|id_)?token|password|passwd|secret|api[-_]?key"
_SECRET_PAIR = re.compile(rf"\b({_CREDENTIAL_NAMES}|signature|sig)=[^\s,;&\"']+", re.IGNORECASE)
# Not after a path or host character, so a URL such as ``https://example.com/token: DENIED`` keeps its message.
_SECRET_COLON = re.compile(rf"(?<![\w/.-])({_CREDENTIAL_NAMES})(\"?[ \t]*:[ \t]*\"?)[^\s,;\"']+", re.IGNORECASE)
# A marker ending a line: ``token:``-style names or ``Authorization:``, or an auth scheme word, after an optional
# ``Authorization:`` (``Bearer``, ``Authorization: Basic``).
_LINE_END_MARKER = (
    rf"(?:(?<![\w/.-])(?:Authorization|{_CREDENTIAL_NAMES})\"?[ \t]*+:[ \t]*+\"?"
    rf"|(?:\bAuthorization\"?[ \t]*+:[ \t]*+\"?[ \t]*+)?\b{_AUTH_SCHEMES})"
)
_NEXT_LINE = re.compile(
    rf"({_LINE_END_MARKER}[ \t]*+\r?\n[ \t]*+\"?)[A-Za-z0-9._~+/=-]{{16,}}+",
    re.IGNORECASE,
)
_ENDS_IN_MARKER = re.compile(rf"(?::|\b{_AUTH_SCHEMES})\Z", re.IGNORECASE)  # read on a line's last few characters
_ERROR_LIST = re.compile(r"\d+ errors? occurred:$")
_MAX_REDACT_CHARS = 16 * 1024  # only the end of a longer text is redacted and shown: the cause is there


def _tail(text: str) -> str:
    """The last :data:`_MAX_REDACT_CHARS` characters of ``text``, without the line the cut falls in.

    A cut inside a line could keep a secret but drop the ``sig=`` or ``token:`` before it that marks it for
    redaction, so that partial line goes. Only :data:`_NEXT_LINE` reaches past a line, from a marker ending in ``:``
    or an auth scheme word, so when the partial line ends that way the line after it goes too.
    """
    if len(text) <= _MAX_REDACT_CHARS:
        return text
    partial, newline, rest = text[-_MAX_REDACT_CHARS:].partition("\n")
    if newline and _ENDS_IN_MARKER.search(partial.rstrip(' \t\r"')[-16:]):
        _, newline, rest = rest.partition("\n")
    return "\u2026\n" + rest if newline else "\u2026"


def _redact_jwts(run: re.Match[str]) -> str:
    """A run of base64url characters with each ``eyJ...``-headed JWT in it (three dot-separated segments) redacted.

    The run is split on its dots once, so finding a JWT never rescans it; a JWT may follow ``-`` or ``_``.
    """
    parts = run[0].split(".")
    out: list[str] = []
    i = 0
    while i < len(parts):
        start = _JWT_START.search(parts[i]) if i + 2 < len(parts) and parts[i + 1] else None
        if start is None:
            out.append(parts[i])
            i += 1
        else:  # this part from "eyJ" on, the next part and the one after it (which may be empty)
            out.append(parts[i][: start.start()] + "<redacted>")
            i += 3
    return ".".join(out)


def _redact(text: str) -> str:
    """``text`` with URL credentials, authorization values, JWTs and ``token=``/``token:``-style values redacted."""
    text = _URL_USERINFO.sub(r"\1<redacted>@", _URL_QUERY.sub(r"\1?<redacted>", text))
    text = _B64_RUN.sub(_redact_jwts, text)
    text = _NEXT_LINE.sub(r"\1<redacted>", text)  # before the header passes, which would take the scheme word
    text = _AUTH_HEADER.sub(lambda m: f"{m[1]}{m[2] or ''}<redacted>", text)
    text = _BEARER.sub(r"\1<redacted>", text)
    return _SECRET_COLON.sub(r"\1\2<redacted>", _SECRET_PAIR.sub(r"\1=<redacted>", text))


def _short(text: str) -> str:
    """Trim ``text`` to its last :data:`_MAX_ERROR_CHARS` characters, with URL credentials redacted."""
    return _redact(_tail(text.strip()))[-_MAX_ERROR_CHARS:]


def error_text(text: str | None) -> str:
    """A stored error as a page shows it in full: its lines kept, redacted again (a row may predate a redaction rule),
    tabs as spaces and other unprintable characters replaced, at most :data:`_MAX_ERROR_CHARS` characters from the end.
    """
    shown = _redact(_tail((text or "").strip()))
    shown = shown.replace("\t", " ")  # Trivy separates its log fields with tabs
    return "".join(ch if ch.isprintable() or ch == "\n" else "?" for ch in shown)[-_MAX_ERROR_CHARS:]


def error_cause(text: str | None, limit: int = 300) -> str:
    """The cause of a failed Trivy run, as one printable line of at most ``limit`` characters.

    Trivy's ``FATAL`` line is a long chain of generic wrappers ("run error: image scan error: ..."), and the cause
    is on the ``* `` lines of the "N errors occurred:" list below it. Without those, the ``FATAL`` message, or
    else the whole text, is used. A cut keeps the end, where the cause is; only the last
    :data:`_MAX_REDACT_CHARS` characters are read. Credentials are redacted as in :func:`_redact`.
    """
    lines = [line.strip() for line in _redact(_tail(text or "")).splitlines() if line.strip()]
    causes: list[str] = []
    in_list = False  # only the "* " lines of Trivy's "N errors occurred:" list are causes
    for line in lines:
        if in_list and line.startswith("* "):
            causes.append(line[2:])
        else:
            in_list = bool(_ERROR_LIST.search(line))
    if causes:
        flat = "; ".join(causes)
    else:
        flat = " ".join([line.split("\t")[-1] for line in lines if "\tFATAL\t" in line] or lines)
    flat = " ".join(flat.split())
    flat = "".join(ch if ch.isprintable() else "?" for ch in flat)
    return flat if len(flat) <= limit else "\u2026" + flat[-(limit - 1) :]


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
    pkg_types: tuple[str, ...] = ("library", "os"),
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
        "--pkg-types",
        ",".join(pkg_types),
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
        report = json.loads(stdout)
        findings, os_family = parse_report(report)
    except json.JSONDecodeError as exc:
        return error("trivy", f"trivy printed invalid JSON: {exc}")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return error("trivy", f"unexpected trivy report shape: {type(exc).__name__}: {exc}")
    scanned = (report.get("Metadata") or {}).get("ImageID")
    return ImageResult(
        image=item_ref,
        platform=platform,
        status="ok",
        findings=findings,
        os_family=os_family,
        scanned_image_id=scanned if isinstance(scanned, str) and is_digest(scanned) else None,
    )


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

    An image that fails with a passing network error (``_PASSING_ERRORS``) is scanned once more after
    ``_RETRY_DELAY_S``, unless ``cancel`` is set by then; when that fails too, its error starts with ``RETRIED_PREFIX``.
    Once ``cancel`` is set no new image starts; scans already running finish and are reported. An exception from
    ``on_result`` (or an interrupt) kills the running scans and propagates.
    """
    if not items:
        return
    workers = settings.parallelism
    groups = _ClientGroups()

    def attempt(item: InventoryItem) -> ImageResult:
        try:
            return scan_image(
                trivy,
                item.image,
                item.platform,
                settings.scan_timeout_s,
                cache_dir=cache_dir,
                pkg_types=settings.pkg_types,
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

    def work(item: InventoryItem) -> ImageResult:
        started = time.monotonic()
        result = attempts(item)
        return result.model_copy(update={"duration_s": round(time.monotonic() - started, 1)})

    def attempts(item: InventoryItem) -> ImageResult:
        result = attempt(item)
        # The wait holds this worker's slot, so a burst of 503s briefly narrows the scan; one retry keeps that short.
        if not _passing(result) or cancel.wait(_RETRY_DELAY_S):
            return result
        again = attempt(item)
        if again.status != "error":
            return again
        kept = (again.error or "")[-(_MAX_ERROR_CHARS - len(RETRIED_PREFIX)) :]  # the prefix stays within the cap
        return again.model_copy(update={"error": RETRIED_PREFIX + kept})

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
