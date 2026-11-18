"""The `kubedelos` command line, a Typer app.

Scanning lives in the web UI (`kubedelos ui`) and the in-cluster schedule (`kubedelos serve`), not here: CI gating is
left to plain Trivy. The CLI serves the UI and keeps two helpers, `trivy install` and `registry test`.
"""

import contextlib
import logging
import os
import re
import secrets
import signal
import sys
import threading
import webbrowser
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer
from pydantic import ValidationError

from kubedelos import __version__
from kubedelos.config import Settings
from kubedelos.hints import login_hint
from kubedelos.kube import client as kube_client
from kubedelos.kube.inventory import parse_image_id
from kubedelos.models import InventoryItem, is_valid_ref, registry_host
from kubedelos.registry import dockerconfig
from kubedelos.registry.access import RegistryAccess
from kubedelos.scheduler import Sweeper, cron_error
from kubedelos.store import queue, runlock
from kubedelos.store.db import connect
from kubedelos.trivy.binary import TrivyVerificationError, ensure_trivy
from kubedelos.trivy.cache import TrivyCache
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.trivy.runner import error_cause, scan_image
from kubedelos.web import server
from kubedelos.web.app import create_app, create_serve_app
from kubedelos.web.jobs import ScanRunner
from kubedelos.web.pages import plural
from kubedelos.web.worker import QueueWorker

app = typer.Typer(
    help="Scan the container images running in a Kubernetes cluster with Trivy, from a local web UI.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Keep `app` a command group, so `version` stays a subcommand."""


@app.command()
def version() -> None:
    """Print the kubedelos version."""
    typer.echo(f"kubedelos {__version__}")


trivy_app = typer.Typer(help="Manage the pinned Trivy binary.", no_args_is_help=True)
app.add_typer(trivy_app, name="trivy")
registry_app = typer.Typer(help="Check access to container registries.", no_args_is_help=True)
app.add_typer(registry_app, name="registry")


def _load_settings(**flags: Any) -> Settings:
    """Settings from the flags that were passed (``None`` means not passed) and ``KUBEDELOS_*`` variables.

    A bad value exits 2 with one line per problem, naming the flag or the variable it came from.
    """
    passed = {k: v for k, v in flags.items() if v is not None}
    try:
        return Settings(**passed)
    except ValidationError as exc:
        for problem in exc.errors():
            field = str(problem["loc"][0]) if problem["loc"] else ""
            if field in passed:
                source = "--" + field.replace("_", "-")
            else:
                source = f"KUBEDELOS_{field.upper()}" if field else "settings"
            typer.echo(f"error: {source}: {problem['msg']}", err=True)
        raise typer.Exit(2) from exc


@trivy_app.command("install")
def trivy_install() -> None:
    """Download and verify the pinned Trivy release, unless it is already installed."""
    settings = _load_settings()
    try:
        path = ensure_trivy(settings)
    except (TrivyVerificationError, RuntimeError, OSError, httpx.HTTPError) as exc:
        typer.echo(f"error: {_flat(exc)}", err=True)
        raise typer.Exit(1) from exc
    if settings.trivy_path is not None:
        typer.echo(f"Using Trivy at {path} (from KUBEDELOS_TRIVY_PATH; kubedelos pins {TRIVY_VERSION})")
    else:
        typer.echo(f"Trivy {TRIVY_VERSION} installed at {path}")


_ERROR_LINE_CHARS = 200


def _flat(exc: BaseException) -> str:
    """``exc`` as one printable line; some messages carry a multi-line Trivy or validation report."""
    return "".join(ch if ch.isprintable() else "?" for ch in " ".join(str(exc).split()))


@contextlib.contextmanager
def _signals_as_interrupt() -> Iterator[None]:
    """Turn SIGTERM and SIGHUP into ``KeyboardInterrupt`` so they stop Trivy like Ctrl-C does.

    Trivy runs in its own process groups, so without this a ``timeout``, a ``kill`` or a closed terminal would end
    Python without unwinding and leave Trivy scans running. Signal handlers can only be set on the
    main thread; elsewhere this does nothing.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def interrupt(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGTERM, getattr(signal, "SIGHUP", None)) if sig}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


_PLATFORM_RE = re.compile(r"[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?")  # os/arch[/variant], as Trivy's --platform takes it


def _one_line(text: str | None, limit: int = _ERROR_LINE_CHARS) -> str:
    """First line of ``text``, cut to ``limit`` characters, with control characters replaced."""
    first = (text or "").strip().splitlines()[:1]
    return "".join(ch if ch.isprintable() else "?" for ch in (first[0] if first else ""))[:limit]


@registry_app.command("test")
def registry_test(
    image: Annotated[str, typer.Argument(help="Image to check, e.g. registry.example/team/app:1")],
    platform: Annotated[str, typer.Option(help="Platform to resolve, as os/arch[/variant].")] = "linux/amd64",
    trivy_path: Annotated[Path | None, typer.Option(help="Use this Trivy binary instead of the pinned one.")] = None,
) -> None:
    """Check that kubedelos can read IMAGE with your current registry login, by scanning it once."""
    ref = parse_image_id(image, "")
    # parse_image_id falls back to :latest when a digest is malformed; for a user's ref that would scan another image.
    if not is_valid_ref(ref.ref) or ("@" in image and ref.digest is None):
        typer.echo(f"error: invalid image reference: {_one_line(image, 512)}", err=True)
        raise typer.Exit(2)
    if not _PLATFORM_RE.fullmatch(platform):
        typer.echo(
            f"error: invalid platform {_one_line(platform, 64)!r}: use os/arch[/variant], e.g. linux/amd64", err=True
        )
        raise typer.Exit(2)
    host = registry_host(ref)
    settings = _load_settings(trivy_path=trivy_path)
    try:
        with _signals_as_interrupt():
            trivy = ensure_trivy(settings)
            # Only access is checked, so scan the smallest level and skip the Java DB.
            with (
                TrivyCache(trivy, settings.cache_dir, java_db=False) as cache,
                RegistryAccess(settings).for_item(InventoryItem(image=ref, platform=platform)) as access,
            ):
                result = scan_image(
                    trivy,
                    ref,
                    platform,
                    settings.scan_timeout_s,
                    cache_dir=cache.dir,
                    pkg_types=("os",),
                    docker_config=access.docker_config,
                )
    except KeyboardInterrupt:
        typer.echo("cancelled", err=True)
        raise typer.Exit(130) from None
    except Exception as exc:
        typer.echo(f"error: {_flat(exc)}", err=True)
        raise typer.Exit(2) from exc

    if result.status == "ok":
        typer.echo(f"ok: {ref.ref} is readable ({len(result.findings)} findings)")
        return
    detail = error_cause(result.error)
    if result.error_kind == "auth":
        typer.echo(f"error: {ref.ref}: authentication failed on {host}: {detail}", err=True)
        typer.echo("hint: " + login_hint(host), err=True)
        raise typer.Exit(1)
    if result.error_kind == "not_found":
        typer.echo(f"error: {ref.ref}: not found on {host}: {detail}", err=True)
        raise typer.Exit(1)
    typer.echo(f"error: {ref.ref}: {result.error_kind}: {detail}", err=True)
    raise typer.Exit(2)


def _log_access() -> None:
    """With KUBEDELOS_LOG_LEVEL=info, print one access line per request on stderr."""
    if os.environ.get("KUBEDELOS_LOG_LEVEL", "").lower() == "info":
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        web_log = logging.getLogger("kubedelos.web")
        web_log.addHandler(handler)
        web_log.setLevel(logging.INFO)


@app.command()
def ui(
    port: Annotated[int, typer.Option(min=1, max=65535, help="Port to listen on.")] = 9370,
    host: Annotated[
        str, typer.Option(help="Loopback address to listen on: 127.0.0.1, ::1 or localhost.")
    ] = "127.0.0.1",
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Do not open the browser.")] = False,
    context: Annotated[str | None, typer.Option(help="Kubeconfig context to show.")] = None,
    kubeconfig: Annotated[Path | None, typer.Option(help="Path to the kubeconfig file.")] = None,
) -> None:
    """Serve the local web UI for the current kube-context, on loopback only.

    The address carries a startup token, valid until the server stops; the first visit swaps it for a session cookie.
    Set KUBEDELOS_LOG_LEVEL=info to print an access line per request on stderr.
    """
    if host not in server.LOOPBACK:
        typer.echo("error: --host must be 127.0.0.1, ::1 or localhost", err=True)
        raise typer.Exit(2)
    settings = _load_settings(context=context, kubeconfig=kubeconfig)
    try:
        name = _one_line(kube_client.load(settings).current_context())
        conn = connect(settings.db_path)  # creates the database and runs the migrations
        try:
            # A run left "running" by a killed scan stays that way for ever; close the ones no live process owns.
            stale = runlock.close_stale_runs(conn, settings.data_dir)
        finally:
            conn.close()
    except Exception as exc:
        typer.echo(f"error: {_flat(exc)}", err=True)
        raise typer.Exit(2) from exc
    if settings.secrets_dir is not None:
        dockerconfig.clear(settings.secrets_dir)  # configs a crashed scan left behind
    if stale:
        typer.echo(f"note: closed {len(stale)} interrupted {plural(len(stale), 'run')}")
    token = secrets.token_urlsafe(32)
    try:
        sock = server.bind(host, port)
    except server.PortInUse as exc:
        typer.echo(f"error: port {port} is in use; pass --port", err=True)
        raise typer.Exit(2) from exc
    except OSError as exc:
        typer.echo(f"error: {_flat(exc)}", err=True)
        raise typer.Exit(2) from exc
    _log_access()
    address = server.url(host, port, token)
    typer.echo(f"kubedelos ui for context {name}: {address}")
    typer.echo("Press Ctrl-C to stop.")
    if not no_browser:
        webbrowser.open(address)
    flags = frozenset(k for k, v in {"context": context, "kubeconfig": kubeconfig}.items() if v is not None)
    server.serve(create_app(settings, context=name, token=token, port=port, flags=flags), sock)


@app.command()
def serve(
    port: Annotated[int, typer.Option(min=1, max=65535, help="Port to listen on.")] = 8080,
    host: Annotated[str, typer.Option(help="Address to listen on.")] = "0.0.0.0",  # noqa: S104 - in-cluster default
    kubeconfig: Annotated[Path | None, typer.Option(help="Path to the kubeconfig file.")] = None,
) -> None:
    """Serve the UI of one cluster and sweep it on a schedule (the in-cluster mode).

    The cluster is named by KUBEDELOS_CLUSTER_NAME. Anyone who can reach the port can read every finding, so expose it
    only through an authenticating proxy or keep it cluster-internal. Writes are open unless KUBEDELOS_READ_ONLY=true.
    Set KUBEDELOS_LOG_LEVEL=info to print an access line per request on stderr.
    """
    settings = _load_settings(kubeconfig=kubeconfig)
    if not settings.cluster_name:
        typer.echo("error: KUBEDELOS_CLUSTER_NAME is required for kubedelos serve", err=True)
        raise typer.Exit(2)
    if problem := cron_error(settings.sweep_schedule, settings.sweep_timezone):
        typer.echo(f"error: {problem}", err=True)
        raise typer.Exit(2)
    try:
        with runlock.hold_serve(settings.data_dir):
            _serve(settings, host, port)
    except runlock.AlreadyServing as exc:
        typer.echo(f"error: {_flat(exc)}", err=True)
        raise typer.Exit(2) from exc


def _serve(settings: Settings, host: str, port: int) -> None:
    """Start the queue worker and the sweeper, and serve until stopped; the caller holds the serve lock."""
    name = settings.cluster_name or ""
    try:
        kube_client.load(settings)  # a bad kubeconfig fails here, not at the first sweep
        conn = connect(settings.db_path)  # creates the database and runs the migrations
        try:
            stale = runlock.close_stale_runs(conn, settings.data_dir)
            queue.abandon_started(conn)
        finally:
            conn.close()
    except Exception as exc:
        typer.echo(f"error: {_flat(exc)}", err=True)
        raise typer.Exit(2) from exc
    if settings.secrets_dir is not None:
        dockerconfig.clear(settings.secrets_dir)  # configs a crashed scan left behind
    if stale:
        typer.echo(f"note: closed {len(stale)} interrupted {plural(len(stale), 'run')}")
    try:
        sock = server.bind(host, port, public=True)
    except server.PortInUse as exc:
        typer.echo(f"error: port {port} is in use; pass --port", err=True)
        raise typer.Exit(2) from exc
    except OSError as exc:
        typer.echo(f"error: {_flat(exc)}", err=True)
        raise typer.Exit(2) from exc
    _log_access()
    clock = lambda: datetime.now(UTC)  # noqa: E731
    runner = ScanRunner(settings, name, fixed_cluster=True)
    worker = QueueWorker(settings, runner, clock=clock)
    sweeper = Sweeper(settings, worker.enqueue_sweep)
    web_app = create_serve_app(settings, runner=runner, worker=worker, sweeper=sweeper, clock=clock)
    shown = f"[{host}]" if ":" in host else host
    typer.echo(f"kubedelos serve for cluster {_one_line(name)} on http://{shown}:{port}")
    # Start the threads last, so a failure building the app leaves nothing running that could start a scan.
    worker.start()
    sweeper.start()
    next_sweep = sweeper.next_run()
    typer.echo(f"next sweep: {next_sweep.isoformat()}" if next_sweep else "sweeps are off")
    typer.echo("Press Ctrl-C to stop.")
    server.serve(web_app, sock)
