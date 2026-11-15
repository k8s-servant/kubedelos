"""The `kubedelos` command line, a Typer app.

Scanning lives in the web UI (`kubedelos ui`), and later in the in-cluster schedule, not here: CI gating is left to
plain Trivy. The CLI serves the UI and keeps two helpers, `trivy install` and `registry test`.
"""

import contextlib
import logging
import os
import secrets
import signal
import sys
import threading
import webbrowser
from collections.abc import Iterator
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
from kubedelos.models import is_valid_ref, registry_host
from kubedelos.store import runlock
from kubedelos.store.db import connect
from kubedelos.trivy.binary import TrivyVerificationError, ensure_trivy
from kubedelos.trivy.cache import TrivyCache
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.trivy.runner import error_cause, scan_image
from kubedelos.web import server
from kubedelos.web.app import create_app
from kubedelos.web.pages import plural

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

    Trivy runs in its own process groups, so without this a ``timeout``, a CI cancel or a closed terminal would end
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


def _one_line(text: str | None, limit: int = _ERROR_LINE_CHARS) -> str:
    """First line of ``text``, cut to ``limit`` characters, with control characters replaced."""
    first = (text or "").strip().splitlines()[:1]
    return "".join(ch if ch.isprintable() else "?" for ch in (first[0] if first else ""))[:limit]


@registry_app.command("test")
def registry_test(
    image: Annotated[str, typer.Argument(help="Image to check, e.g. registry.example/team/app:1")],
    platform: Annotated[str, typer.Option(help="Platform to resolve, as os/arch.")] = "linux/amd64",
    trivy_path: Annotated[Path | None, typer.Option(help="Use this Trivy binary instead of the pinned one.")] = None,
) -> None:
    """Check that kubedelos can read IMAGE with your current registry login, by scanning it once."""
    ref = parse_image_id(image, "")
    # parse_image_id falls back to :latest when a digest is malformed; for a user's ref that would scan another image.
    if not is_valid_ref(ref.ref) or ("@" in image and ref.digest is None):
        typer.echo(f"error: invalid image reference: {_one_line(image, 512)}", err=True)
        raise typer.Exit(2)
    host = registry_host(ref)
    settings = _load_settings(trivy_path=trivy_path)
    try:
        with _signals_as_interrupt():
            trivy = ensure_trivy(settings)
            # Only access is checked, so scan the smallest level and skip the Java DB.
            with TrivyCache(trivy, settings.cache_dir, java_db=False) as cache:
                result = scan_image(
                    trivy, ref, platform, settings.scan_timeout_s, cache_dir=cache.dir, pkg_types=("os",)
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
    if os.environ.get("KUBEDELOS_LOG_LEVEL", "").lower() == "info":
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        web_log = logging.getLogger("kubedelos.web")
        web_log.addHandler(handler)
        web_log.setLevel(logging.INFO)
    address = server.url(host, port, token)
    typer.echo(f"kubedelos ui for context {name}: {address}")
    typer.echo("Press Ctrl-C to stop.")
    if not no_browser:
        webbrowser.open(address)
    server.serve(create_app(settings, context=name, token=token, port=port), sock)
