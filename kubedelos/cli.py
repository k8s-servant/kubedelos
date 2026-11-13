"""The `kubedelos` command line, a Typer app."""

import contextlib
import signal
import sys
import threading
from collections.abc import Iterator
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer
from pydantic import ValidationError
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, TextColumn
from rich.progress import Progress as RichProgress

from kubedelos import __version__
from kubedelos.config import Settings
from kubedelos.kube import client as kube_client
from kubedelos.kube.inventory import parse_image_id
from kubedelos.models import Severity, is_valid_ref, registry_host
from kubedelos.output import RENDERERS
from kubedelos.scan.service import Progress, run_scan
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo
from kubedelos.trivy.binary import TrivyVerificationError, ensure_trivy
from kubedelos.trivy.cache import TrivyCache
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.trivy.runner import scan_image

app = typer.Typer(help="Scan the container images running in a Kubernetes cluster with Trivy.", no_args_is_help=True)


@app.callback()
def main() -> None:
    """Keep `app` a command group so more subcommands can be added next to `version`."""


@app.command()
def version() -> None:
    """Print the kubedelos version."""
    typer.echo(f"kubedelos {__version__}")


trivy_app = typer.Typer(help="Manage the pinned Trivy binary.", no_args_is_help=True)
app.add_typer(trivy_app, name="trivy")
registry_app = typer.Typer(help="Check access to container registries.", no_args_is_help=True)
app.add_typer(registry_app, name="registry")


def _login_hint(host: str) -> str:
    """How to log in to ``host`` so that Docker, and with it kubedelos, can read it."""
    name = host.split(":", 1)[0]
    if name.endswith(".azurecr.io"):
        command = f"az acr login --name {name.split('.', 1)[0]}"
    elif name == "gcr.io" or name.endswith((".gcr.io", "-docker.pkg.dev")):
        command = f"gcloud auth configure-docker {host}"
    elif ".dkr.ecr." in name and name.endswith(".amazonaws.com"):
        region = name.split(".dkr.ecr.", 1)[1].removesuffix(".amazonaws.com")
        command = f"aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {host}"
    else:
        command = f"docker login {host}"
    return f"log in to {host} first, e.g. `{command}`; kubedelos uses the same Docker credentials"


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
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    if settings.trivy_path is not None:
        typer.echo(f"Using Trivy at {path} (from KUBEDELOS_TRIVY_PATH; kubedelos pins {TRIVY_VERSION})")
    else:
        typer.echo(f"Trivy {TRIVY_VERSION} installed at {path}")


class OutputFormat(StrEnum):
    table = "table"
    json = "json"
    csv = "csv"
    sarif = "sarif"


class FailOn(StrEnum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def _parse_severities(value: str) -> set[str]:
    names = {part.strip().upper() for part in value.split(",") if part.strip()}
    valid = {s.value for s in Severity}
    unknown = sorted(names - valid)
    if unknown or not names:
        raise typer.BadParameter(f"unknown severity {', '.join(unknown) or value!r}; use {', '.join(sorted(valid))}")
    return names


_ERROR_LINE_CHARS = 200


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


@app.command()
def scan(
    context: Annotated[str | None, typer.Option(help="Kubeconfig context to scan.")] = None,
    kubeconfig: Annotated[Path | None, typer.Option(help="Path to the kubeconfig file.")] = None,
    namespace: Annotated[
        list[str] | None, typer.Option("--namespace", "-n", help="Namespace to scan (repeatable).")
    ] = None,
    exclude_namespace: Annotated[list[str] | None, typer.Option(help="Namespace to skip (repeatable).")] = None,
    output: Annotated[OutputFormat, typer.Option("--output", "-o", help="Output format.")] = OutputFormat.table,
    severity: Annotated[
        str, typer.Option(help="Comma-separated severities to output. Does not limit what --fail-on checks.")
    ] = "CRITICAL,HIGH",
    fail_on: Annotated[
        FailOn,
        typer.Option(
            help="Exit 1 when any finding is at or above this severity, including findings hidden by --severity."
        ),
    ] = FailOn.none,
    parallelism: Annotated[int | None, typer.Option(min=1, max=32, help="Images scanned at once.")] = None,
    pkg_types: Annotated[
        str | None,
        typer.Option(help="Package types to scan: os, library or both, comma-separated. Default: os,library."),
    ] = None,
    trivy_path: Annotated[Path | None, typer.Option(help="Use this Trivy binary instead of the pinned one.")] = None,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Ignore cached scan results.")] = False,
    allow_partial: Annotated[
        bool,
        typer.Option(
            "--allow-partial",
            help="With --fail-on, do not exit 2 when skipped namespaces or resources mean coverage was incomplete. "
            "Warnings that lose only detail (owner info, node platform) never cause exit 2.",
        ),
    ] = False,
    output_file: Annotated[Path | None, typer.Option(help="Write results here instead of stdout.")] = None,
) -> None:
    """Scan the images running in the current kube-context.

    Exit codes: 0 ok, 1 findings at or above --fail-on, 2 error (fatal, or with --fail-on: image failures or
    skipped namespaces/resources unless --allow-partial), 130 cancelled (Ctrl-C, SIGTERM or SIGHUP).
    """
    wanted = _parse_severities(severity)
    passed: dict[str, Any] = {
        "context": context,
        "kubeconfig": kubeconfig,
        "namespaces": namespace,
        "exclude_namespaces": exclude_namespace,
        "parallelism": parallelism,
        "pkg_types": pkg_types,
        "trivy_path": trivy_path,
    }
    settings = _load_settings(**passed)
    err = Console(stderr=True)
    cancel = threading.Event()
    try:
        with _signals_as_interrupt():
            api = kube_client.load(settings)
            typer.echo(f"scanning context {_one_line(api.current_context())}", err=True)
            with contextlib.closing(connect(settings.db_path)) as conn:
                repo = Repo(conn)
                with RichProgress(
                    TextColumn("{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    console=err,
                    disable=not sys.stderr.isatty(),
                ) as bar:
                    task = bar.add_task("scanning", total=None)

                    def on_progress(p: Progress) -> None:
                        bar.update(task, total=p.total, completed=p.done, description=f"scanning ({p.errors} errors)")

                    kwargs: dict[str, Any] = {"api": api, "on_progress": on_progress, "cancel": cancel}
                    if no_cache:
                        kwargs["cache_max_age"] = timedelta(0)
                    outcome = run_scan(settings, repo=repo, **kwargs)
                run = repo.get_run(outcome.run_id)
                if run is None or run["status"] == "failed":
                    raise RuntimeError("scan run failed")
                findings = repo.run_findings(outcome.run_id)
                failed = repo.run_errors(outcome.run_id)
    except KeyboardInterrupt:
        typer.echo("cancelled", err=True)
        raise typer.Exit(130) from None
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    for warning in outcome.warnings:
        typer.echo(f"warning: {_one_line(warning.text, 512)}", err=True)
    if run["status"] == "cancelled":
        typer.echo("cancelled", err=True)
        raise typer.Exit(130)

    rendered = RENDERERS[output.value]([r for r in findings if r["severity"] in wanted])
    if output_file is not None:
        try:
            output_file.write_text(rendered)
        except OSError as exc:
            typer.echo(f"error: cannot write {output_file}: {exc.strerror or exc}", err=True)
            raise typer.Exit(2) from exc
    else:
        typer.echo(rendered, nl=not rendered.endswith("\n"))

    for row in failed:
        typer.echo(
            f"error: {_one_line(row['ref'], 512)} [{row['platform']}] {row['error_kind']}: {_one_line(row['error'])}",
            err=True,
        )
    for host in sorted(
        {registry_host(parse_image_id(row["ref"], "")) for row in failed if row["error_kind"] == "auth"}
    ):
        typer.echo("hint: " + _login_hint(host), err=True)
    errors = run["images_error"] or 0
    if errors:
        typer.echo(f"{errors} image(s) failed to scan", err=True)
    if fail_on is FailOn.none:
        return
    gaps = [w for w in outcome.warnings if w.coverage]
    if gaps and not allow_partial:
        typer.echo(
            f"error: inventory incomplete ({len(gaps)} namespaces/resources skipped); pass --allow-partial to accept",
            err=True,
        )
    if errors or (gaps and not allow_partial):
        raise typer.Exit(2)  # fail closed: image errors or incomplete inventory must not pass as clean
    threshold = Severity(fail_on.value.upper()).rank
    hits = [r for r in findings if Severity(r["severity"]).rank >= threshold]
    if hits:
        hidden = sum(r["severity"] not in wanted for r in hits)
        if hidden:
            typer.echo(f"{hidden} finding(s) at or above --fail-on are hidden by --severity", err=True)
        raise typer.Exit(1)


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
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    if result.status == "ok":
        typer.echo(f"ok: {ref.ref} is readable ({len(result.findings)} findings)")
        return
    detail = _one_line(result.error)
    if result.error_kind == "auth":
        typer.echo(f"error: {ref.ref}: authentication failed on {host}: {detail}", err=True)
        typer.echo("hint: " + _login_hint(host), err=True)
        raise typer.Exit(1)
    if result.error_kind == "not_found":
        typer.echo(f"error: {ref.ref}: not found on {host}: {detail}", err=True)
        raise typer.Exit(1)
    typer.echo(f"error: {ref.ref}: {result.error_kind}: {detail}", err=True)
    raise typer.Exit(2)
