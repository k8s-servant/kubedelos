"""Command line entrypoints: `kubedelos` (the Typer app) and `delos` (the UI launcher)."""

import sys
import threading
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, TextColumn
from rich.progress import Progress as RichProgress

from kubedelos import __version__
from kubedelos.config import Settings
from kubedelos.models import Severity
from kubedelos.output import RENDERERS
from kubedelos.scan.service import Progress, run_scan
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo
from kubedelos.trivy.binary import TrivyVerificationError, ensure_trivy
from kubedelos.trivy.pins import TRIVY_VERSION

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


@trivy_app.command("install")
def trivy_install() -> None:
    """Download and verify the pinned Trivy release, unless it is already installed."""
    settings = Settings()
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


@app.command()
def scan(
    context: Annotated[str | None, typer.Option(help="Kubeconfig context to scan.")] = None,
    kubeconfig: Annotated[Path | None, typer.Option(help="Path to the kubeconfig file.")] = None,
    namespace: Annotated[
        list[str] | None, typer.Option("--namespace", "-n", help="Namespace to scan (repeatable).")
    ] = None,
    exclude_namespace: Annotated[list[str] | None, typer.Option(help="Namespace to skip (repeatable).")] = None,
    output: Annotated[OutputFormat, typer.Option("--output", "-o", help="Output format.")] = OutputFormat.table,
    severity: Annotated[str, typer.Option(help="Comma-separated severities to output.")] = "CRITICAL,HIGH",
    fail_on: Annotated[FailOn, typer.Option(help="Exit 1 when a finding is at or above this severity.")] = FailOn.none,
    parallelism: Annotated[int | None, typer.Option(min=1, max=32, help="Images scanned at once.")] = None,
    trivy_path: Annotated[Path | None, typer.Option(help="Use this Trivy binary instead of the pinned one.")] = None,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Ignore cached scan results.")] = False,
    output_file: Annotated[Path | None, typer.Option(help="Write results here instead of stdout.")] = None,
) -> None:
    """Scan the images running in the current kube-context.

    Exit codes: 0 ok, 1 findings at or above --fail-on, 2 error (image failures with --fail-on, or fatal), 130 cancelled.
    """
    wanted = _parse_severities(severity)
    passed: dict[str, Any] = {
        "context": context,
        "kubeconfig": kubeconfig,
        "namespaces": namespace,
        "exclude_namespaces": exclude_namespace,
        "parallelism": parallelism,
        "trivy_path": trivy_path,
    }
    err = Console(stderr=True)
    cancel = threading.Event()
    try:
        settings = Settings(**{k: v for k, v in passed.items() if v is not None})
        repo = Repo(connect(settings.db_path))
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

            kwargs: dict[str, Any] = {"on_progress": on_progress, "cancel": cancel}
            if no_cache:
                kwargs["cache_max_age"] = timedelta(0)
            outcome = run_scan(settings, repo=repo, **kwargs)
        run = repo.get_run(outcome.run_id)
        if run is None or run["status"] == "failed":
            raise RuntimeError("scan run failed")
        findings = repo.run_findings(outcome.run_id)
    except KeyboardInterrupt:
        cancel.set()
        typer.echo("cancelled", err=True)
        raise typer.Exit(130) from None
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    for text in outcome.warnings:
        typer.echo(f"warning: {text}", err=True)
    if run["status"] == "cancelled":
        typer.echo("cancelled", err=True)
        raise typer.Exit(130)

    rendered = RENDERERS[output.value]([r for r in findings if r["severity"] in wanted])
    if output_file is not None:
        output_file.write_text(rendered)
    else:
        typer.echo(rendered, nl=not rendered.endswith("\n"))

    errors = run["images_error"] or 0
    if errors:
        typer.echo(f"{errors} image(s) failed to scan", err=True)
    if fail_on is FailOn.none:
        return
    if errors:
        raise typer.Exit(2)
    threshold = Severity(fail_on.value.upper()).rank
    if any(Severity(r["severity"]).rank >= threshold for r in findings):
        raise typer.Exit(1)


def delos_main() -> None:
    """Entrypoint of the `delos` command."""
    typer.echo("UI coming in Phase 2")
