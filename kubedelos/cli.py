"""Command line entrypoints: `kubedelos` (the Typer app) and `delos` (the UI launcher)."""

import httpx
import typer

from kubedelos import __version__
from kubedelos.config import Settings
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


def delos_main() -> None:
    """Entrypoint of the `delos` command."""
    typer.echo("UI coming in Phase 2")
