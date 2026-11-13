"""Command line entrypoints: `kubedelos` (the Typer app) and `delos` (the UI launcher)."""

import typer

from kubedelos import __version__

app = typer.Typer(help="Scan the container images running in a Kubernetes cluster with Trivy.", no_args_is_help=True)


@app.callback()
def main() -> None:
    """Keep `app` a command group so more subcommands can be added next to `version`."""


@app.command()
def version() -> None:
    """Print the kubedelos version."""
    typer.echo(f"kubedelos {__version__}")


def delos_main() -> None:
    """Entrypoint of the `delos` command."""
    typer.echo("UI coming in Phase 2")
