import pathlib
import tomllib

from typer.testing import CliRunner

from kubedelos.cli import app


def test_version_prints_package_version():
    r = CliRunner().invoke(app, ["version"])
    assert r.exit_code == 0
    assert r.stdout.strip().startswith("kubedelos ")


def test_kubedelos_is_the_only_console_script():
    scripts = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["scripts"]
    assert scripts == {"kubedelos": "kubedelos.cli:app"}
