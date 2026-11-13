import pathlib
import tomllib

from typer.testing import CliRunner

from kubedelos.cli import app, delos_main


def test_version_prints_package_version():
    r = CliRunner().invoke(app, ["version"])
    assert r.exit_code == 0
    assert r.stdout.strip().startswith("kubedelos ")


def test_both_console_scripts_declared():
    scripts = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["scripts"]
    assert scripts == {"kubedelos": "kubedelos.cli:app", "delos": "kubedelos.cli:delos_main"}


def test_delos_main_announces_ui_and_returns(capsys):
    assert delos_main() is None
    assert "UI coming in Phase 2" in capsys.readouterr().out
