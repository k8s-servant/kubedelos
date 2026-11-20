import importlib
import subprocess
import sys

from kubedelos import cli


def test_importing_main_does_not_run_the_cli(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "app", lambda *args, **kwargs: calls.append(args))
    sys.modules.pop("kubedelos.__main__", None)
    importlib.import_module("kubedelos.__main__")
    assert calls == []


def test_python_dash_m_runs_the_cli():
    proc = subprocess.run([sys.executable, "-P", "-m", "kubedelos", "version"], capture_output=True, text=True)
    assert proc.returncode == 0 and proc.stdout.strip()
