import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import tomllib

import pytest
from typer.testing import CliRunner

from kubedelos.cli import app


def test_version_prints_package_version():
    r = CliRunner().invoke(app, ["version"])
    assert r.exit_code == 0
    assert r.stdout.strip().startswith("kubedelos ")


def test_kubedelos_is_the_only_console_script():
    scripts = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["scripts"]
    assert scripts == {"kubedelos": "kubedelos.cli:app"}


FAKE_TRIVY = pathlib.Path(__file__).parent / "trivy" / "fake_trivy.py"


@pytest.fixture
def fake_env(tmp_path, monkeypatch):
    monkeypatch.setenv("KUBEDELOS_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("KUBEDELOS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("FAKE_TRIVY_RECORD", str(tmp_path / "record.json"))
    monkeypatch.setenv("FAKE_TRIVY_DOWNLOAD_LOG", str(tmp_path / "downloads.jsonl"))
    return tmp_path


def _registry_test(*args: str):
    return CliRunner().invoke(app, ["registry", "test", "--trivy-path", str(FAKE_TRIVY), *args])


def test_registry_test_ok(fake_env):
    r = _registry_test("nginx:1.19")
    assert r.exit_code == 0, r.output
    assert r.stdout.startswith("ok: docker.io/library/nginx:1.19 is readable")


def test_registry_test_auth_failure_prints_hint(fake_env, monkeypatch):
    monkeypatch.setenv("FAKE_TRIVY_STDERR", "UNAUTHORIZED: authentication required")
    monkeypatch.setenv("FAKE_TRIVY_EXIT", "1")
    r = _registry_test("registry.example/team/app:1")
    assert r.exit_code == 1
    assert "authentication failed on registry.example" in r.stderr
    assert "hint: log in to registry.example first" in r.stderr


def test_registry_test_not_found(fake_env, monkeypatch):
    monkeypatch.setenv("FAKE_TRIVY_STDERR", "MANIFEST_UNKNOWN: manifest unknown")
    monkeypatch.setenv("FAKE_TRIVY_EXIT", "1")
    r = _registry_test("registry.example/team/app:1")
    assert r.exit_code == 1
    assert "not found on registry.example" in r.stderr


def test_registry_test_rejects_invalid_ref(fake_env):
    r = _registry_test("--", "-oyaml")
    assert r.exit_code == 2
    assert "invalid image reference" in r.stderr
    assert not (fake_env / "record.json").exists()
    assert not (fake_env / "downloads.jsonl").exists()


def _gone(pid: int) -> bool:
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def test_registry_test_cancel_exits_130(fake_env):
    pid_file = fake_env / "scan.pid"
    env = {**os.environ, "FAKE_TRIVY_SLEEP": "30", "FAKE_TRIVY_PID_FILE": str(pid_file)}
    proc = subprocess.Popen(
        [sys.executable, "-c", "from kubedelos.cli import app; app(prog_name='kubedelos')",
         "registry", "test", "--trivy-path", str(FAKE_TRIVY), "nginx:1.19"],
        env=env,
    )  # fmt: skip
    try:
        for _ in range(100):
            if pid_file.exists():
                break
            time.sleep(0.1)
        assert pid_file.exists(), "the fake Trivy scan never started"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == 130
    finally:
        proc.kill()
    assert _gone(int(pid_file.read_text()))


@pytest.mark.parametrize("image", ["nginx@sha256:dead", "nginx@sha512:" + "a" * 128, "nginx@"])
def test_registry_test_rejects_bad_digest_instead_of_scanning_latest(fake_env, image):
    r = _registry_test(image)
    assert r.exit_code == 2
    assert "invalid image reference" in r.stderr
    assert not (fake_env / "record.json").exists()


@pytest.mark.parametrize(
    ("image", "command"),
    [
        ("registry.example/team/app:1", "docker login registry.example"),
        ("nginx:1.19", "docker login docker.io"),
        ("myregistry.azurecr.io/app:1", "az acr login --name myregistry"),
        ("europe-docker.pkg.dev/proj/repo/app:1", "gcloud auth configure-docker europe-docker.pkg.dev"),
        ("gcr.io/proj/app:1", "gcloud auth configure-docker gcr.io"),
        ("123456789012.dkr.ecr.eu-west-1.amazonaws.com/app:1", "aws ecr get-login-password --region eu-west-1"),
    ],
)
def test_registry_test_hint_matches_the_registry(fake_env, monkeypatch, image, command):
    monkeypatch.setenv("FAKE_TRIVY_STDERR", "UNAUTHORIZED: authentication required")
    monkeypatch.setenv("FAKE_TRIVY_EXIT", "1")
    hint = [line for line in _registry_test(image).stderr.splitlines() if line.startswith("hint: ")]
    assert len(hint) == 1 and command in hint[0]
    if "docker login" in command:
        assert "gcloud" not in hint[0] and "az acr" not in hint[0]


def test_registry_test_scans_os_only(fake_env):
    r = _registry_test("nginx:1.19")
    assert r.exit_code == 0, r.output
    argv = json.loads((fake_env / "record.json").read_text())["FakeArgv"]
    assert argv[argv.index("--pkg-types") + 1] == "os"
    assert "--download-java-db-only" not in (fake_env / "downloads.jsonl").read_text()


def test_registry_test_bad_env_setting_exits_2_without_traceback(fake_env, monkeypatch):
    monkeypatch.setenv("KUBEDELOS_PKG_TYPES", "foo")
    r = _registry_test("nginx:1.19")
    assert r.exit_code == 2
    assert "error: KUBEDELOS_PKG_TYPES:" in r.stderr
    assert r.exception is None or isinstance(r.exception, SystemExit)


def test_trivy_install_bad_env_setting_exits_2(monkeypatch):
    monkeypatch.setenv("KUBEDELOS_PARALLELISM", "0")
    r = CliRunner().invoke(app, ["trivy", "install"])
    assert r.exit_code == 2
    assert "error: KUBEDELOS_PARALLELISM:" in r.stderr


def test_registry_test_shows_the_trivy_cause(fake_env, monkeypatch):
    monkeypatch.setenv(
        "FAKE_TRIVY_STDERR",
        "2026-11-14T08:37:11+02:00\tFATAL\tFatal error\trun error: image scan error: scan error: unable to initialize "
        'a scan service: unable to find the specified image "registry.example/team/app:1" in ["remote"]: 1 error '
        "occurred:\n\t* remote error: GET https://registry.example/token: DENIED: requested access to the resource "
        "is denied\n\n",
    )
    monkeypatch.setenv("FAKE_TRIVY_EXIT", "1")
    r = _registry_test("registry.example/team/app:1")
    assert r.exit_code == 1
    assert (
        "error: registry.example/team/app:1: authentication failed on registry.example: "
        "remote error: GET https://registry.example/token: DENIED: requested access to the resource is denied\n"
    ) in r.stderr
    assert "FATAL" not in r.stderr


class _FakeApi:
    def __init__(self, context="my-cluster", error=None):
        self._context, self._error = context, error

    def current_context(self):
        if self._error:
            raise self._error
        return self._context


@pytest.fixture
def ui_env(fake_env, monkeypatch):
    """Fake out kube, the socket, the server and the browser; record what ``ui`` hands them."""
    from kubedelos import cli
    from kubedelos.web import server

    calls = {"opened": [], "served": [], "app": {}}
    monkeypatch.setattr(cli.kube_client, "load", lambda settings: _FakeApi())
    monkeypatch.setattr(server, "bind", lambda host, port: ("sock", host, port))
    monkeypatch.setattr(server, "serve", lambda app, sock: calls["served"].append((app, sock)))
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: calls["opened"].append(url))

    def fake_create_app(settings, **kwargs):
        calls["app"] = kwargs
        return "the-app"

    monkeypatch.setattr(cli, "create_app", fake_create_app)
    return calls


def test_ui_rejects_non_loopback_host(ui_env):
    r = CliRunner().invoke(app, ["ui", "--host", "0.0.0.0"])  # noqa: S104 - checks the rejection
    assert r.exit_code == 2
    assert "error: --host must be 127.0.0.1, ::1 or localhost" in r.output
    assert ui_env["served"] == []


def test_ui_port_in_use_exits_2(ui_env, monkeypatch):
    from kubedelos.web import server

    def busy(host, port):
        raise server.PortInUse(port)

    monkeypatch.setattr(server, "bind", busy)
    r = CliRunner().invoke(app, ["ui", "--port", "9444"])
    assert r.exit_code == 2
    assert "error: port 9444 is in use; pass --port" in r.output


def test_ui_bad_context_exits_2(ui_env, monkeypatch):
    from kubedelos import cli

    monkeypatch.setattr(cli.kube_client, "load", lambda settings: _FakeApi(error=RuntimeError("no such\ncontext")))
    r = CliRunner().invoke(app, ["ui"])
    assert r.exit_code == 2
    assert "error: no such context" in r.output


def test_ui_prints_url_and_opens_browser(ui_env):
    r = CliRunner().invoke(app, ["ui", "--port", "9444"])
    assert r.exit_code == 0, r.output
    token = ui_env["app"]["token"]
    expected = f"http://127.0.0.1:9444/?token={token}"
    assert f"kubedelos ui for context my-cluster: {expected}" in r.stdout
    assert "Ctrl-C" in r.stdout
    assert ui_env["opened"] == [expected]
    assert ui_env["app"]["context"] == "my-cluster"
    assert ui_env["app"]["port"] == 9444
    assert ui_env["served"] == [("the-app", ("sock", "127.0.0.1", 9444))]


def test_ui_no_browser_does_not_open_one(ui_env):
    r = CliRunner().invoke(app, ["ui", "--no-browser"])
    assert r.exit_code == 0, r.output
    assert ui_env["opened"] == []


def test_ui_creates_and_migrates_db(ui_env):
    import sqlite3

    from kubedelos.config import Settings
    from kubedelos.store.db import MIGRATIONS

    r = CliRunner().invoke(app, ["ui", "--no-browser"])
    assert r.exit_code == 0, r.output
    conn = sqlite3.connect(Settings().db_path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    finally:
        conn.close()
