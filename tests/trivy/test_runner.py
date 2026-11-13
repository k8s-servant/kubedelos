import json
import os
import threading
import time
from pathlib import Path

import pytest

from kubedelos.config import Settings
from kubedelos.models import ImageRef, ImageResult, InventoryItem
from kubedelos.trivy import runner
from kubedelos.trivy.parse import parse_report
from kubedelos.trivy.runner import TrivyServer, scan_image, scan_many

FAKE_TRIVY = Path(__file__).parent / "fake_trivy.py"
FIXTURES = Path(__file__).parent / "fixtures"
REF = ImageRef(ref="registry.example/app@sha256:" + "a" * 64, repo="registry.example/app", digest="sha256:" + "a" * 64)
URL = "http://127.0.0.1:1"


def _gone(pid: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def test_fake_trivy_is_executable():
    assert os.access(FAKE_TRIVY, os.X_OK)


def test_runner_builds_expected_args(tmp_path, monkeypatch):
    record = tmp_path / "record.json"
    monkeypatch.setenv("FAKE_TRIVY_RECORD", str(record))
    monkeypatch.setenv("FAKE_TRIVY_REPORT", str(FIXTURES / "alpine.json"))
    monkeypatch.delenv("DOCKER_CONFIG", raising=False)

    result = scan_image(FAKE_TRIVY, URL, REF, "linux/arm64", 120, token="s3cret", cache_dir=tmp_path / "trivy-cache")

    echoed = json.loads(record.read_text())
    assert echoed["FakeArgv"] == [
        "image",
        "--server",
        URL,
        "--format",
        "json",
        "--scanners",
        "vuln",
        "--image-src",
        "remote",
        "--platform",
        "linux/arm64",
        "--quiet",
        "--timeout",
        "120s",
        "--cache-dir",
        str(tmp_path / "trivy-cache"),
        "--skip-db-update",
        "--skip-java-db-update",
        REF.ref,
    ]
    assert echoed["FakeEnv"] == {"TRIVY_TOKEN": "s3cret", "DOCKER_CONFIG": None}
    findings, os_family = parse_report(json.loads((FIXTURES / "alpine.json").read_text()))
    assert result.status == "ok"
    assert result.error_kind is None
    assert result.findings == findings
    assert result.os_family == os_family
    assert result.image == REF
    assert result.platform == "linux/arm64"


def test_runner_sets_docker_config_only_when_given(tmp_path, monkeypatch):
    record = tmp_path / "record.json"
    monkeypatch.setenv("FAKE_TRIVY_RECORD", str(record))
    scan_image(FAKE_TRIVY, URL, REF, "linux/amd64", 60, docker_config=tmp_path / "docker")
    echoed = json.loads(record.read_text())
    assert echoed["FakeEnv"]["DOCKER_CONFIG"] == str(tmp_path / "docker")
    assert "--cache-dir" not in echoed["FakeArgv"]


@pytest.mark.parametrize(
    ("stderr", "kind"),
    [
        ("FATAL unable to fetch: UNAUTHORIZED: authentication required", "auth"),
        ("GET https://registry.example/v2/app: DENIED: requested access to the resource is denied", "auth"),
        ("MANIFEST_UNKNOWN: manifest unknown", "not_found"),
        ("NAME_UNKNOWN: repository name not known to registry; name unknown", "not_found"),
        ("FATAL scan error: rpc error: context deadline exceeded", "timeout"),
        ("FATAL image scan error: something exploded", "trivy"),
    ],
)
def test_runner_classifies_errors(monkeypatch, stderr, kind):
    monkeypatch.setenv("FAKE_TRIVY_STDERR", stderr)
    monkeypatch.setenv("FAKE_TRIVY_EXIT", "1")
    result = scan_image(FAKE_TRIVY, URL, REF, "linux/amd64", 60)
    assert result.status == "error"
    assert result.error_kind == kind
    assert result.findings == []
    assert stderr in result.error


def test_runner_classifies_timeout(monkeypatch):
    monkeypatch.setattr(runner, "_TIMEOUT_GRACE_S", 0)
    monkeypatch.setenv("FAKE_TRIVY_SLEEP", "10")
    started = time.monotonic()
    result = scan_image(FAKE_TRIVY, URL, REF, "linux/amd64", 1)
    assert time.monotonic() - started < 4
    assert result.status == "error"
    assert result.error_kind == "timeout"


@pytest.mark.parametrize("mode", ["garbage", "badreport"])
def test_runner_malformed_output_is_trivy_error(monkeypatch, mode):
    monkeypatch.setenv("FAKE_TRIVY_MODE", mode)
    result = scan_image(FAKE_TRIVY, URL, REF, "linux/amd64", 60)
    assert result.status == "error"
    assert result.error_kind == "trivy"
    assert result.error


def test_runner_error_is_truncated_and_hides_token(monkeypatch):
    monkeypatch.setenv("FAKE_TRIVY_STDERR", "boom s3cret " + "x" * 5000)
    monkeypatch.setenv("FAKE_TRIVY_EXIT", "3")
    result = scan_image(FAKE_TRIVY, URL, REF, "linux/amd64", 60, token="s3cret")
    assert result.error_kind == "trivy"
    assert len(result.error) <= 2000
    assert "s3cret" not in result.error


def test_trivy_server_stops_on_exit(tmp_path, monkeypatch):
    pid_file, child_file, log = tmp_path / "server.pid", tmp_path / "child.pid", tmp_path / "downloads.jsonl"
    monkeypatch.setenv("FAKE_TRIVY_PID_FILE", str(pid_file))
    monkeypatch.setenv("FAKE_TRIVY_CHILD_PID_FILE", str(child_file))
    monkeypatch.setenv("FAKE_TRIVY_DOWNLOAD_LOG", str(log))

    with TrivyServer(FAKE_TRIVY, tmp_path) as server:
        assert server.url.startswith("http://127.0.0.1:")
        assert len(server.token) >= 32
        pid, child = int(pid_file.read_text()), int(child_file.read_text())
        os.kill(pid, 0)
        os.kill(child, 0)

    assert _gone(pid)
    assert _gone(child)
    cache = str(tmp_path / "trivy-cache")
    downloads = [json.loads(line) for line in log.read_text().splitlines()]
    assert downloads == [
        ["image", "--download-db-only", "--cache-dir", cache],
        ["image", "--download-java-db-only", "--cache-dir", cache],
    ]


def test_trivy_server_kills_when_term_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_STOP_GRACE_S", 0.3)
    pid_file = tmp_path / "server.pid"
    monkeypatch.setenv("FAKE_TRIVY_PID_FILE", str(pid_file))
    monkeypatch.setenv("FAKE_TRIVY_IGNORE_TERM", "1")
    with TrivyServer(FAKE_TRIVY, tmp_path):
        pid = int(pid_file.read_text())
    assert _gone(pid)


def test_trivy_server_raises_when_process_exits(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_TRIVY_SERVER_CRASH", "FATAL listen failed")
    with pytest.raises(RuntimeError, match="FATAL listen failed"), TrivyServer(FAKE_TRIVY, tmp_path):
        pass


def test_trivy_server_raises_when_db_download_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_TRIVY_DOWNLOAD_FAIL", "FATAL db download failed")
    with pytest.raises(RuntimeError, match="FATAL db download failed"), TrivyServer(FAKE_TRIVY, tmp_path):
        pass


def _items(n: int) -> list[InventoryItem]:
    return [
        InventoryItem(
            image=ImageRef(ref=f"registry.example/app:{i}", repo="registry.example/app", tag=str(i)),
            platform="linux/amd64",
        )
        for i in range(n)
    ]


def test_scan_many_reports_every_item(tmp_path, monkeypatch):
    record = tmp_path / "record.json"
    monkeypatch.setenv("FAKE_TRIVY_RECORD", str(record))
    settings = Settings(cache_dir=tmp_path, parallelism=3, scan_timeout_s=30)
    results: list[ImageResult] = []
    with TrivyServer(FAKE_TRIVY, tmp_path) as server:
        scan_many(
            _items(5),
            server=server,
            trivy=FAKE_TRIVY,
            settings=settings,
            on_result=results.append,
            cancel=threading.Event(),
        )
        token = server.token
    assert sorted(r.image.ref for r in results) == sorted(i.image.ref for i in _items(5))
    assert all(r.status == "ok" for r in results)
    echoed = json.loads(record.read_text())
    assert echoed["FakeEnv"]["TRIVY_TOKEN"] == token
    assert token not in echoed["FakeArgv"]
    assert echoed["FakeArgv"][echoed["FakeArgv"].index("--cache-dir") + 1] == str(tmp_path / "trivy-cache")


def test_scan_many_respects_cancel(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_TRIVY_SLEEP", "0.2")
    settings = Settings(cache_dir=tmp_path, parallelism=2, scan_timeout_s=30)
    cancel = threading.Event()
    results: list[ImageResult] = []

    def on_result(result: ImageResult) -> None:
        results.append(result)
        cancel.set()

    with TrivyServer(FAKE_TRIVY, tmp_path) as server:
        scan_many(_items(10), server=server, trivy=FAKE_TRIVY, settings=settings, on_result=on_result, cancel=cancel)
    assert 1 <= len(results) < 10


def test_scan_many_turns_worker_exceptions_into_unknown(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("exec format error")

    monkeypatch.setattr(runner, "scan_image", boom)
    settings = Settings(cache_dir=tmp_path, parallelism=2)
    results: list[ImageResult] = []
    with TrivyServer(FAKE_TRIVY, tmp_path) as server:
        scan_many(
            _items(2),
            server=server,
            trivy=FAKE_TRIVY,
            settings=settings,
            on_result=results.append,
            cancel=threading.Event(),
        )
    assert [r.error_kind for r in results] == ["unknown", "unknown"]
    assert all(r.status == "error" and "exec format error" in r.error for r in results)


def test_scan_many_propagates_on_result_errors(tmp_path):
    settings = Settings(cache_dir=tmp_path, parallelism=2)

    def on_result(result: ImageResult) -> None:
        raise ValueError("sink broke")

    with TrivyServer(FAKE_TRIVY, tmp_path) as server, pytest.raises(ValueError, match="sink broke"):
        scan_many(
            _items(3), server=server, trivy=FAKE_TRIVY, settings=settings, on_result=on_result, cancel=threading.Event()
        )
