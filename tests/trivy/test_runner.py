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
from kubedelos.trivy.runner import scan_image, scan_many

FAKE_TRIVY = Path(__file__).parent / "fake_trivy.py"
FIXTURES = Path(__file__).parent / "fixtures"
REF = ImageRef(ref="registry.example/app@sha256:" + "a" * 64, repo="registry.example/app", digest="sha256:" + "a" * 64)


def test_fake_trivy_is_executable():
    assert os.access(FAKE_TRIVY, os.X_OK)


def test_runner_builds_expected_args(tmp_path, monkeypatch):
    record = tmp_path / "record.json"
    monkeypatch.setenv("FAKE_TRIVY_RECORD", str(record))
    monkeypatch.setenv("FAKE_TRIVY_REPORT", str(FIXTURES / "alpine.json"))
    monkeypatch.delenv("DOCKER_CONFIG", raising=False)

    result = scan_image(FAKE_TRIVY, REF, "linux/arm64", 120, cache_dir=tmp_path / "trivy-cache")

    echoed = json.loads(record.read_text())
    assert echoed["FakeArgv"] == [
        "image",
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
        "--cache-backend",
        "memory",
        "--cache-dir",
        str(tmp_path / "trivy-cache"),
        "--skip-db-update",
        "--skip-java-db-update",
        "--",
        REF.ref,
    ]
    assert echoed["FakeEnv"] == {"DOCKER_CONFIG": None}
    findings, os_family = parse_report(json.loads((FIXTURES / "alpine.json").read_text()))
    assert result.status == "ok"
    assert result.error_kind is None
    assert result.findings == findings
    assert result.os_family == os_family
    assert result.image == REF
    assert result.platform == "linux/arm64"


def test_runner_inherits_docker_config_from_env(tmp_path, monkeypatch):
    record = tmp_path / "record.json"
    monkeypatch.setenv("FAKE_TRIVY_RECORD", str(record))
    monkeypatch.setenv("DOCKER_CONFIG", "/x/docker")  # e.g. a CI job's own login
    scan_image(FAKE_TRIVY, REF, "linux/amd64", 60)
    assert json.loads(record.read_text())["FakeEnv"]["DOCKER_CONFIG"] == "/x/docker"


def test_runner_sets_docker_config_only_when_given(tmp_path, monkeypatch):
    record = tmp_path / "record.json"
    monkeypatch.setenv("FAKE_TRIVY_RECORD", str(record))
    scan_image(FAKE_TRIVY, REF, "linux/amd64", 60, docker_config=tmp_path / "docker")
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
        (
            'error getting credentials - err: exec: "docker-credential-desktop": executable file not found in $PATH',
            "auth",
        ),
        ("FATAL image scan error: something exploded", "trivy"),
    ],
)
def test_runner_classifies_errors(monkeypatch, stderr, kind):
    monkeypatch.setenv("FAKE_TRIVY_STDERR", stderr)
    monkeypatch.setenv("FAKE_TRIVY_EXIT", "1")
    result = scan_image(FAKE_TRIVY, REF, "linux/amd64", 60)
    assert result.status == "error"
    assert result.error_kind == kind
    assert result.findings == []
    assert stderr in result.error


def test_runner_classifies_timeout(monkeypatch):
    monkeypatch.setattr(runner, "_TIMEOUT_GRACE_S", 0)
    monkeypatch.setenv("FAKE_TRIVY_SLEEP", "10")
    started = time.monotonic()
    result = scan_image(FAKE_TRIVY, REF, "linux/amd64", 1)
    assert time.monotonic() - started < 4
    assert result.status == "error"
    assert result.error_kind == "timeout"


@pytest.mark.parametrize("mode", ["garbage", "badreport"])
def test_runner_malformed_output_is_trivy_error(monkeypatch, mode):
    monkeypatch.setenv("FAKE_TRIVY_MODE", mode)
    result = scan_image(FAKE_TRIVY, REF, "linux/amd64", 60)
    assert result.status == "error"
    assert result.error_kind == "trivy"
    assert result.error


def test_runner_error_is_truncated(monkeypatch):
    monkeypatch.setenv("FAKE_TRIVY_STDERR", "boom " + "x" * 5000)
    monkeypatch.setenv("FAKE_TRIVY_EXIT", "3")
    result = scan_image(FAKE_TRIVY, REF, "linux/amd64", 60)
    assert result.error_kind == "trivy"
    assert len(result.error) <= 2000


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
    scan_many(
        _items(5),
        cache_dir=tmp_path / "trivy-cache",
        trivy=FAKE_TRIVY,
        settings=settings,
        on_result=results.append,
        cancel=threading.Event(),
    )
    assert sorted(r.image.ref for r in results) == sorted(i.image.ref for i in _items(5))
    assert all(r.status == "ok" for r in results)
    argv = json.loads(record.read_text())["FakeArgv"]
    assert "--server" not in argv
    assert argv[argv.index("--cache-backend") + 1] == "memory"
    assert argv[argv.index("--cache-dir") + 1] == str(tmp_path / "trivy-cache")


def test_scan_many_respects_cancel(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_TRIVY_SLEEP", "0.2")
    settings = Settings(cache_dir=tmp_path, parallelism=2, scan_timeout_s=30)
    cancel = threading.Event()
    results: list[ImageResult] = []

    def on_result(result: ImageResult) -> None:
        results.append(result)
        cancel.set()

    scan_many(_items(10), cache_dir=tmp_path, trivy=FAKE_TRIVY, settings=settings, on_result=on_result, cancel=cancel)
    assert 1 <= len(results) < 10


def test_scan_many_turns_worker_exceptions_into_unknown(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("exec format error")

    monkeypatch.setattr(runner, "scan_image", boom)
    settings = Settings(cache_dir=tmp_path, parallelism=2)
    results: list[ImageResult] = []
    scan_many(
        _items(2),
        cache_dir=tmp_path,
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

    with pytest.raises(ValueError, match="sink broke"):
        scan_many(
            _items(3), cache_dir=tmp_path, trivy=FAKE_TRIVY, settings=settings, on_result=on_result,
            cancel=threading.Event(),
        )  # fmt: skip


def test_scan_many_returns_immediately_for_no_items(tmp_path):
    results: list[ImageResult] = []
    scan_many(
        [], cache_dir=tmp_path, trivy=FAKE_TRIVY, settings=Settings(cache_dir=tmp_path), on_result=results.append,
        cancel=threading.Event(),
    )  # fmt: skip
    assert results == []
