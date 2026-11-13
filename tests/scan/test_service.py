import threading
from datetime import timedelta
from pathlib import Path

import pytest
from kubernetes.client import V1Namespace, V1ObjectMeta

from kubedelos.config import Settings
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity
from kubedelos.scan import service
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo
from tests.kube.fakes import FakeKubeApi, pod

D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64


def _api():
    pods = [
        pod("p1", image="reg.io/a:1", image_id=f"reg.io/a@{D1}", container="c1"),
        pod("p2", image="reg.io/b:1", image_id=f"reg.io/b@{D2}", container="c2"),
    ]
    return FakeKubeApi(namespaces=[V1Namespace(metadata=V1ObjectMeta(name="default"))], pods={"default": pods})


def _settings(tmp_path):
    return Settings(namespaces=["default"], data_dir=tmp_path / "data", cache_dir=tmp_path / "cache")


class FakeServer:
    started = 0

    def __init__(self, trivy, cache_dir):
        pass

    def __enter__(self):
        FakeServer.started += 1
        return self

    def __exit__(self, *exc):
        return None


@pytest.fixture
def env(tmp_path, monkeypatch):
    FakeServer.started = 0
    calls: list[list] = []
    monkeypatch.setattr(service, "TrivyServer", FakeServer)
    monkeypatch.setattr(service, "ensure_trivy", lambda settings: Path("/fake/trivy"))
    conn = connect(tmp_path / "t.db")
    yield _settings(tmp_path), Repo(conn), calls
    conn.close()


def _fake_scan(calls, fail_ref=None):
    def scan_many(items, *, server, trivy, settings, on_result, cancel):
        calls.append(list(items))
        for item in items:
            if fail_ref and item.image.ref == fail_ref:
                r = ImageResult(image=item.image, platform=item.platform, status="error", error_kind="auth", error="x")
            else:
                f = Finding(vuln_id="CVE-1", pkg_name="p", installed_version="1", severity=Severity.HIGH,
                            target="t", pkg_type="os")  # fmt: skip
                r = ImageResult(image=item.image, platform=item.platform, status="ok", findings=[f])
            on_result(r)

    return scan_many


def _status(repo, run_id):
    return repo.get_run(run_id)["status"]


def test_service_persists_results_and_status_partial(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls, fail_ref="reg.io/b@" + D2))
    progress = []
    out = service.run_scan(settings, api=_api(), repo=repo, on_progress=progress.append)
    run = repo.get_run(out.run_id)
    assert run["status"] == "partial"
    assert run["images_total"] == 2 and run["images_error"] == 1
    assert len(repo.run_findings(out.run_id)) == 1
    assert [(p.done, p.errors) for p in progress] == [(0, 0), (1, 0), (2, 1)]
    assert progress[-1].total == 2 and progress[-1].current is not None
    assert repo.get_cached(D1, "linux/amd64", timedelta(hours=1)) is not None
    assert repo.get_cached(D2, "linux/amd64", timedelta(hours=1)) is None  # errors not cached


def test_service_uses_cache_second_run(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    service.run_scan(settings, api=_api(), repo=repo)
    assert FakeServer.started == 1
    progress = []
    out = service.run_scan(settings, api=_api(), repo=repo, on_progress=progress.append)
    assert len(calls) == 1 and FakeServer.started == 1  # nothing left to scan: no scan_many, no server
    assert _status(repo, out.run_id) == "ok"
    assert len(repo.run_findings(out.run_id)) == 2  # stored findings kept
    assert (
        repo._conn.execute(
            "SELECT COUNT(*) FROM image_result WHERE run_id = ? AND status = 'cached'", (out.run_id,)
        ).fetchone()[0]
        == 2
    )
    assert [p.done for p in progress] == [0, 1, 2]


def test_service_cancel(env, monkeypatch):
    settings, repo, _calls = env
    cancel = threading.Event()

    def scan_many(items, *, server, trivy, settings, on_result, cancel):
        cancel.set()

    monkeypatch.setattr(service, "scan_many", scan_many)
    out = service.run_scan(settings, api=_api(), repo=repo, cancel=cancel)
    assert _status(repo, out.run_id) == "cancelled"


def test_service_keyboard_interrupt_marks_cancelled_and_reraises(env, monkeypatch):
    settings, repo, _calls = env

    def scan_many(items, **kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(service, "scan_many", scan_many)
    cancel = threading.Event()
    with pytest.raises(KeyboardInterrupt):
        service.run_scan(settings, api=_api(), repo=repo, cancel=cancel)
    assert cancel.is_set()
    assert _status(repo, repo.latest_run_id()) == "cancelled"


def test_service_failed_on_exception(env, monkeypatch):
    settings, repo, _calls = env

    def scan_many(items, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(service, "scan_many", scan_many)
    with pytest.raises(RuntimeError, match="boom"):
        service.run_scan(settings, api=_api(), repo=repo)
    assert _status(repo, repo.latest_run_id()) == "failed"


def test_cached_result_stores_current_ref(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    service.run_scan(settings, api=_api(), repo=repo)
    pods = [pod("p1", image="reg.io/a:2", image_id=f"reg.io/a@{D1}", container="c1")]
    api = FakeKubeApi(namespaces=[V1Namespace(metadata=V1ObjectMeta(name="default"))], pods={"default": pods})
    out = service.run_scan(settings, api=api, repo=repo)
    row = repo._conn.execute("SELECT ref, tag, status FROM image_result WHERE run_id = ?", (out.run_id,)).fetchone()
    assert (row["ref"], row["tag"], row["status"]) == (f"reg.io/a@{D1}", "2", "cached")


@pytest.mark.parametrize("bad", ["-oyaml", "nginx --help", "reg.io/a:1\nx", "reg.io/" + "a" * 600])
def test_service_rejects_invalid_refs(env, monkeypatch, bad):
    settings, repo, calls = env
    good = InventoryItem(image=ImageRef(ref="reg.io/a:1", repo="reg.io/a", tag="1"), platform="linux/amd64")
    evil = InventoryItem(image=ImageRef(ref=bad, repo=bad), platform="linux/amd64")
    monkeypatch.setattr(service, "collect", lambda api, settings: ([good, evil], []))
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    progress = []
    out = service.run_scan(settings, api=_api(), repo=repo, on_progress=progress.append)
    assert [[i.image.ref for i in batch] for batch in calls] == [["reg.io/a:1"]]
    rows = repo._conn.execute(
        "SELECT ref, status, error_kind, error FROM image_result WHERE run_id = ? ORDER BY id", (out.run_id,)
    ).fetchall()
    assert [tuple(r) for r in rows if r["ref"] == bad] == [(bad, "error", "unknown", "invalid image reference")]
    assert progress[-1].errors == 1
    assert _status(repo, out.run_id) == "partial"


def test_service_skips_server_when_only_invalid_refs(env, monkeypatch):
    settings, repo, calls = env
    evil = InventoryItem(image=ImageRef(ref="-oyaml", repo="-oyaml"), platform="linux/amd64")
    monkeypatch.setattr(service, "collect", lambda api, settings: ([evil], []))
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    out = service.run_scan(settings, api=_api(), repo=repo)
    assert calls == [] and FakeServer.started == 0
    assert _status(repo, out.run_id) == "partial"
