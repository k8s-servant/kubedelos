import threading
from datetime import timedelta
from pathlib import Path
from typing import ClassVar

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


class FakeCache:
    started = 0

    java_db: ClassVar[list[bool]] = []

    def __init__(self, trivy, cache_dir, *, java_db=True):
        self.dir = cache_dir / "trivy-cache"
        FakeCache.java_db.append(java_db)

    def __enter__(self):
        FakeCache.started += 1
        return self

    def __exit__(self, *exc):
        return None


@pytest.fixture
def env(tmp_path, monkeypatch):
    FakeCache.started = 0
    FakeCache.java_db = []
    calls: list[list] = []
    monkeypatch.setattr(service, "TrivyCache", FakeCache)
    monkeypatch.setattr(service, "ensure_trivy", lambda settings: Path("/fake/trivy"))
    conn = connect(tmp_path / "t.db")
    yield _settings(tmp_path), Repo(conn), calls
    conn.close()


def _fake_scan(calls, fail_ref=None):
    def scan_many(items, *, cache_dir, trivy, settings, on_result, cancel):
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
    assert repo.get_cached(D1, "linux/amd64", timedelta(hours=1), scan_level="library,os") is not None
    assert repo.get_cached(D2, "linux/amd64", timedelta(hours=1), scan_level="library,os") is None  # errors not cached


def test_service_uses_cache_second_run(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    service.run_scan(settings, api=_api(), repo=repo)
    assert FakeCache.started == 1
    progress = []
    out = service.run_scan(settings, api=_api(), repo=repo, on_progress=progress.append)
    assert len(calls) == 1 and FakeCache.started == 1  # nothing left to scan: no scan_many, no Trivy
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

    def scan_many(items, *, cache_dir, trivy, settings, on_result, cancel):
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


def test_service_skips_trivy_when_only_invalid_refs(env, monkeypatch):
    settings, repo, calls = env
    evil = InventoryItem(image=ImageRef(ref="-oyaml", repo="-oyaml"), platform="linux/amd64")
    monkeypatch.setattr(service, "collect", lambda api, settings: ([evil], []))
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    out = service.run_scan(settings, api=_api(), repo=repo)
    assert calls == [] and FakeCache.started == 0
    assert _status(repo, out.run_id) == "partial"


def test_custom_trivy_path_skips_cache_and_records_custom(env, monkeypatch, tmp_path):
    settings, repo, calls = env
    settings = settings.model_copy(update={"trivy_path": tmp_path / "my-trivy"})
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    pinned = service.run_scan(settings.model_copy(update={"trivy_path": None}), api=_api(), repo=repo)
    assert repo.get_run(pinned.run_id)["trivy_version"] == "0.76.1"
    assert repo._conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 2
    out = service.run_scan(settings, api=_api(), repo=repo)
    assert len(calls) == 2 and len(calls[1]) == 2  # the pinned run's cache was not read
    assert repo.get_run(out.run_id)["trivy_version"] == "custom"
    repo._conn.execute("DELETE FROM image_cache")
    service.run_scan(settings, api=_api(), repo=repo)
    assert repo._conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 0  # and not written


def test_corrupt_cache_row_is_rescanned(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    service.run_scan(settings, api=_api(), repo=repo)
    repo._conn.execute('UPDATE image_cache SET report_json = \'{"findings": "nope"}\'')
    out = service.run_scan(settings, api=_api(), repo=repo)
    assert _status(repo, out.run_id) == "ok"
    assert len(calls) == 2 and len(calls[1]) == 2


def test_service_uses_scan_level_for_cache(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    first = service.run_scan(settings.model_copy(update={"pkg_types": ("os",)}), api=_api(), repo=repo)
    second = service.run_scan(settings, api=_api(), repo=repo)
    assert len(calls) == 2  # an os-only result is never a cache hit for library,os
    assert FakeCache.java_db == [False, True]
    assert repo.get_run(first.run_id)["pkg_types"] == "os"
    assert repo.get_run(second.run_id)["pkg_types"] == "library,os"
