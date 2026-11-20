import json
import threading
from datetime import timedelta
from pathlib import Path
from typing import ClassVar

import pytest
from kubernetes.client import V1Namespace, V1ObjectMeta

from kubedelos.config import Settings
from kubedelos.kube.inventory import Inventory
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity
from kubedelos.scan import service
from kubedelos.store import runlock
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
    def scan_many(items, *, cache_dir, trivy, settings, on_result, cancel, access=None):
        calls.append(list(items))
        for item in items:
            if fail_ref and item.image.ref == fail_ref:
                r = ImageResult(image=item.image, platform=item.platform, status="error", error_kind="auth", error="x")
            else:
                f = Finding(vuln_id="CVE-1", pkg_name="p", installed_version="1", severity=Severity.HIGH,
                            target="t", pkg_type="os")  # fmt: skip
                r = ImageResult(image=item.image, platform=item.platform, status="ok", findings=[f], duration_s=12.5)
            on_result(r)

    return scan_many


def _finding_count(repo, run_id):
    return repo._conn.execute(
        "SELECT COUNT(*) FROM finding f JOIN image_result r ON r.id = f.image_result_id WHERE r.run_id = ?", (run_id,)
    ).fetchone()[0]


def _status(repo, run_id):
    return repo.get_run(run_id)["status"]


def test_service_persists_results_and_status_partial(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls, fail_ref="reg.io/b@" + D2))
    progress = []
    out = service.run_scan(settings, api=_api(), repo=repo, on_progress=progress.append)
    run = repo.get_run(out.run_id)
    assert run["status"] == "partial" and out.status == "partial"
    assert run["images_total"] == 2 and run["images_error"] == 1
    assert _finding_count(repo, out.run_id) == 1
    assert [(p.done, p.errors) for p in progress if p.current] == [(1, 0), (2, 1)]
    assert progress[-1].total == 2 and progress[-1].phase == "saving"
    assert progress[0].run_id is None  # the inventory comes before the run row
    assert {p.run_id for p in progress[1:]} == {out.run_id}  # from then on, so a reader can list its failures live
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
    assert _status(repo, out.run_id) == "ok" and out.status == "ok"
    assert _finding_count(repo, out.run_id) == 2  # stored findings kept
    assert (
        repo._conn.execute(
            "SELECT COUNT(*) FROM image_result WHERE run_id = ? AND status = 'cached'", (out.run_id,)
        ).fetchone()[0]
        == 2
    )
    assert [p.done for p in progress if p.current] == [1, 2]


def test_rescan_skips_cached_results_and_refreshes_the_cache(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    service.run_scan(settings, api=_api(), repo=repo)
    before = repo._conn.execute("SELECT MAX(scanned_at) FROM image_cache").fetchone()[0]
    out = service.run_scan(settings, api=_api(), repo=repo, rescan=True)
    assert len(calls) == 2 and FakeCache.started == 2  # every image went to Trivy again
    statuses = repo._conn.execute("SELECT status FROM image_result WHERE run_id = ?", (out.run_id,)).fetchall()
    assert "cached" not in {row[0] for row in statuses}
    assert repo._conn.execute("SELECT MAX(scanned_at) FROM image_cache").fetchone()[0] > before  # fresh result stored
    third = service.run_scan(settings, api=_api(), repo=repo)
    assert len(calls) == 2 and _status(repo, third.run_id) == "ok"  # the next plain scan uses the refreshed cache


def test_service_cancel(env, monkeypatch):
    settings, repo, _calls = env
    cancel = threading.Event()

    def scan_many(items, *, cache_dir, trivy, settings, on_result, cancel, access=None):
        cancel.set()

    monkeypatch.setattr(service, "scan_many", scan_many)
    out = service.run_scan(settings, api=_api(), repo=repo, cancel=cancel)
    assert _status(repo, out.run_id) == "cancelled" and out.status == "cancelled"


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


def test_a_cached_result_records_no_scan_time(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    first = service.run_scan(settings, api=_api(), repo=repo)
    second = service.run_scan(settings, api=_api(), repo=repo)
    sql = "SELECT status, duration_s FROM image_result WHERE run_id = ?"
    assert {tuple(r) for r in repo._conn.execute(sql, (first.run_id,))} == {("ok", 12.5)}
    assert {tuple(r) for r in repo._conn.execute(sql, (second.run_id,))} == {("cached", None)}


@pytest.mark.parametrize("bad", ["-oyaml", "nginx --help", "reg.io/a:1\nx", "reg.io/" + "a" * 600])
def test_service_rejects_invalid_refs(env, monkeypatch, bad):
    settings, repo, calls = env
    good = InventoryItem(image=ImageRef(ref="reg.io/a:1", repo="reg.io/a", tag="1"), platform="linux/amd64")
    evil = InventoryItem(image=ImageRef(ref=bad, repo=bad), platform="linux/amd64")
    monkeypatch.setattr(service, "collect_inventory", lambda api, settings: Inventory([good, evil], [], {}))
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
    monkeypatch.setattr(service, "collect_inventory", lambda api, settings: Inventory([evil], [], {}))
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


def test_run_scan_stores_the_cluster_name(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    api = _api()
    monkeypatch.setattr(api, "current_context", lambda: "kind-x")
    named = service.run_scan(settings.model_copy(update={"cluster_name": "my-cluster"}), api=api, repo=repo)
    assert repo.get_run(named.run_id)["context"] == "my-cluster"
    plain = service.run_scan(settings, api=api, repo=repo)
    assert repo.get_run(plain.run_id)["context"] == "kind-x"


def test_run_scan_stores_the_requester(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    out = service.run_scan(settings, api=_api(), repo=repo, requested_by="a@example.com")
    assert repo.get_run(out.run_id)["requested_by"] == "a@example.com"


def test_service_records_scope(env, monkeypatch):
    import json

    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    out = service.run_scan(settings.model_copy(update={"selector": "app=web"}), api=_api(), repo=repo)
    assert json.loads(repo.get_run(out.run_id)["scope"])["selector"] == "app=web"


def test_service_stores_inventory_warnings(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    settings = settings.model_copy(update={"namespaces": ["default", "missing"]})
    outcome = service.run_scan(settings, api=_api(), repo=repo)
    rows = repo.run_warnings(outcome.run_id)
    assert [(r["text"], r["coverage"]) for r in rows] == [("namespace missing not found", 1)]


def test_service_failed_when_storing_warnings_fails(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))

    def add_warnings(run_id, warnings):
        raise RuntimeError("disk full")

    monkeypatch.setattr(repo, "add_warnings", add_warnings)
    with pytest.raises(RuntimeError, match="disk full"):
        service.run_scan(settings, api=_api(), repo=repo)
    assert _status(repo, repo.latest_run_id()) == "failed"


def test_run_scan_records_an_owner_that_is_live_during_the_scan(env, monkeypatch):
    settings, repo, calls = env
    seen = []

    def scan_many(items, *, cache_dir, trivy, settings, on_result, cancel, access=None):
        owner = repo.get_run(repo.latest_run_id())["owner"]
        seen.append((owner, runlock.is_owned(settings.data_dir, owner)))
        _fake_scan(calls)(
            items, cache_dir=cache_dir, trivy=trivy, settings=settings, on_result=on_result, cancel=cancel
        )

    monkeypatch.setattr(service, "scan_many", scan_many)
    out = service.run_scan(settings, api=_api(), repo=repo)
    [(owner, live)] = seen
    assert owner and live
    assert repo.get_run(out.run_id)["owner"] == owner
    assert not runlock.is_owned(settings.data_dir, owner)


def _phases(progress):
    out: list[str] = []
    for p in progress:
        if not out or out[-1] != p.phase:
            out.append(p.phase)
    return out


def test_progress_reports_phases_in_order_and_counts_cached(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    service.run_scan(settings, api=_api(), repo=repo)  # caches both images
    repo._conn.execute("DELETE FROM image_cache WHERE image_key = ?", (D2,))
    repo._conn.commit()
    progress = []
    service.run_scan(settings, api=_api(), repo=repo, on_progress=progress.append)
    assert _phases(progress) == ["inventory", "scanning", "trivy-db", "scanning", "saving"]
    assert progress[-1].cached == 1
    assert progress[-1].done == 2
    assert all(p.current is None for p in progress if p.phase in ("inventory", "trivy-db", "saving"))


def test_progress_skips_trivy_db_phase_when_everything_is_cached(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    service.run_scan(settings, api=_api(), repo=repo)
    progress = []
    service.run_scan(settings, api=_api(), repo=repo, on_progress=progress.append)
    assert "trivy-db" not in _phases(progress)
    assert _phases(progress) == ["inventory", "scanning", "saving"]
    assert progress[-1].cached == 2


def test_cancel_during_inventory_never_reaches_trivy(env, monkeypatch):
    settings, repo, calls = env
    cancel = threading.Event()
    real_collect = service.collect_inventory

    def collect(api, settings):
        cancel.set()  # Ctrl-C on the UI while the cluster is being listed
        return real_collect(api, settings)

    def refuse(settings):
        raise AssertionError("a cancelled scan fetched Trivy")

    phases: list[str] = []
    monkeypatch.setattr(service, "collect_inventory", collect)
    monkeypatch.setattr(service, "ensure_trivy", refuse)
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    out = service.run_scan(settings, api=_api(), repo=repo, cancel=cancel, on_progress=lambda p: phases.append(p.phase))
    assert out.status == "cancelled" and _status(repo, out.run_id) == "cancelled"
    assert FakeCache.started == 0 and calls == []
    assert "trivy-db" not in phases


def test_cancel_during_the_trivy_download_never_starts_the_db(env, monkeypatch):
    settings, repo, calls = env
    cancel = threading.Event()

    def ensure_trivy(settings):
        cancel.set()  # Ctrl-C on the UI while the Trivy binary downloads
        return Path("/fake/trivy")

    monkeypatch.setattr(service, "ensure_trivy", ensure_trivy)
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    out = service.run_scan(settings, api=_api(), repo=repo, cancel=cancel)
    assert out.status == "cancelled" and _status(repo, out.run_id) == "cancelled"
    assert FakeCache.started == 0 and calls == []


LOCAL_ID = "sha256:" + "e" * 64


def _kind_api():
    pods = [pod("p1", image="registry.k8s.io/etcd:3.6.6-0", image_id=LOCAL_ID, container="c1")]
    return FakeKubeApi(namespaces=[V1Namespace(metadata=V1ObjectMeta(name="default"))], pods={"default": pods})


def _scan_reporting(calls, scanned_image_id):
    def scan_many(items, *, cache_dir, trivy, settings, on_result, cancel, access=None):
        calls.append(list(items))
        for item in items:
            r = ImageResult(image=item.image, platform=item.platform, status="ok", scanned_image_id=scanned_image_id)
            on_result(r)

    return scan_many


def test_local_image_id_is_cached_when_trivy_scanned_that_image(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _scan_reporting(calls, LOCAL_ID))
    service.run_scan(settings, api=_kind_api(), repo=repo)
    out = service.run_scan(settings, api=_kind_api(), repo=repo)
    assert len(calls) == 1  # the second run came from the cache
    statuses = repo._conn.execute("SELECT status FROM image_result WHERE run_id = ?", (out.run_id,)).fetchall()
    assert [s[0] for s in statuses] == ["cached"]


@pytest.mark.parametrize("scanned", ["sha256:" + "f" * 64, None])
def test_local_image_id_is_not_cached_when_trivy_scanned_another_image(env, monkeypatch, scanned):
    # the tag was pushed again since the node pulled it (or Trivy did not say): the result is not the pod's image
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _scan_reporting(calls, scanned))
    service.run_scan(settings, api=_kind_api(), repo=repo)
    service.run_scan(settings, api=_kind_api(), repo=repo)
    assert len(calls) == 2
    assert repo._conn.execute("SELECT COUNT(*) FROM image_cache").fetchone()[0] == 0


def test_tag_ref_without_image_id_is_still_not_cached(env, monkeypatch):
    settings, repo, calls = env
    pods = [pod("p1", image="reg.io/a:1", image_id="", container="c1")]
    api = FakeKubeApi(namespaces=[V1Namespace(metadata=V1ObjectMeta(name="default"))], pods={"default": pods})
    monkeypatch.setattr(service, "scan_many", _scan_reporting(calls, LOCAL_ID))
    service.run_scan(settings, api=api, repo=repo)
    service.run_scan(settings, api=api, repo=repo)
    assert len(calls) == 2


def _partial_run(env, monkeypatch, *, pkg_types=("library", "os")):
    """A finished partial run of the fake cluster in which reg.io/b failed."""
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls, fail_ref="reg.io/b@" + D2))
    out = service.run_scan(settings.model_copy(update={"pkg_types": pkg_types}), api=_api(), repo=repo)
    calls.clear()
    return out.run_id


def test_retry_rescans_only_the_failed_images_in_the_same_run(env, monkeypatch):
    settings, repo, calls = env
    run_id = _partial_run(env, monkeypatch, pkg_types=("os",))
    seen = []

    def scan_many(items, *, cache_dir, trivy, settings, on_result, cancel, access=None):
        seen.append(settings)
        _fake_scan(calls)(
            items, cache_dir=cache_dir, trivy=trivy, settings=settings, on_result=on_result, cancel=cancel
        )

    monkeypatch.setattr(service, "scan_many", scan_many)
    progress = []
    retry = settings.model_copy(update={"scan_timeout_s": 1800, "parallelism": 2})
    out = service.retry_failed(retry, run_id, repo=repo, on_progress=progress.append)
    assert (out.run_id, out.status) == (run_id, "ok")
    assert [[i.image.ref for i in items] for items in calls] == [["reg.io/b@" + D2]]
    assert [i.workloads[0].container for i in calls[0]] == ["c2"]
    assert (seen[0].pkg_types, seen[0].scan_timeout_s, seen[0].parallelism) == (("os",), 1800, 2)  # the run's level
    run = repo.get_run(run_id)
    assert (run["status"], run["images_total"], run["images_error"]) == ("ok", 2, 0)
    assert _finding_count(repo, run_id) == 2
    assert repo.run_warnings(run_id)[-1]["text"].endswith(": 1 scanned, 0 still failing")
    assert repo.get_cached(D2, "linux/amd64", timedelta(hours=1), scan_level="os") is not None
    assert {p.run_id for p in progress} == {run_id} and progress[-1].phase == "saving"
    assert [(p.total, p.done) for p in progress if p.current] == [(1, 1)]


def test_retry_of_some_kinds_rescans_only_those(env, monkeypatch):
    settings, repo, calls = env
    run_id = _partial_run(env, monkeypatch)  # reg.io/b failed with auth
    with pytest.raises(service.RetryRefused, match="run 1 has no failed images of kind not_found, timeout"):
        service.retry_failed(settings, run_id, repo=repo, kinds={"timeout", "not_found"})
    assert calls == [] and repo.run_warnings(run_id) == []
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    assert service.retry_failed(settings, run_id, repo=repo, kinds={"auth"}).status == "ok"
    assert repo.run_warnings(run_id)[-1]["text"].startswith("retried 1 failed image (auth) at ")


def test_retry_uses_a_cached_result(env, monkeypatch):
    settings, repo, calls = env
    run_id = _partial_run(env, monkeypatch)
    item = repo.failed_items(run_id)[0][1]
    repo.put_cache(D2, "linux/amd64", ImageResult(image=item.image, platform="linux/amd64", status="ok"),
                   scan_level="library,os")  # fmt: skip
    out = service.retry_failed(settings, run_id, repo=repo)
    assert out.status == "ok" and calls == []


def test_retry_that_fails_again_keeps_the_run_partial(env, monkeypatch):
    settings, repo, calls = env
    run_id = _partial_run(env, monkeypatch)
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls, fail_ref="reg.io/b@" + D2))
    assert service.retry_failed(settings, run_id, repo=repo).status == "partial"
    assert repo.get_run(run_id)["images_error"] == 1
    assert repo.run_warnings(run_id)[-1]["text"].endswith(": 0 scanned, 1 still failing")


def test_retry_cancelled_keeps_what_finished_and_settles_the_run(env, monkeypatch):
    settings, repo, _calls = env
    run_id = _partial_run(env, monkeypatch)

    def scan_many(items, *, cache_dir, trivy, settings, on_result, cancel, access=None):
        cancel.set()

    monkeypatch.setattr(service, "scan_many", scan_many)
    out = service.retry_failed(settings, run_id, repo=repo)
    assert out.status == "partial" and repo.get_run(run_id)["status"] == "partial"
    assert "1 still failing" in repo.run_warnings(run_id)[-1]["text"]


def test_retry_settles_the_run_when_the_scan_raises(env, monkeypatch):
    settings, repo, _calls = env
    run_id = _partial_run(env, monkeypatch)

    def scan_many(items, **kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(service, "scan_many", scan_many)
    with pytest.raises(KeyboardInterrupt):
        service.retry_failed(settings, run_id, repo=repo)
    assert repo.get_run(run_id)["status"] == "partial"
    assert repo.run_warnings(run_id)[-1]["text"].startswith("retried 1 failed image at ")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("missing", "no run"),
        ("ok", "has no failed images"),
        ("running", "is running"),
        ("trivy", "scanned with Trivy 0.1.0"),
    ],
)
def test_retry_refuses_a_run_it_cannot_retry(env, monkeypatch, change, message):
    settings, repo, calls = env
    run_id = _partial_run(env, monkeypatch)
    if change == "missing":
        run_id += 100
    elif change == "ok":
        repo.finish_run(run_id, "ok")
    else:
        column, value = ("status", "running") if change == "running" else ("trivy_version", "0.1.0")
        repo._conn.execute(f"UPDATE scan_run SET {column} = ? WHERE id = ?", (value, run_id))  # noqa: S608
        repo._conn.commit()
    with pytest.raises(service.RetryRefused, match=message):
        service.retry_failed(settings, run_id, repo=repo)
    assert calls == []


def _with_pull_secrets(repo, monkeypatch):
    real = repo.failed_items

    def failed_items(run_id, kinds=None):
        return [
            (rid, item.model_copy(update={"pull_secrets": [("default", "regcred")]}))
            for rid, item in real(run_id, kinds)
        ]

    monkeypatch.setattr(repo, "failed_items", failed_items)


def test_retry_loads_the_cluster_only_for_pull_secrets(env, monkeypatch):
    settings, repo, calls = env
    run_id = _partial_run(env, monkeypatch)
    loaded = []
    monkeypatch.setattr(service.kube_client, "load", lambda s: loaded.append(s) or FakeKubeApi())
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    _with_pull_secrets(repo, monkeypatch)
    service.retry_failed(settings, run_id, repo=repo)  # no namespaces configured
    assert loaded == []


def test_retry_loads_the_cluster_when_failed_images_have_pull_secrets(env, monkeypatch, tmp_path):
    settings, repo, calls = env
    run_id = _partial_run(env, monkeypatch)
    loaded, accesses = [], []
    api = FakeKubeApi()
    monkeypatch.setattr(service.kube_client, "load", lambda s: loaded.append(s) or api)

    def scan_many(items, *, access=None, **kw):
        accesses.append(access)
        _fake_scan(calls)(items, **kw)

    monkeypatch.setattr(service, "scan_many", scan_many)
    _with_pull_secrets(repo, monkeypatch)
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    retry = settings.model_copy(update={"secrets_dir": secrets, "pod_pull_secret_namespaces": ["default"]})
    service.retry_failed(retry, run_id, repo=repo)
    assert len(loaded) == 1 and len(accesses) == 1


def test_retry_does_not_load_the_cluster_when_no_failed_image_has_pull_secrets(env, monkeypatch, tmp_path):
    settings, repo, calls = env
    run_id = _partial_run(env, monkeypatch)
    loaded = []
    monkeypatch.setattr(service.kube_client, "load", lambda s: loaded.append(s) or FakeKubeApi())
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    retry = settings.model_copy(update={"secrets_dir": secrets, "pod_pull_secret_namespaces": ["default"]})
    service.retry_failed(retry, run_id, repo=repo)
    assert loaded == []


def test_cache_hit_still_stores_facts(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    service.run_scan(settings, api=_api(), repo=repo)
    out = service.run_scan(settings, api=_api(), repo=repo)  # every image comes from the cache
    rows = repo._conn.execute(
        "SELECT w.facts FROM workload w JOIN image_result r ON r.id = w.image_result_id "
        "WHERE r.run_id = ? AND r.status = 'cached'",
        (out.run_id,),
    ).fetchall()
    assert len(rows) == 2 and all(row["facts"] is not None for row in rows)
    sources = json.loads(
        repo._conn.execute("SELECT fact_sources FROM scan_run WHERE id = ?", (out.run_id,)).fetchone()[0]
    )
    assert sources["pod_security"] == "ok" and sources["services"] == "ok"


def test_run_scan_refreshes_feeds_first_and_survives_failure(env, monkeypatch):
    settings, repo, calls = env
    settings = settings.model_copy(update={"threat_feeds": True})
    progress: list = []
    refreshed: list[list[str]] = []

    def refresh_feeds(given):
        refreshed.append(_phases(progress))
        assert given is settings
        raise RuntimeError("the feed server is down")

    monkeypatch.setattr(service.threatintel, "refresh_feeds", refresh_feeds)
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    out = service.run_scan(settings, api=_api(), repo=repo, on_progress=progress.append)
    assert out.status == "ok" and _status(repo, out.run_id) == "ok"
    assert refreshed == [["threat-feeds"]]
    assert _phases(progress)[:2] == ["threat-feeds", "inventory"]


def test_run_scan_skips_the_feeds_when_they_are_off(env, monkeypatch):
    settings, repo, calls = env
    monkeypatch.setattr(service.threatintel, "refresh_feeds", lambda s: pytest.fail("the feeds are off"))
    monkeypatch.setattr(service, "scan_many", _fake_scan(calls))
    progress: list = []
    service.run_scan(settings, api=_api(), repo=repo, on_progress=progress.append)
    assert "threat-feeds" not in _phases(progress)
