"""Orchestrates one scan run: inventory, cache lookup, the Trivy DB cache, parallel scans and persistence.

``rescan=True`` scans every image again instead of taking the ones scanned in the last 24 hours from the result
cache, and stores the fresh results there for the scans after it.

``retry_failed`` scans a finished run's failed images again through the same steps, minus the inventory: it puts each
new result in place of its failure and recounts the run.
"""

import functools
import threading
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import timedelta

from kubedelos.config import Settings
from kubedelos.kube import client as kube_client
from kubedelos.kube.client import KubeApi
from kubedelos.kube.inventory import InventoryWarning, collect
from kubedelos.models import ImageRef, ImageResult, InventoryItem, is_valid_ref
from kubedelos.store import db, runlock
from kubedelos.store.repo import Repo
from kubedelos.trivy.binary import ensure_trivy
from kubedelos.trivy.cache import TrivyCache
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.trivy.runner import scan_many

CUSTOM_TRIVY = "custom"
PHASES = ("inventory", "scanning", "trivy-db", "saving")


@dataclass
class Progress:
    total: int
    done: int
    errors: int
    current: str | None
    phase: str = "scanning"  # one of PHASES; scanning repeats around trivy-db
    cached: int = 0  # cache hits among ``done``; the freshly scanned count is done - cached - errors
    run_id: int | None = None  # set once the run row exists, so a reader can list the run's failures while it runs


@dataclass
class ScanOutcome:
    run_id: int
    warnings: list[InventoryWarning]
    status: str  # the run's final status: ok, partial or cancelled (a failed run raises instead)


def run_scan(
    settings: Settings,
    *,
    api: KubeApi | None = None,
    repo: Repo | None = None,
    trigger: str = "cli",
    on_progress: Callable[[Progress], None] = lambda p: None,
    cancel: threading.Event | None = None,
    cache_max_age: timedelta = timedelta(hours=24),
    rescan: bool = False,
) -> ScanOutcome:
    """Scan every image in the cluster and record the run. Interrupts mark the run ``cancelled`` and re-raise."""
    api = api if api is not None else kube_client.load(settings)
    repo = repo if repo is not None else Repo(db.connect(settings.db_path))
    cancel = cancel if cancel is not None else threading.Event()

    on_progress(Progress(total=0, done=0, errors=0, current=None, phase="inventory"))
    items, warnings = collect(api, settings)
    # The lock exists before the run row, so the stale-run sweep never sees this run without a live owner.
    with runlock.hold(settings.data_dir) as owner:
        # A user-supplied Trivy may be any version: record it as such and keep it away from the shared cache.
        run_id = repo.start_run(
            api.current_context(),
            trigger,
            CUSTOM_TRIVY if settings.trivy_path else TRIVY_VERSION,
            scan_level=settings.scan_level,
            scope=settings.scope,
            owner=owner,
        )
        try:
            repo.add_warnings(run_id, warnings)
            save = functools.partial(repo.add_result, run_id)
            errors = _scan(settings, repo, run_id, items, save, on_progress, cancel, cache_max_age, rescan=rescan)
        except KeyboardInterrupt:
            cancel.set()
            repo.finish_run(run_id, "cancelled")
            raise
        except BaseException:
            repo.finish_run(run_id, "failed")
            raise
        status = "cancelled" if cancel.is_set() else "partial" if errors else "ok"
        repo.finish_run(run_id, status)
    return ScanOutcome(run_id=run_id, warnings=warnings, status=status)


class RetryRefused(Exception):
    """The run can't be retried: missing, not a finished partial run, or scanned with another Trivy."""


def retry_failed(
    settings: Settings,
    run_id: int,
    *,
    repo: Repo | None = None,
    on_progress: Callable[[Progress], None] = lambda p: None,
    cancel: threading.Event | None = None,
    cache_max_age: timedelta = timedelta(hours=24),
    kinds: Collection[str] | None = None,
) -> ScanOutcome:
    """Scan the failed images of the finished partial run ``run_id`` again (only those of ``kinds`` when given) and put
    the results in that run.

    The refs, platforms and workloads come from the database, so the cluster is not read. The run's package types
    apply; ``settings`` gives the time limit and parallelism. Each new result replaces its failure, and the run is
    recounted (``ok`` once nothing fails) and noted, also when the retry is cancelled or interrupted.
    """
    repo = repo if repo is not None else Repo(db.connect(settings.db_path))
    cancel = cancel if cancel is not None else threading.Event()
    run = repo.get_run(run_id)
    if run is None:
        raise RetryRefused(f"no run {run_id}")
    if run["status"] == "running":
        raise RetryRefused(f"run {run['number']} is running")
    trivy = CUSTOM_TRIVY if settings.trivy_path else TRIVY_VERSION
    if run["trivy_version"] != trivy:
        raise RetryRefused(f"run {run['number']} was scanned with Trivy {run['trivy_version']}, not {trivy}")
    failed = repo.failed_items(run_id, kinds) if run["status"] == "partial" else []
    if not failed:
        which = f" of kind {', '.join(sorted(kinds))}" if kinds is not None else ""
        raise RetryRefused(f"run {run['number']} has no failed images{which}")

    ids = {id(item): result_id for result_id, item in failed}
    run_settings = settings.model_copy(update={"pkg_types": tuple(run["pkg_types"].split(","))})

    def save(item: InventoryItem, result: ImageResult) -> None:
        repo.replace_result(ids[id(item)], result)

    try:
        _scan(run_settings, repo, run_id, [item for _, item in failed], save, on_progress, cancel, cache_max_age)
    finally:
        status = repo.settle_retry(run_id, [result_id for result_id, _ in failed], kinds=kinds)
    return ScanOutcome(run_id=run_id, warnings=[], status=status)


def _cacheable(image: ImageRef, result: ImageResult) -> bool:
    """Whether ``result`` may be cached for ``image``: by its digest, or by its local image ID when Trivy scanned
    exactly that image. Trivy pulls the tag from the registry, which may have been pushed again since the node pulled
    it; then the IDs differ and the result, though shown for this run, is not reused."""
    if image.digest:
        return True
    return image.image_id is not None and result.scanned_image_id == image.image_id


def _scan(
    settings: Settings,
    repo: Repo,
    run_id: int,
    items: list[InventoryItem],
    save: Callable[[InventoryItem, ImageResult], None],
    on_progress: Callable[[Progress], None],
    cancel: threading.Event,
    cache_max_age: timedelta,
    *,
    rescan: bool = False,
) -> int:
    """Hand cached and fresh results for ``items`` to ``save`` and return how many images errored. With ``rescan``
    nothing comes from the cache, but fresh results still go into it."""
    total = len(items)
    done = errors = cached_count = 0
    use_cache = settings.trivy_path is None  # results from an unpinned Trivy never enter or come from the cache

    def emit(phase: str, current: str | None = None) -> None:
        on_progress(Progress(total, done, errors, current, phase=phase, cached=cached_count, run_id=run_id))

    emit("scanning")

    def record(item: InventoryItem, result: ImageResult) -> None:
        nonlocal done, errors, cached_count
        save(item, result)
        done += 1
        errors += result.status == "error"
        cached_count += result.status == "cached"
        emit("scanning", result.image.ref)

    todo: list[InventoryItem] = []
    for item in items:
        if not is_valid_ref(item.image.ref):  # never hand a malformed, cluster-supplied ref to Trivy
            record(
                item,
                ImageResult(
                    image=item.image,
                    platform=item.platform,
                    status="error",
                    error_kind="unknown",
                    error="invalid image reference",
                ),
            )
            continue
        cached = (
            repo.get_cached(item.image.cache_key, item.platform, cache_max_age, scan_level=settings.scan_level)
            if use_cache and not rescan and item.image.cache_key
            else None
        )
        if cached is None:
            todo.append(item)
        else:
            update = {"status": "cached", "image": item.image, "platform": item.platform, "duration_s": None}
            record(item, cached.model_copy(update=update))

    by_key = {(i.image.key, i.platform): i for i in todo}

    def on_result(result: ImageResult) -> None:  # called on this thread by scan_many
        item = by_key[(result.image.key, result.platform)]
        record(item, result)
        if result.status == "ok" and use_cache and _cacheable(item.image, result):
            repo.put_cache(item.image.cache_key, result.platform, result, scan_level=settings.scan_level)

    # Nothing to scan (everything was cached or rejected), or cancelled already: neither fetch Trivy nor wait for the
    # DB, since neither download nor the DB lock wait would notice the cancel.
    if todo and not cancel.is_set():
        emit("trivy-db")
        trivy = ensure_trivy(settings)
        if not cancel.is_set():  # a shutdown during the binary download: no DB download either
            with TrivyCache(trivy, settings.cache_dir, java_db="library" in settings.pkg_types) as cache:
                emit("scanning")
                scan_many(todo, cache_dir=cache.dir, trivy=trivy, settings=settings, on_result=on_result, cancel=cancel)
    emit("saving")
    return errors
