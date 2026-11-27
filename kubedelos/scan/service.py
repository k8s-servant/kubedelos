"""Orchestrates one scan run: the threat feeds (at most once a day), inventory, cache lookup, the Trivy DB cache,
parallel scans and persistence.

``rescan=True`` scans every image again instead of taking the ones scanned in the last 24 hours from the result
cache, and stores the fresh results there for the scans after it.

A run is recorded before the cluster is listed, so a listing that fails leaves a ``failed`` run with the reason. A scope
that selects no namespace, or whose every namespace refuses the pod list, fails the run too (``EmptyScope``): an empty
run would read as "no findings". A namespace that is listed and runs no pods is an ``ok`` run with no images.

``retry_failed`` scans a finished run's failed images again through the same steps, minus the inventory: it puts each
new result in place of its failure and recounts the run.
"""

import functools
import logging
import threading
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from kubernetes.client.exceptions import ApiException

from kubedelos import threatintel
from kubedelos.config import Settings
from kubedelos.kube import client as kube_client
from kubedelos.kube.client import KubeApi
from kubedelos.kube.inventory import Inventory, InventoryWarning, collect_inventory
from kubedelos.models import ImageRef, ImageResult, InventoryItem, is_valid_ref
from kubedelos.registry.access import RegistryAccess
from kubedelos.store import db, runlock
from kubedelos.store.repo import NOTHING_SCANNED, TRIVY_DB_NOTE_PREFIX, Repo
from kubedelos.trivy.binary import ensure_trivy
from kubedelos.trivy.cache import TrivyCache, db_info, db_is_stale
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.trivy.runner import scan_many

CUSTOM_TRIVY = "custom"
PHASES = ("threat-feeds", "inventory", "scanning", "trivy-db", "saving")

logger = logging.getLogger(__name__)


@dataclass
class Progress:
    total: int
    done: int
    errors: int
    current: str | None
    phase: str = "scanning"  # one of PHASES; scanning repeats around trivy-db
    cached: int = 0  # cache hits among ``done``; the freshly scanned count is done - cached - errors
    run_id: int | None = None  # set once the run row exists, so a reader can list the run's failures while it runs


class EmptyScope(RuntimeError):
    """The scope selected nothing that could be listed, so the run would hold no images while the cluster may have
    some."""


def _empty_scope(inventory: Inventory) -> str | None:
    """Why ``inventory`` must fail the run, or None."""
    if not inventory.namespaces_selected:
        return "no namespace matched the scope"
    if not inventory.namespaces_listed:
        return f"every namespace in scope was forbidden ({inventory.namespaces_selected})"
    return None


def _nothing_scanned(why: str) -> InventoryWarning:
    return InventoryWarning(f"{why}{NOTHING_SCANNED}", coverage=False)


def _listing_failure(exc: Exception) -> str:
    """The reason a listing failed, as stored on the run."""
    if isinstance(exc, ApiException):  # its str() dumps the response headers and body: keep neither
        return f"HTTP {exc.status} {exc.reason}"
    return str(exc) or type(exc).__name__


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
    requested_by: str | None = None,
) -> ScanOutcome:
    """Scan every image in the cluster and record the run. Interrupts mark the run ``cancelled`` and re-raise."""
    api = api if api is not None else kube_client.load(settings)
    repo = repo if repo is not None else Repo(db.connect(settings.db_path))
    cancel = cancel if cancel is not None else threading.Event()

    if settings.threat_feeds:
        on_progress(Progress(total=0, done=0, errors=0, current=None, phase="threat-feeds"))
        _refresh_feeds(settings, cancel)
    # The lock exists before the run row, so the stale-run sweep never sees this run without a live owner.
    with runlock.hold(settings.data_dir) as owner:
        # A user-supplied Trivy may be any version: record it as such and keep it away from the shared cache.
        context = settings.context or settings.cluster_name or api.current_context()
        run_id = repo.start_run(
            settings.cluster_name or context,
            context,
            trigger,
            CUSTOM_TRIVY if settings.trivy_path else TRIVY_VERSION,
            scan_level=settings.scan_level,
            scope=settings.scope,
            owner=owner,
            requested_by=requested_by,
        )
        try:
            on_progress(Progress(total=0, done=0, errors=0, current=None, phase="inventory"))
            try:
                inventory = collect_inventory(api, settings)
            except Exception as exc:
                repo.add_warnings(run_id, [_nothing_scanned(f"listing the cluster failed: {_listing_failure(exc)}")])
                raise
            repo.add_warnings(run_id, inventory.warnings)
            repo.set_fact_sources(run_id, inventory.fact_sources)
            if why := _empty_scope(inventory):
                repo.add_warnings(run_id, [_nothing_scanned(why)])
                raise EmptyScope(why)
            items = inventory.items
            save = functools.partial(repo.add_result, run_id)
            access = RegistryAccess(settings, api)  # per run, so the Secret contents it read go with the run
            errors = _scan(
                settings, repo, run_id, items, save, on_progress, cancel, cache_max_age, access, rescan=rescan
            )
        except KeyboardInterrupt:
            cancel.set()
            repo.finish_run(run_id, "cancelled")
            raise
        except BaseException:
            repo.finish_run(run_id, "failed")
            raise
        status = "cancelled" if cancel.is_set() else "partial" if errors else "ok"
        repo.finish_run(run_id, status)
    return ScanOutcome(run_id=run_id, warnings=inventory.warnings, status=status)


_CANCEL_POLL_S = 0.2


def _refresh_feeds(settings: Settings, cancel: threading.Event) -> None:
    """Refresh the threat feeds (at most once a day, backing off after a failure) on a daemon thread, and wait for it
    unless the scan is cancelled meanwhile: a download on a network that drops packets waits out its timeouts, and a
    cancel must not wait with it. A refresh left running finishes or fails on its own; it never fails the scan."""

    def refresh() -> None:
        try:
            threatintel.refresh_feeds(settings)  # logs and keeps the old copy on failure
        except Exception as exc:
            logger.warning("threat feeds not updated: %s", exc)

    thread = threading.Thread(target=refresh, name="kubedelos-threat-feeds", daemon=True)
    thread.start()
    while thread.is_alive() and not cancel.wait(_CANCEL_POLL_S):
        thread.join(_CANCEL_POLL_S)


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

    The refs, platforms and workloads come from the database, so the cluster is not read, except for the pull secrets
    of failed images: when ``pod_pull_secret_namespaces`` is set and one of them names any, the Secrets are read
    again. The run's package types apply; ``settings`` gives the time limit and parallelism. Each new result replaces
    its failure, and the run is recounted (``ok`` once nothing fails) and noted, also when the retry is cancelled or
    interrupted.
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

    items = [item for _, item in failed]
    api = (
        kube_client.load(settings)
        if settings.pod_pull_secret_namespaces and any(i.pull_secrets for i in items)
        else None
    )
    try:
        _scan(
            run_settings, repo, run_id, items, save, on_progress, cancel, cache_max_age, RegistryAccess(settings, api)
        )
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
    access: RegistryAccess,
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
                _record_trivy_db(repo, run_id, settings, updated=cache.updated)
                emit("scanning")
                scan_many(
                    todo,
                    cache_dir=cache.dir,
                    trivy=trivy,
                    settings=settings,
                    on_result=on_result,
                    cancel=cancel,
                    access=access,
                )
    emit("saving")
    return errors


def _record_trivy_db(repo: Repo, run_id: int, settings: Settings, *, updated: bool) -> None:
    """Record when the vulnerability DB this run scans with was built and, when it or the Java DB the run reads for
    library packages is out of date, one note saying which and why (and log it). An old DB never fails the scan:
    findings from it are still findings, only maybe not all of them."""
    now = datetime.now(UTC)
    info = db_info(settings.cache_dir, "db")
    dbs = [("", info)]
    if "library" in settings.pkg_types:
        dbs.append(("for Java libraries ", db_info(settings.cache_dir, "java-db")))
    stale = [
        f"{label}built {db.updated_at.astimezone(UTC):%Y-%m-%d %H:%M} UTC" for label, db in dbs if db_is_stale(db, now)
    ]
    note = None
    if stale:
        cause = (
            "the download did not bring a newer one"
            if updated
            else "another kubedelos run was using the DB cache, so this run did not update it"
        )
        verb = "is" if len(stale) == 1 else "are"
        note = f"{TRIVY_DB_NOTE_PREFIX}{' and Trivy DB '.join(stale)} {verb} out of date: {cause}"
        logger.warning("%s", note)
    repo.set_trivy_db(run_id, info.updated_at if info else None, note)
