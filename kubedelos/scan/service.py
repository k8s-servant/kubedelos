"""Orchestrates one scan run: inventory, cache lookup, the Trivy DB cache, parallel scans and persistence."""

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from kubedelos.config import Settings
from kubedelos.kube import client as kube_client
from kubedelos.kube.client import KubeApi
from kubedelos.kube.inventory import InventoryWarning, collect
from kubedelos.models import ImageResult, InventoryItem, is_valid_ref
from kubedelos.store import db
from kubedelos.store.repo import Repo
from kubedelos.trivy.binary import ensure_trivy
from kubedelos.trivy.cache import TrivyCache
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.trivy.runner import scan_many

CUSTOM_TRIVY = "custom"


@dataclass
class Progress:
    total: int
    done: int
    errors: int
    current: str | None


@dataclass
class ScanOutcome:
    run_id: int
    warnings: list[InventoryWarning]


def run_scan(
    settings: Settings,
    *,
    api: KubeApi | None = None,
    repo: Repo | None = None,
    trigger: str = "cli",
    on_progress: Callable[[Progress], None] = lambda p: None,
    cancel: threading.Event | None = None,
    cache_max_age: timedelta = timedelta(hours=24),
) -> ScanOutcome:
    """Scan every image in the cluster and record the run. Interrupts mark the run ``cancelled`` and re-raise."""
    api = api if api is not None else kube_client.load(settings)
    repo = repo if repo is not None else Repo(db.connect(settings.db_path))
    cancel = cancel if cancel is not None else threading.Event()

    items, warnings = collect(api, settings)
    # A user-supplied Trivy may be any version: record it as such and keep it away from the shared cache.
    run_id = repo.start_run(
        api.current_context(),
        trigger,
        CUSTOM_TRIVY if settings.trivy_path else TRIVY_VERSION,
        scan_level=settings.scan_level,
    )
    try:
        errors = _scan(settings, repo, run_id, items, on_progress, cancel, cache_max_age)
    except KeyboardInterrupt:
        cancel.set()
        repo.finish_run(run_id, "cancelled")
        raise
    except BaseException:
        repo.finish_run(run_id, "failed")
        raise
    repo.finish_run(run_id, "cancelled" if cancel.is_set() else "partial" if errors else "ok")
    return ScanOutcome(run_id=run_id, warnings=warnings)


def _scan(
    settings: Settings,
    repo: Repo,
    run_id: int,
    items: list[InventoryItem],
    on_progress: Callable[[Progress], None],
    cancel: threading.Event,
    cache_max_age: timedelta,
) -> int:
    """Persist cached and fresh results for ``items`` and return how many images errored."""
    total = len(items)
    done = errors = 0
    use_cache = settings.trivy_path is None  # results from an unpinned Trivy never enter or come from the cache
    on_progress(Progress(total=total, done=0, errors=0, current=None))

    def record(item: InventoryItem, result: ImageResult) -> None:
        nonlocal done, errors
        repo.add_result(run_id, item, result)
        done += 1
        errors += result.status == "error"
        on_progress(Progress(total=total, done=done, errors=errors, current=result.image.ref))

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
            repo.get_cached(item.image.key, item.platform, cache_max_age, scan_level=settings.scan_level)
            if use_cache
            else None
        )
        if cached is None:
            todo.append(item)
        else:
            record(item, cached.model_copy(update={"status": "cached", "image": item.image, "platform": item.platform}))

    by_key = {(i.image.key, i.platform): i for i in todo}

    def on_result(result: ImageResult) -> None:  # called on this thread by scan_many
        item = by_key[(result.image.key, result.platform)]
        record(item, result)
        if result.status == "ok" and use_cache:
            repo.put_cache(result.image.key, result.platform, result, scan_level=settings.scan_level)

    if not todo:  # everything cached or rejected: no Trivy needed
        return errors

    trivy = ensure_trivy(settings)
    with TrivyCache(trivy, settings.cache_dir, java_db="library" in settings.pkg_types) as cache:
        scan_many(todo, cache_dir=cache.dir, trivy=trivy, settings=settings, on_result=on_result, cancel=cancel)
    return errors
