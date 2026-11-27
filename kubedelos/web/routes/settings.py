"""The Settings page (``GET /settings``): every setting in effect, read-only, and where its value came from.

Each ``Settings`` field is listed with its value and its source (``config.setting_sources``): a flag given to
``kubedelos ui``, its ``KUBEDELOS_*`` variable, or the default. The page answers "why did the scan do that?"; the Scans
form can still change the scope, parallel images and package types for one scan. Below the table: the database file,
the data and cache directories, the Trivy in use, the log level and when each threat feed (CISA KEV, EPSS) was last
fetched.

The Registries card says which cloud identity and which mounted Docker config Secrets (by name) the scans use, and
which namespaces' pull secrets are read. In ``kubedelos serve`` it has a form, ``POST /settings/registry-test``, that
scans one image with the cloud identity and the mounted Docker configs, one test at a time. There is no pod, so
pod pull secrets are not used: an image only a pod pull secret can open fails here and works in a scan.
No token is shown or read for display: ``Settings`` holds none (a test keeps it that way), and a failed test
shows Trivy's redacted cause only.

In ``kubedelos ui`` the page ends with "Delete this cluster's history": ``POST /settings/forget`` deletes the shown
cluster's runs (and, when ticked, its risk acceptances) once its name is typed to confirm, and refuses while a scan of
it runs. ``serve`` has no such form: there the history is shared, and anyone who can write could wipe it.
"""

import logging
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from kubedelos.config import Settings, setting_sources
from kubedelos.hints import login_hint
from kubedelos.kube.inventory import DEFAULT_PLATFORM, parse_user_ref
from kubedelos.models import InventoryItem, registry_host
from kubedelos.registry import dockerconfig
from kubedelos.registry.access import RegistryAccess
from kubedelos.store import intel
from kubedelos.store.clusters import ClusterBusy, forget_cluster, history_counts
from kubedelos.store.queries import newest_run, run_registry_hosts
from kubedelos.trivy.binary import ensure_trivy
from kubedelos.trivy.cache import TrivyCache
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.trivy.runner import error_cause, scan_image
from kubedelos.web.jobs import ACTIVE
from kubedelos.web.pages import cluster_of, link, open_db, open_db_rw, plural, render, scannable_contexts, shown_context

router = APIRouter()
logger = logging.getLogger("kubedelos.web")

FLAGS = {"context": "--context", "kubeconfig": "--kubeconfig"}  # the settings `kubedelos ui` takes as flags
FALLBACKS = {  # what an unset setting means
    "kubeconfig": "$KUBECONFIG or ~/.kube/config",
    "context": "the kubeconfig's current context",
    "trivy_path": "the pinned Trivy",
}
EMPTY_LISTS = {
    "namespaces": "none (every namespace)",
    "exclude_namespaces": "none",
    "exclude_images": "none",
}


# The registry hosts Trivy uses the cloud identity for (checked in Trivy v0.76.1): (shown text, anchored pattern). One
# table feeds the card and the Test box's host check.
_LABEL = r"[a-z0-9]+(?:-[a-z0-9]+)*"
# The start of Trivy's ECR endpoint regex (pkg/fanal/image/registry/ecr/ecr.go): the dkr[.-]ecr and ecr-fips forms.
_ECR = r"[^.]+\.dkr[.-]ecr(?:-fips)?\.[^.]+\."
CLOUD_HOSTS = {
    "azure": [("*.azurecr.io", rf"{_LABEL}\.azurecr\.io"), ("*.azurecr.cn", rf"{_LABEL}\.azurecr\.cn")],
    "gcp": [
        ("gcr.io", r"gcr\.io"),
        ("*.gcr.io", rf"{_LABEL}\.gcr\.io"),
        ("*-docker.pkg.dev", rf"{_LABEL}-docker\.pkg\.dev"),
    ],
    "aws": [
        (f"<account>.dkr.ecr.<region>.{shown}", rf"{_ECR}{pattern}")
        for shown, pattern in [
            ("amazonaws.com (also ecr-fips)", r"amazonaws\.com"),
            ("amazonaws.com.cn", r"amazonaws\.com\.cn"),
            ("sc2s.sgov.gov", r"sc2s\.sgov\.gov"),
            ("c2s.ic.gov", r"c2s\.ic\.gov"),
            ("on.aws (as <account>.dkr-ecr.<region>.on.aws)", r"on\.aws"),
        ]
    ],
}
DOCS = "https://github.com/k8s-servant/kubedelos/blob/main/docs/registries/"
TEST_TIMEOUT_S = 120
_LOCK = threading.Lock()  # one registry test at a time: each runs a Trivy
_MAX_BODY = 64 * 1024


def docs_page(host: str) -> str:
    """The docs page for an authentication failure on ``host``: its cloud's, else the pull secrets one."""
    name = host.split(":", 1)[0]
    if name.endswith((".azurecr.io", ".azurecr.cn")):
        page = "acr"
    elif name == "gcr.io" or name.endswith((".gcr.io", "-docker.pkg.dev")):
        page = "gar"
    elif any(re.fullmatch(pattern, name) for _, pattern in CLOUD_HOSTS["aws"]):
        page = "ecr"
    else:
        page = "pull-secrets"
    return f"{DOCS}{page}.md"


def _host_source(request: Request, host: str) -> str | None:
    """Why the Test box may contact ``host``: ``mounted`` (a mounted config names it), ``cloud`` (the provider's) or
    ``run`` (the cluster's newest run has images from it); ``None`` refuses. Anything else could point Trivy at an
    internal address."""
    settings: Settings = request.app.state.settings
    host = host.lower().rstrip(".")
    if host in dockerconfig.load_mounted(settings.docker_configs):
        return "mounted"
    if any(re.fullmatch(pattern, host) for _, pattern in CLOUD_HOSTS.get(settings.cloud_provider, [])):
        return "cloud"
    with open_db(request) as conn:
        run = newest_run(conn, cluster_of(request, conn, request.app.state.context), cluster_scope=False)
        if run is not None and host in {h.lower().rstrip(".") for h in run_registry_hosts(conn, run.id)}:
            return "run"
    return None


def _registries(settings: Settings, *, serve: bool) -> dict:
    """What the Registries card shows; names and namespaces only, never a file's contents."""
    provider = settings.cloud_provider
    if provider == "none":
        identity = "not configured" if serve else "none: your own cloud logins apply"
    else:
        identity = f"{provider}: {settings.cloud_identity or 'identity not set'}"
    return {
        "identity": identity,
        "hosts": [shown for shown, _ in CLOUD_HOSTS.get(provider, [])],
        "secrets": [path.parent.name for path in settings.docker_configs],
        "namespaces": ", ".join(settings.pod_pull_secret_namespaces) or "off",
    }


def shown_value(field: str, value: object) -> str:
    """A setting's value as the page shows it: lists comma-joined, an unset value named as such."""
    if isinstance(value, bool):
        return "true" if value else "false"  # as KUBEDELOS_* takes it
    if isinstance(value, list | tuple):
        return ", ".join(str(v) for v in value) if value else EMPTY_LISTS.get(field, "none")
    if value is None:
        return f"not set: {FALLBACKS[field]}" if field in FALLBACKS else "not set"
    return str(value)


def fetched_text(fetched: datetime | None) -> str:
    """When a threat feed was last fetched, in UTC, or that it never was."""
    return fetched.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if fetched is not None else "never fetched"


def log_level(raw: str | None) -> str:
    """``KUBEDELOS_LOG_LEVEL`` as ``kubedelos ui`` reads it: only ``info`` turns the access log on."""
    if not raw:
        return "default (no access log)"
    if raw.lower() == "info":
        return "info (an access line per request)"
    return f"{raw} (no effect: only info is used)"


def _rows(settings: Settings, flags: frozenset[str]) -> list[dict]:
    sources = setting_sources(settings, flags=flags, environ=os.environ)
    prefix = settings.model_config.get("env_prefix", "")
    return [
        {
            "field": field,
            "variable": (prefix + field).upper(),
            "flag": FLAGS.get(field),
            "value": shown_value(field, getattr(settings, field)),
            "source": sources[field],
        }
        for field in type(settings).model_fields
    ]


@router.get("/settings", response_class=HTMLResponse)
def settings(request: Request) -> HTMLResponse:
    current: Settings = request.app.state.settings
    with open_db(request) as conn:
        shown_context(request, conn)
        cluster = request.state.cluster
        newest = newest_run(conn, cluster, cluster_scope=False)  # the sidebar's "scanned N ago"
        fetched = intel.feeds(conn)
        runs, accepted = history_counts(conn, cluster)
    trivy = f"custom: {Path(current.trivy_path)}" if current.trivy_path else f"v{TRIVY_VERSION} (pinned)"
    ctx = {
        "now": request.app.state.clock(),
        "run": newest,
        "registries": _registries(current, serve=request.app.state.serve),
        "rows": _rows(current, request.app.state.flags),
        "files": [
            ("Database file", str(current.db_path)),
            ("Data directory", str(current.data_dir)),
            ("Cache directory", str(current.cache_dir)),
            ("Trivy", trivy),
            ("Log level", log_level(os.environ.get("KUBEDELOS_LOG_LEVEL"))),
            ("CISA KEV last fetched", fetched_text(fetched.get("kev"))),
            ("EPSS last fetched", fetched_text(fetched.get("epss"))),
        ],
        "history": None if request.app.state.serve else _history_text(runs, accepted),
        "deleted": _deleted_text(request),
    }
    return render(request, "settings.html", ctx)


def _counted(runs: int, accepted: int) -> str:
    """What was deleted: the acceptances only when there were any, since they go only when ticked."""
    text = f"{runs} {plural(runs, 'run')}"
    return text + (f" and {accepted} risk {plural(accepted, 'acceptance')}" if accepted else "")


def _history_text(runs: int, accepted: int) -> str:
    """What the cluster holds, both counts always, so "0 risk acceptances" says the box would delete nothing."""
    return f"{runs} {plural(runs, 'run')} and {accepted} risk {plural(accepted, 'acceptance')}"


def _deleted_text(request: Request) -> str | None:
    """The notice after a delete, from the redirect's ``deleted`` and ``acceptances`` counts."""
    params = request.query_params
    try:
        runs, accepted = int(params["deleted"]), int(params.get("acceptances", "0"))
    except (KeyError, ValueError):
        return None
    if runs < 0 or accepted < 0:
        return None
    return f"Deleted {_counted(runs, accepted)} of this cluster."


@router.post("/settings/forget")
async def forget(request: Request) -> Response:
    if request.app.state.serve:
        return Response(status_code=404)
    body = await request.body()  # the CSRF guard has read it already
    return await run_in_threadpool(_forget, request, body)


def _forget(request: Request, body: bytes) -> Response:
    try:
        fields = parse_qs(body[:_MAX_BODY].decode(), keep_blank_values=True, max_num_fields=100, errors="strict")
    except ValueError:
        return render(request, "error.html", {"title": "Bad request", "message": "the form could not be read"}, 400)
    with open_db(request) as conn:
        context = shown_context(request, conn, wanted=fields.get("context", [""])[0] or request.app.state.context)
    cluster = request.state.cluster
    if fields.get("confirm", [""])[0].strip() != context:
        message = f"Type {context} to confirm: nothing was deleted."
        return render(request, "error.html", {"title": "Not confirmed", "message": message}, 400)
    # The UI's own job counts before it has a run row. A scan that starts after this check can't hurt the history:
    # its run row needs the write lock forget_cluster holds, so it lands after the delete, as the first run of a fresh
    # history. One that wrote its row first is "running", and forget_cluster refuses then.
    job = request.app.state.scans.view()
    busy = "a scan of this cluster is running: wait for it to finish or cancel it, then try again"
    if job is not None and job.state in ACTIVE:
        with open_db(request) as conn:
            if cluster_of(request, conn, job.context) == cluster:
                return render(request, "error.html", {"title": "Not now", "message": busy}, 409)
    try:
        with open_db_rw(request) as conn:
            done = forget_cluster(conn, cluster, acceptances=fields.get("acceptances", [""])[0] == "on")
    except ClusterBusy:  # a scan from another kubedelos process
        return render(request, "error.html", {"title": "Not now", "message": busy}, 409)
    # A cluster known only from its history is gone with it: go back to the startup context then.
    request.state.context = context if context in scannable_contexts(request) else request.app.state.context
    return RedirectResponse(
        link(request, "/settings", deleted=done.runs, acceptances=done.acceptances), status_code=303
    )


def _result(request: Request, text: str, **extra: object) -> HTMLResponse:
    """The result box's content. Always 200: htmx swaps no 4xx or 5xx, and the text says what went wrong."""
    return render(request, "partials/registry_test.html", {"text": text, **extra})


@router.post("/settings/registry-test", response_class=HTMLResponse)
async def registry_test(request: Request) -> Response:
    if not request.app.state.serve:
        return Response(status_code=404)
    body = await request.body()  # the CSRF guard has read it already
    return await run_in_threadpool(_registry_test, request, body)


def _registry_test(request: Request, body: bytes) -> Response:
    try:
        fields = parse_qs(body[:_MAX_BODY].decode(), keep_blank_values=True, max_num_fields=100, errors="strict")
    except ValueError:
        return _result(request, "error: the form could not be read", failed=True)
    image = fields.get("image", [""])[0].strip()
    ref = parse_user_ref(image)
    if ref is None:
        shown = "".join(ch if ch.isprintable() else "?" for ch in image)[:200]
        return _result(request, f"error: invalid image reference: {shown}", failed=True)
    host = registry_host(ref)
    source = _host_source(request, host)
    if source is None:
        return _result(
            request,
            f"error: {host} is not a registry this instance uses: test an image from a configured registry or one the"
            " cluster runs",
            failed=True,
        )
    if not _LOCK.acquire(blocking=False):
        return _result(request, "A test is already running", failed=True)
    try:
        settings: Settings = request.app.state.settings
        try:
            trivy = ensure_trivy(settings)
            with (
                TrivyCache(trivy, settings.cache_dir, java_db=False) as cache,
                RegistryAccess(settings).for_item(InventoryItem(image=ref, platform=DEFAULT_PLATFORM)) as access,
            ):
                result = scan_image(
                    trivy,
                    ref,
                    DEFAULT_PLATFORM,
                    min(settings.scan_timeout_s, TEST_TIMEOUT_S),
                    cache_dir=cache.dir,
                    pkg_types=("os",),
                    docker_config=access.docker_config,
                )
        except Exception as exc:  # the test must answer, whatever went wrong
            logger.warning("registry test of %s failed: %s", ref.ref, error_cause(str(exc)), exc_info=False)
            # A RuntimeError is Trivy's own (its DB or cache); error_cause redacts it. Any other shows only its type.
            why = error_cause(str(exc)) if isinstance(exc, RuntimeError) else type(exc).__name__
            return _result(request, f"error: the test could not run: {why}", failed=True)
    finally:
        _LOCK.release()
    if result.status != "error":
        return _result(request, f"ok: {ref.ref} is readable")
    cause = error_cause(result.error)
    if result.error_kind == "auth":
        return _result(
            request,
            f"error: {ref.ref}: auth: {cause}",
            failed=True,
            hint=login_hint(host),
            note="pod pull secrets are not tried here" if source == "run" else None,
            docs=docs_page(host),
        )
    return _result(request, f"error: {ref.ref}: {result.error_kind}: {cause}", failed=True)
