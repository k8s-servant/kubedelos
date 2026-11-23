"""The FastAPI applications behind ``kubedelos ui`` and ``kubedelos serve``.

``create_app`` (the laptop UI) and ``create_serve_app`` (the in-cluster UI, optionally read-only) share ``_build``,
which wires the templates, the static files, the exception handlers and the page routers; each then adds its own
security middleware.
The helpers the pages and the security middleware share (``open_db``, ``render``) live in ``kubedelos.web.pages``, so
that this module can import the routes at the top level without an import cycle. The laptop app owns one
``ScanRunner`` for the scans page; the serve app is handed its runner, queue worker and sweeper already built, since
the worker, not a route, starts every scan there. ``server.serve`` stops them when the server stops.
"""

import contextlib
import hashlib
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import jinja2
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from kubedelos.analytics import ago, describe_pkg_types, describe_scope, is_stale
from kubedelos.config import Settings
from kubedelos.kube import client as kube_client
from kubedelos.scheduler import Sweeper
from kubedelos.web.identity import identity
from kubedelos.web.jobs import ScanRunner
from kubedelos.web.pages import UnknownContext, open_db, plural, render, shown_context
from kubedelos.web.routes import (
    about,
    accepted,
    dashboard,
    diff,
    failed,
    findings,
    health,
    namespaces,
    reports,
    scans,
    times,
)
from kubedelos.web.routes import settings as settings_page
from kubedelos.web.security import READ_ONLY_NOTICE, Guard, ServeGuard, install, install_serve
from kubedelos.web.worker import QueueWorker

_HERE = Path(__file__).parent


def _utcnow() -> datetime:
    return datetime.now(UTC)


def safe_url(url: object) -> str | None:
    """``url`` if it is an absolute http(s) URL, else None, so a CVE link can never be ``javascript:`` or ``data:``."""
    if not isinstance(url, str):
        return None
    try:
        # urlsplit strips the leading whitespace and the tabs and newlines a browser ignores, so it sees the same scheme.
        parts = urlsplit(url)
    except ValueError:
        return None
    return url if parts.scheme.lower() in ("http", "https") and parts.netloc else None


def finished_text(run: Any, now: datetime) -> str:
    """When ``run`` finished, as the run chips and the sidebar say it: "N ago", or "at an unknown time"."""
    return ago(run.finished_at, now) if run.finished_at else "at an unknown time"


def static_url(name: str) -> str:
    """``/static/<name>`` with the file's content hash as ``?v=``: a new release changes the URL, so a browser never
    pairs new markup with a stylesheet or script it cached from an older one. The files ship with the package."""
    if name not in _STATIC_VERSIONS:
        _STATIC_VERSIONS[name] = hashlib.sha256((_HERE / "static" / name).read_bytes()).hexdigest()[:12]
    return f"/static/{name}?v={_STATIC_VERSIONS[name]}"


_STATIC_VERSIONS: dict[str, str] = {}


def _templates(
    csrf_token: Callable[[Request], str], can_write: Callable[[Request], bool], *, serve: bool
) -> Jinja2Templates:
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(_HERE / "templates"), autoescape=True)
    env.globals["csrf_token"] = csrf_token
    env.globals["can_write"] = can_write  # whether the page offers its forms: False only in read-only serve
    env.globals["serve"] = serve
    env.globals["read_only_notice"] = READ_ONLY_NOTICE  # shown by base.html wherever can_write is False
    env.filters["safe_url"] = safe_url
    env.filters["plural"] = plural
    env.globals.update(
        ago=ago,
        describe_scope=describe_scope,
        describe_pkg_types=describe_pkg_types,
        finished_text=finished_text,
        is_stale=is_stale,
        static_url=static_url,
    )
    return Jinja2Templates(env=env)


def _build(
    settings: Settings,
    *,
    context: str,
    list_contexts: Callable[[], list[str]],
    cluster_keys: Callable[[], dict[str, str]],
    clock: Callable[[], datetime],
    csrf_token: Callable[[Request], str],
    can_write: Callable[[Request], bool],
    serve: bool,
    flags: frozenset[str] = frozenset(),
) -> FastAPI:
    """The app both UIs share: state, templates, static files, exception handlers and routers, without middleware."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.context = context
    app.state.flags = flags
    app.state.list_contexts = list_contexts
    app.state.cluster_keys = cluster_keys
    app.state.clock = clock
    app.state.serve = serve
    app.state.templates = _templates(csrf_token, can_write, serve=serve)
    app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")

    @app.exception_handler(RequestValidationError)
    async def invalid_parameter(request: Request, exc: RequestValidationError) -> HTMLResponse:
        errors = exc.errors()
        loc = errors[0].get("loc", ()) if errors else ()
        # ("query", name, ...): the parameter's name, not the union member a typed parameter adds after it.
        name = loc[1] if len(loc) > 1 else (loc[0] if loc else "request")
        # Validation fails before the route resolves ``?context=``, so resolve it here: the page keeps its cluster.
        with contextlib.suppress(UnknownContext, sqlite3.Error), open_db(request) as conn:
            shown_context(request, conn)
        return render(request, "error.html", {"title": "Bad request", "message": f"invalid parameter: {name}"}, 400)

    @app.exception_handler(UnknownContext)
    async def unknown_context(request: Request, exc: UnknownContext) -> HTMLResponse:
        message = f"no context named {exc.name} in your kubeconfig or the scan history"
        return render(request, "error.html", {"title": "Unknown context", "message": message}, 404)

    app.include_router(dashboard.router)
    app.include_router(findings.router)
    app.include_router(namespaces.router)
    app.include_router(diff.router)
    app.include_router(reports.router)
    app.include_router(accepted.router)
    app.include_router(failed.router)
    app.include_router(times.router)
    app.include_router(scans.router)
    app.include_router(settings_page.router)
    app.include_router(about.router)
    app.include_router(health.router)
    return app


def create_app(
    settings: Settings,
    *,
    context: str,
    token: str,
    port: int,
    clock: Callable[[], datetime] = _utcnow,
    list_contexts: Callable[[], list[str]] | None = None,
    cluster_keys: Callable[[], dict[str, str]] | None = None,
    flags: frozenset[str] = frozenset(),
) -> FastAPI:
    """Build the UI. ``context`` is the one shown by default, ``token`` the startup secret, ``port`` what the Host
    check expects, ``list_contexts`` lists the kubeconfig's contexts and ``cluster_keys`` maps each to its cluster key
    (both read on each page, and the keys again when a scan starts), and ``flags`` names the settings given as flags
    to ``kubedelos ui`` (for the Settings page)."""
    guard = Guard(token, port)

    def csrf_token(request: Request) -> str:
        sid = request.cookies.get(guard.cookie_name)
        return guard.csrf_token(sid) if guard.valid_session(sid) else ""

    keys = cluster_keys or (lambda: kube_client.cluster_keys(settings))

    def cluster_of(target: str) -> str:
        """The cluster a scan through ``target`` belongs to, as the kubeconfig has it when the scan starts."""
        return keys().get(target, target)

    app = _build(
        settings,
        context=context,
        list_contexts=list_contexts or (lambda: kube_client.list_contexts(settings)),
        cluster_keys=keys,
        clock=clock,
        csrf_token=csrf_token,
        can_write=lambda request: True,
        serve=False,
        flags=flags,
    )
    app.state.guard = guard
    app.state.scans = ScanRunner(settings, context, clock=clock, cluster_of=cluster_of)
    install(app, guard)
    return app


def create_serve_app(
    settings: Settings,
    *,
    runner: ScanRunner,
    worker: QueueWorker,
    sweeper: Sweeper,
    clock: Callable[[], datetime] = _utcnow,
) -> FastAPI:
    """Build the UI of ``kubedelos serve``. Its one context is ``settings.cluster_name``; ``runner`` (built with
    ``fixed_cluster=True``) runs what ``worker`` takes off the queue, and ``sweeper`` queues the scheduled sweeps.
    The forms carry a CSRF token bound to the request's cookie and signed-in name; read-only mode hides them."""
    name = settings.cluster_name or ""
    guard = ServeGuard(
        read_only=settings.read_only,
        trust_proxy_headers=settings.trust_proxy_headers,
        identity_header=settings.identity_header,
        secure_cookies=settings.secure_cookies,
    )

    def csrf_token(request: Request) -> str:
        return guard.csrf_token(request.state.csrf_cookie, identity(request))

    app = _build(
        settings,
        context=name,
        list_contexts=lambda: [name],
        cluster_keys=lambda: {name: name},  # the one cluster serve scans is keyed by its name
        clock=clock,
        csrf_token=csrf_token,
        can_write=lambda request: not guard.read_only,
        serve=True,
    )
    app.state.serve_guard = guard
    app.state.scans = runner
    app.state.worker = worker
    app.state.sweeper = sweeper
    install_serve(app, settings.allowed_hosts, guard)
    return app
