"""The FastAPI application behind ``kubedelos ui``.

``create_app`` wires the security middleware, the templates, the static files and the page routers. The helpers the
pages and the security middleware share (``open_db``, ``render``) live in ``kubedelos.web.pages``, so that this module
can import the routes at the top level without an import cycle. The app owns one ``ScanRunner`` for the scans page;
``server.serve`` shuts it down when the server stops.
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
from kubedelos.web.jobs import ScanRunner
from kubedelos.web.pages import UnknownContext, open_db, plural, render, shown_context
from kubedelos.web.routes import accepted, dashboard, failed, findings, namespaces, scans
from kubedelos.web.security import Guard, install

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


def _templates(guard: Guard) -> Jinja2Templates:
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(_HERE / "templates"), autoescape=True)

    def csrf_token(request: Request) -> str:
        sid = request.cookies.get(guard.cookie_name)
        return guard.csrf_token(sid) if guard.valid_session(sid) else ""

    env.globals["csrf_token"] = csrf_token
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


def create_app(
    settings: Settings,
    *,
    context: str,
    token: str,
    port: int,
    clock: Callable[[], datetime] = _utcnow,
    list_contexts: Callable[[], list[str]] | None = None,
) -> FastAPI:
    """Build the UI. ``context`` is the one shown by default, ``token`` the startup secret, ``port`` what the Host
    check expects, and ``list_contexts`` lists the kubeconfig's contexts (read on each page)."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    guard = Guard(token, port)
    app.state.settings = settings
    app.state.context = context
    app.state.list_contexts = list_contexts or (lambda: kube_client.list_contexts(settings))
    app.state.clock = clock
    app.state.guard = guard
    app.state.templates = _templates(guard)
    app.state.scans = ScanRunner(settings, context, clock=clock)
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
    app.include_router(accepted.router)
    app.include_router(failed.router)
    app.include_router(scans.router)
    install(app, guard)
    return app
