"""The FastAPI application behind ``kubedelos ui``.

``create_app`` wires the security middleware, the templates, the static files and the page routers. The helpers the
pages and the security middleware share (``open_db``, ``render``) live in ``kubedelos.web.pages``, so that this module
can import the routes at the top level without an import cycle.
"""

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
from kubedelos.web.pages import render
from kubedelos.web.routes import dashboard, findings
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


def _templates(guard: Guard) -> Jinja2Templates:
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(_HERE / "templates"), autoescape=True)

    def csrf_token(request: Request) -> str:
        sid = request.cookies.get(guard.cookie_name)
        return guard.csrf_token(sid) if guard.valid_session(sid) else ""

    env.globals["csrf_token"] = csrf_token
    env.filters["safe_url"] = safe_url
    env.globals.update(
        ago=ago,
        describe_scope=describe_scope,
        describe_pkg_types=describe_pkg_types,
        finished_text=finished_text,
        is_stale=is_stale,
    )
    return Jinja2Templates(env=env)


def create_app(
    settings: Settings, *, context: str, token: str, port: int, clock: Callable[[], datetime] = _utcnow
) -> FastAPI:
    """Build the UI for one kube-context. ``token`` is the startup secret; ``port`` is what the Host check expects."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    guard = Guard(token, port)
    app.state.settings = settings
    app.state.context = context
    app.state.clock = clock
    app.state.guard = guard
    app.state.templates = _templates(guard)
    app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")

    @app.exception_handler(RequestValidationError)
    async def invalid_parameter(request: Request, exc: RequestValidationError) -> HTMLResponse:
        errors = exc.errors()
        name = errors[0]["loc"][-1] if errors and errors[0].get("loc") else "request"
        return render(request, "error.html", {"title": "Bad request", "message": f"invalid parameter: {name}"}, 400)

    app.include_router(dashboard.router)
    app.include_router(findings.router)
    install(app, guard)
    return app
