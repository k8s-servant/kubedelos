"""The FastAPI application behind ``kubedelos ui``, and the helpers its pages share.

``create_app`` wires the security middleware, the templates and the static files. Pages call ``open_db`` for a
read-only connection of their own (sqlite3 objects never cross threads) and ``render`` to fill a template with what
every page needs: the request, the kube-context, the CSP nonce and the nav.
"""

import contextlib
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
from kubedelos.store.db import connect_readonly
from kubedelos.web.security import SESSION_COOKIE, Guard, install

_HERE = Path(__file__).parent
NAV = (("Dashboard", "/"), ("Findings", "/findings"))


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


def _templates(guard: Guard) -> Jinja2Templates:
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(_HERE / "templates"), autoescape=True)

    def csrf_token(request: Request) -> str:
        sid = request.cookies.get(SESSION_COOKIE)
        return guard.csrf_token(sid) if guard.valid_session(sid) else ""

    env.globals["csrf_token"] = csrf_token
    env.filters["safe_url"] = safe_url
    env.globals.update(ago=ago, describe_scope=describe_scope, describe_pkg_types=describe_pkg_types, is_stale=is_stale)
    return Jinja2Templates(env=env)


def create_app(
    settings: Settings, *, context: str, token: str, port: int, clock: Callable[[], datetime] = _utcnow
) -> FastAPI:
    """Build the UI for one kube-context. ``token`` is the startup secret; ``port`` is what the Host check expects."""
    from kubedelos.web.routes import dashboard  # the routes import this module's helpers, so import them late

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
    install(app, guard)
    return app


def open_db(request: Request) -> contextlib.closing[sqlite3.Connection]:
    """A read-only connection to the scan database, closed by the ``with`` block. Open it inside the endpoint."""
    return contextlib.closing(connect_readonly(request.app.state.settings.db_path))


def render(request: Request, name: str, ctx: dict[str, Any], status: int = 200) -> HTMLResponse:
    """Render template ``name`` with ``ctx`` plus the request, the context label, the CSP nonce and the nav."""
    path = request.url.path
    nav = [{"label": label, "href": href, "active": path == href} for label, href in NAV]
    full = {
        **ctx,
        "request": request,
        "context": request.app.state.context,
        "nonce": request.state.csp_nonce,
        "nav": nav,
    }
    return request.app.state.templates.TemplateResponse(request, name, full, status_code=status)
