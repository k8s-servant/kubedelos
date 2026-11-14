"""The helpers every page of the local UI shares: a read-only database connection and the template renderer.

They live apart from ``kubedelos.web.app`` so the routes and the security middleware can import them at the top level:
this module imports nothing from ``app``, ``routes`` or ``security``, which keeps the import graph acyclic. Pages call
``open_db`` for a read-only connection of their own (sqlite3 objects never cross threads) and ``render`` to fill a
template with what every page needs: the request, the kube-context, the CSP nonce and the nav. A page may override the
context and nav (the signed-out page shows neither).
"""

import contextlib
import sqlite3
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse

from kubedelos.store.db import connect_readonly

MAX_ID = 2**63 - 1  # SQLite integers are signed 64-bit; a larger id would raise OverflowError
NAV = (("Dashboard", "/"), ("Findings", "/findings"))


def open_db(request: Request) -> contextlib.closing[sqlite3.Connection]:
    """A read-only connection to the scan database, closed by the ``with`` block. Open it inside the endpoint."""
    return contextlib.closing(connect_readonly(request.app.state.settings.db_path))


def render(request: Request, name: str, ctx: dict[str, Any], status: int = 200) -> HTMLResponse:
    """Render template ``name`` with ``ctx`` plus the request, the CSP nonce and, unless ``ctx`` sets them, the context and nav."""
    path = request.url.path
    nav = [{"label": label, "href": href, "active": path == href} for label, href in NAV]
    full = {
        "context": request.app.state.context,
        "nav": nav,
        **ctx,
        "request": request,
        "nonce": request.state.csp_nonce,
    }
    return request.app.state.templates.TemplateResponse(request, name, full, status_code=status)
