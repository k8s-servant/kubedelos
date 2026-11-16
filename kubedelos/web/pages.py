"""The helpers every page of the local UI shares: the database connections and the template renderer.

They live apart from ``kubedelos.web.app`` so the routes and the security middleware can import them at the top level:
this module imports nothing from ``app``, ``routes`` or ``security``, which keeps the import graph acyclic. Pages call
``open_db`` for a read-only connection of their own (sqlite3 objects never cross threads); only the POST routes call
``open_db_rw`` for a writable one. ``short_image`` is how every page names an image. ``render`` fills a template with
what every page needs: the request, the kube-context, the CSP nonce and the nav. A page may override the context and nav
(the signed-out page shows neither).
"""

import contextlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse

from kubedelos.store import db  # through the module, so a test that patches db.connect reaches every caller
from kubedelos.store.queries import context_scans

MAX_ID = 2**63 - 1  # SQLite integers are signed 64-bit; a larger id would raise OverflowError
NAV = (
    ("Dashboard", "/"),
    ("Findings", "/findings"),
    ("Namespaces", "/namespaces"),
    ("Accepted", "/accepted"),
    ("Scans", "/scans"),
)


def open_db(request: Request) -> contextlib.closing[sqlite3.Connection]:
    """A read-only connection to the scan database, closed by the ``with`` block. Open it inside the endpoint."""
    return contextlib.closing(db.connect_readonly(request.app.state.settings.db_path))


def open_db_rw(request: Request) -> contextlib.closing[sqlite3.Connection]:
    """A read-write connection to the scan database, closed by the ``with`` block. For POST routes only."""
    return contextlib.closing(db.connect(request.app.state.settings.db_path))


class UnknownContext(Exception):
    """The ``context`` asked for is neither in the kubeconfig nor in the scan history."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


@dataclass(frozen=True)
class ContextEntry:
    """One line of the sidebar's context switcher."""

    name: str
    finished_at: datetime | None  # when its newest result run finished, None when it has none
    scannable: bool  # in the kubeconfig, so the UI can scan it; a context known only from history can only be viewed
    href: str  # the same page for that context, without the other parameters (run ids and filters are per cluster)
    shown: bool


def shown_context(request: Request, conn: sqlite3.Connection, wanted: str | None = None) -> str:
    """Resolve the page's context, ``wanted`` or else ``?context=`` (the UI's startup context by default), and record
    it, with the switcher's entries, on ``request.state``. Raises :class:`UnknownContext` for a name the UI doesn't
    know.

    The kubeconfig is listed on every call, so a context added while the UI runs shows up; listing never loads one.
    """
    default = request.app.state.context
    wanted = wanted or request.query_params.get("context") or default
    kubeconfig = scannable_contexts(request)
    scans = context_scans(conn)
    known = sorted(kubeconfig | set(scans), key=str.casefold)
    if wanted not in known:
        raise UnknownContext(wanted)
    request.state.context = wanted
    request.state.contexts = [
        ContextEntry(
            name, scans.get(name), name in kubeconfig, _with_context(request, request.url.path, name), name == wanted
        )
        for name in known
    ]
    return wanted


def scannable_contexts(request: Request) -> set[str]:
    """The contexts a scan may target: the kubeconfig's, as it is now, and the UI's startup context. The kubeconfig
    is read once per request, however many times a page asks."""
    if not hasattr(request.state, "kube_contexts"):
        request.state.kube_contexts = frozenset(request.app.state.list_contexts()) | {request.app.state.context}
    return set(request.state.kube_contexts)


def context_param(request: Request) -> str | None:
    """The ``context`` value links must carry: the shown context, or None for the UI's startup context."""
    shown = getattr(request.state, "context", None)
    return shown if shown and shown != request.app.state.context else None


def _with_context(request: Request, path: str, context: str | None, params: dict[str, Any] | None = None) -> str:
    query = {"context": context if context != request.app.state.context else None, **(params or {})}
    encoded = urlencode([(k, v) for k, v in query.items() if v is not None and v != []], doseq=True)
    return f"{path}?{encoded}" if encoded else path


def link(request: Request, path: str, **params: Any) -> str:
    """``path`` with ``params`` and, unless it is the startup context, the shown context; None values are dropped."""
    return _with_context(request, path, context_param(request), params)


def render(request: Request, name: str, ctx: dict[str, Any], status: int = 200) -> HTMLResponse:
    """Render template ``name`` with ``ctx`` plus the request, the CSP nonce and, unless ``ctx`` sets them, the context,
    the context switcher and the nav. Every link the nav and the templates build carries the shown context."""
    path = request.url.path
    nav = [{"label": label, "href": link(request, href), "active": path == href} for label, href in NAV]
    full = {
        "context": getattr(request.state, "context", request.app.state.context),
        "contexts": getattr(request.state, "contexts", []),
        "context_param": context_param(request),
        "link": lambda target, **params: link(request, target, **params),
        "nav": nav,
        **ctx,
        "request": request,
        "nonce": request.state.csp_nonce,
    }
    return request.app.state.templates.TemplateResponse(request, name, full, status_code=status)


def plural(count: int, singular: str, plural: str | None = None) -> str:
    """The word for ``count`` things: ``singular`` for exactly one, else ``plural`` (``singular`` + "s" by default)."""
    return singular if count == 1 else plural or singular + "s"


def short_image(r: Any) -> str:
    """``repo:tag`` plus a short digest: what people recognise, where the full ref is 64 hex characters long."""
    if not r["repo"]:
        return r["image"]
    name = f"{r['repo']}:{r['tag']}" if r["tag"] else r["repo"]
    return f"{name}@{r['digest'][:15]}" if r["digest"] else name  # "sha256:" + 8 hex
