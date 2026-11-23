"""The helpers every page of the local UI shares: the database connections and the template renderer.

They live apart from ``kubedelos.web.app`` so the routes and the security middleware can import them at the top level:
this module imports nothing from ``app``, ``routes`` or ``security``, which keeps the import graph acyclic. Pages call
``open_db`` for a read-only connection of their own (sqlite3 objects never cross threads); only the POST routes call
``open_db_rw`` for a writable one. In ``kubedelos serve`` the scan and retry routes queue their request through
``queue_ui_request``. ``shown_context`` resolves the page's kube-context and the cluster key it stands for, which the
store queries take, since contexts that point at one API server share one history. ``short_image`` is how every page
names an image. ``render`` fills a template with what every page needs: the request, the kube-context, the CSP nonce
and the nav. A page may override the context and nav (the signed-out page shows neither).
"""

import contextlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from kubedelos.store import (
    db,
    intel,
    queue,
)  # through the module, so a test that patches db.connect reaches every caller
from kubedelos.store.queries import cluster_scans, context_cluster
from kubedelos.web.identity import identity

QUEUE_FULL = "the queue is full"
DB_BUSY = "the database is busy; try again"
MAX_ID = 2**63 - 1  # SQLite integers are signed 64-bit; a larger id would raise OverflowError
NAV = (
    ("Dashboard", "/"),
    ("Findings", "/findings"),
    ("Namespaces", "/namespaces"),
    ("Compare", "/diff"),
    ("Reports", "/reports"),
    ("Accepted", "/accepted"),
    ("Scans", "/scans"),
    ("Settings", "/settings"),
    ("About", "/about"),
)


def open_db(request: Request) -> contextlib.closing[sqlite3.Connection]:
    """A read-only connection to the scan database, closed by the ``with`` block. Open it inside the endpoint."""
    return contextlib.closing(db.connect_readonly(request.app.state.settings.db_path))


def open_db_rw(request: Request) -> contextlib.closing[sqlite3.Connection]:
    """A read-write connection to the scan database, closed by the ``with`` block. For POST routes only."""
    return contextlib.closing(db.connect(request.app.state.settings.db_path))


def queue_ui_request(
    request: Request,
    *,
    kind: str,
    overrides: dict,
    on_error: Callable[[str, int], Response],
    target_run_id: int | None = None,
) -> Response:
    """Queue a scan or retry asked for in the serve UI, under the signed-in name, and wake the worker. Back to
    ``/scans``, with ``?notice=queued`` when an equal request was already waiting; else ``on_error(message, status)``:
    a 409 when the queue is full, a 503 when the database stays locked."""
    try:
        with open_db_rw(request) as conn:
            queued = queue.enqueue(
                conn,
                kind=kind,
                trigger="ui",
                overrides=overrides,
                requested_by=identity(request),
                target_run_id=target_run_id,
                now=request.app.state.clock(),
            )
    except queue.QueueFull:
        return on_error(QUEUE_FULL, 409)
    except sqlite3.OperationalError:  # locked past the busy timeout, most likely by a scan writing results
        return on_error(DB_BUSY, 503)
    request.app.state.worker.wake()
    return RedirectResponse("/scans" if queued.added else "/scans?notice=queued", status_code=303)


class UnknownContext(Exception):
    """The ``context`` asked for is neither in the kubeconfig nor the name of a cluster in the scan history."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


@dataclass(frozen=True)
class ContextEntry:
    """One line of the sidebar's context switcher."""

    name: str
    finished_at: datetime | None  # when its cluster's newest result run finished, None when it has none
    scannable: bool  # in the kubeconfig, so the UI can scan it; a cluster known only from history can only be viewed
    href: str  # the same page for that context, without the other parameters (run ids and filters are per cluster)
    shown: bool


def shown_context(request: Request, conn: sqlite3.Connection, wanted: str | None = None) -> str:
    """Resolve the page's context, ``wanted`` or else ``?context=`` (the UI's startup context by default), and record
    it, its cluster key (``request.state.cluster``, what the store queries take) and the switcher's entries on
    ``request.state``. Raises :class:`UnknownContext` for a name the UI doesn't know.

    The switcher lists every kubeconfig context, each with its cluster's last scan, so two contexts of one cluster
    show the same one, plus one entry per cluster no kubeconfig context points at, named after the context of its
    newest run (or by its key when that name already stands for another cluster). The kubeconfig is listed on every
    call, so a context added while the UI runs shows up; listing never loads one.
    """
    default = request.app.state.context
    wanted = wanted or request.query_params.get("context") or default
    kubeconfig = scannable_contexts(request)
    scans = {scan.cluster: scan for scan in cluster_scans(conn)}
    clusters = {name: cluster_of(request, conn, name) for name in kubeconfig}  # entry name -> cluster key
    claimed = set(clusters.values())
    for scan in scans.values():  # by name, so a clash keeps the same winner on every page
        if scan.cluster in claimed:
            continue
        name = scan.name
        if name in clusters or cluster_of(request, conn, name) != scan.cluster:
            name = scan.cluster  # a key resolves to itself, since no context is named after it
        if name not in clusters:
            clusters[name] = scan.cluster
    if wanted not in clusters:
        raise UnknownContext(wanted)
    request.state.context = wanted
    request.state.cluster = clusters[wanted]
    request.state.contexts = [
        ContextEntry(
            name,
            scan.finished_at if (scan := scans.get(clusters[name])) else None,
            name in kubeconfig,
            _with_context(request, request.url.path, name),
            name == wanted,
        )
        for name in sorted(clusters, key=str.casefold)
    ]
    return wanted


def cluster_keys(request: Request) -> dict[str, str]:
    """Each kubeconfig context's cluster key, as the kubeconfig is now; read once per request."""
    if not hasattr(request.state, "kube_cluster_keys"):
        request.state.kube_cluster_keys = dict(request.app.state.cluster_keys())
    return request.state.kube_cluster_keys


def cluster_of(request: Request, conn: sqlite3.Connection, name: str) -> str:
    """The cluster key a context name stands for: the kubeconfig's, else the cluster of the newest run made through
    that context (one the kubeconfig no longer has), else the name itself."""
    return cluster_keys(request).get(name) or context_cluster(conn, name) or name


RISK_HIDDEN = (
    "Risk scores are hidden for this run: no attack-surface facts were collected and no threat feed has been "
    "downloaded, so a score would only restate severity."
)
RISK_NO_FACTS = (
    "Attack-surface facts were not collected for this run, so exposure, host access and API rights count as unknown."
)
RISK_NO_FEEDS = "No threat feed has been downloaded yet, so known exploitation (KEV, EPSS) adds nothing."


def risk_view(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """The template context for the risk score: whether to show it and the one note that says what is missing, if any."""
    shown = intel.risk_shown(conn, run_id)
    if not shown:
        note: str | None = RISK_HIDDEN
    elif not intel.run_has_facts(conn, run_id):
        note = RISK_NO_FACTS
    elif not intel.feeds(conn):
        note = RISK_NO_FEEDS
    else:
        note = None
    return {"risk_shown": shown, "risk_note": note}


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


def seconds_text(seconds: float | None) -> str:
    """A span of time as "s s" under a minute and "m min s s" above, rounded to the second; "—" when unknown."""
    if seconds is None:
        return "—"
    minutes, rest = divmod(max(0, round(seconds)), 60)
    return f"{minutes} min {rest} s" if minutes else f"{rest} s"


TAG_SHOWN = 16  # longer tags (a kind build such as v20251212-v0.29.0-alpha-105-g20ccfc88) are cut to their first 10


def short_name(ref: str) -> str:
    """The image's own name (the last path segment) with its tag, or with ``sha256:`` and 8 hex of a digest-only ref.

    A tag over ``TAG_SHOWN`` characters keeps its first 10 and an ellipsis; the page puts the full ref in a tooltip.
    """
    name, _, digest = ref.partition("@")
    image, _, tag = name.rsplit("/", 1)[-1].partition(":")  # a registry port sits before the last slash
    if tag:
        return f"{image}:{tag if len(tag) <= TAG_SHOWN else tag[:10] + chr(0x2026)}"
    return f"{image}@{digest[:15]}" if digest else image


def short_image(r: Any) -> str:
    """``repo:tag`` plus a short digest: what people recognise, where the full ref is 64 hex characters long."""
    if not r["repo"]:
        return r["image"]
    name = f"{r['repo']}:{r['tag']}" if r["tag"] else r["repo"]
    return f"{name}@{r['digest'][:15]}" if r["digest"] else name  # "sha256:" + 8 hex
