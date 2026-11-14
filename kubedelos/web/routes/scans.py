"""The scans page (``GET /scans``): the form that starts a scan, and the paged history of every run of this context.

The page is read-only: it reads through ``open_db`` and never closes a run. A ``running`` row whose owner lock nobody
holds reads "interrupted" here; the stale-run sweep closes such rows when the next scan starts. Only ``ok`` and
``partial`` runs link to their findings, since a failed or cancelled run has no results to show. The form posts to
``/scans`` with the CSRF token; each field starts at the UI's saved settings and says what they are.
"""

from datetime import datetime
from math import ceil
from urllib.parse import urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from kubedelos.store import runlock
from kubedelos.store.queries import RESULT_STATUSES, HistoryRow, newest_run, run_history
from kubedelos.web.pages import open_db, render

router = APIRouter()

PER_PAGE = 25
PKG_TYPES = ("os", "library")
CHIP = {
    "ok": "chip-ok",
    "partial": "chip-stale",
    "failed": "chip-bad",
    "interrupted": "chip-bad",
    "running": "chip-pinned",
}


def duration_text(started_at: datetime, finished_at: datetime | None) -> str:
    """How long a run took, as "m min s s", or "—" while it has no end."""
    if finished_at is None:
        return "—"
    minutes, seconds = divmod(max(0, int((finished_at - started_at).total_seconds())), 60)
    return f"{minutes} min {seconds} s"


def scans_href(page: int) -> str:
    return "/scans?" + urlencode({"page": page}) if page > 1 else "/scans"


def _row(request: Request, run: HistoryRow) -> dict:
    status = run.status
    if status == "running" and not (run.owner and runlock.is_owned(request.app.state.settings.data_dir, run.owner)):
        status = "interrupted"
    return {
        "id": run.id,
        "status": status,
        "chip": CHIP.get(status, ""),
        "href": "/findings?" + urlencode({"run_id": run.id}) if run.status in RESULT_STATUSES else None,
        "scope": run.scope,
        "pkg_types": run.pkg_types,
        "images": run.images,
        "failed": run.failed,
        "duration": duration_text(run.started_at, run.finished_at),
    }


def _form(request: Request) -> dict:
    """Each form field's value and its "saved: X" hint, from the UI's saved settings."""
    s = request.app.state.settings
    return {
        "namespaces": ", ".join(s.namespaces),
        "namespaces_saved": ", ".join(s.namespaces) or "all namespaces",
        "namespace_selector": s.namespace_selector or "",
        "namespace_selector_saved": s.namespace_selector or "none",
        "selector": s.selector or "",
        "selector_saved": s.selector or "none",
        "exclude_images": ", ".join(s.exclude_images),
        "exclude_images_saved": ", ".join(s.exclude_images) or "none",
        "pkg_types": s.pkg_types,
        "pkg_types_saved": s.scan_level,
    }


@router.get("/scans", response_class=HTMLResponse)
def scans(request: Request, page: int = Query(1, ge=1, le=10**9)) -> HTMLResponse:
    context = request.app.state.context
    with open_db(request) as conn:
        history, total = run_history(conn, context, page, PER_PAGE)
        run = newest_run(conn, context, cluster_scope=False)  # the sidebar's "scanned N ago"
    last_page = max(1, ceil(total / PER_PAGE))
    first = (page - 1) * PER_PAGE + 1
    ctx = {
        "now": request.app.state.clock(),
        "run": run,
        "form": _form(request),
        "pkg_choices": PKG_TYPES,
        "rows": [_row(request, r) for r in history],
        "total": total,
        "page": page,
        "first": first,
        "last": first + len(history) - 1,
        "last_page": last_page,
        "past_end": not history and total > 0,
        "prev_href": scans_href(page - 1) if page > 1 and history else None,
        "next_href": scans_href(page + 1) if page < last_page and history else None,
        "last_page_href": scans_href(last_page),
    }
    return render(request, "scans.html", ctx)
