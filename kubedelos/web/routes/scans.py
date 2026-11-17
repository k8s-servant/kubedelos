"""The scans page: start a scan of the UI's context, follow its progress, cancel it, and page through every run.

``GET /scans`` never writes to the database: it reads through ``open_db`` and never closes a run, though checking a
run's owner may delete an orphan lock file. A ``running`` row whose owner lock nobody holds reads "interrupted" there.
Only ``ok`` and ``partial`` runs link to their findings, since a failed or cancelled run has no results to show. The
form posts to ``/scans`` with the CSRF token; each field starts at the UI's saved settings and says what they are.

``POST /scans`` reads the urlencoded body itself (the CSRF guard has already cached it, and python-multipart is not a
dependency), validates the seven fields against ``Settings`` and passes only the validated values to the app's
``ScanRunner``, plus the "Rescan every image" box, which skips the result cache for that one scan. Before it starts the scan it closes the stale ``running`` rows no live process owns, through
``open_db_rw``, the only writable connection these routes open. ``GET /scans/progress`` serves the progress readout
alone, for polling; once the scan has ended it tells htmx to reload the page, so the history shows the finished run.
``POST /scans/cancel`` asks the running scan to stop.
"""

import re
import sqlite3
from datetime import datetime, timedelta
from math import ceil
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from kubedelos.analytics import describe_pkg_types
from kubedelos.config import Settings
from kubedelos.store import runlock
from kubedelos.store.queries import RESULT_STATUSES, HistoryRow, newest_run, run_failures, run_history, run_number
from kubedelos.web.jobs import ScanBusy
from kubedelos.web.pages import (
    UnknownContext,
    context_param,
    link,
    open_db,
    open_db_rw,
    render,
    scannable_contexts,
    seconds_text,
    short_image,
    shown_context,
)
from kubedelos.web.routes.failed import failure

router = APIRouter()

PER_PAGE = 25
ACTIVE = ("starting", "running", "stopping")
PKG_TYPES = ("os", "library")
CHIP = {
    "ok": "chip-ok",
    "partial": "chip-stale",
    "failed": "chip-bad",
    "interrupted": "chip-bad",
    "running": "chip-pinned",
}
# The form's fields, as Settings names them, with the labels the form shows them under.
FIELDS = {
    "namespaces": "Namespaces",
    "exclude_namespaces": "Exclude namespaces",
    "namespace_selector": "Namespace selector",
    "selector": "Label selector",
    "exclude_images": "Exclude images",
    "parallelism": "Parallel images",
    "pkg_types": "Package types",
}
LIST_FIELDS = ("namespaces", "exclude_namespaces", "exclude_images")
READOUT_FAILURES = 5  # the newest failures the progress readout lists; the failures page has them all
PHASES = {"inventory": "inventory", "trivy-db": "Trivy DB", "scanning": "scanning", "saving": "saving"}
_MAX_FORM_FIELDS = 100
_MAX_BODY = 64 * 1024
UNREADABLE = "the form could not be read"


def duration_text(started_at: datetime, finished_at: datetime | None) -> str:
    """How long a run took, as "s s" under a minute and "m min s s" above, or "—" while it has no end."""
    if finished_at is None:
        return "—"
    return seconds_text(int((finished_at - started_at).total_seconds()))


def scans_href(page: int, context: str | None = None) -> str:
    """A history page link; ``context`` is the shown context to keep, None for the UI's startup context."""
    query = urlencode({k: v for k, v in {"context": context, "page": page if page > 1 else None}.items() if v})
    return "/scans?" + query if query else "/scans"


def _row(request: Request, run: HistoryRow, retryable_id: int | None = None) -> dict:
    status = run.status
    if status == "running" and not (run.owner and runlock.is_owned(request.app.state.settings.data_dir, run.owner)):
        status = "interrupted"
    return {
        "id": run.id,
        "number": run.number,
        "status": status,
        "chip": CHIP.get(status, ""),
        "href": link(request, "/findings", run_id=run.id) if run.status in RESULT_STATUSES else None,
        "compare_href": link(request, "/diff", to=run.id) if run.status in RESULT_STATUSES else None,
        "report_href": link(request, "/report", run_id=run.id) if run.status in RESULT_STATUSES else None,
        "scope": run.scope,
        "pkg_types": run.pkg_types,
        "images": run.images,
        "failed": run.failed,
        "failed_href": link(request, f"/scans/{run.id}/failed") if run.failed else None,
        # The newest result run's failures can be retried; the failures page has the form and the last word on it.
        "retry_href": link(request, f"/scans/{run.id}/failed") + "#retry" if run.id == retryable_id else None,
        "duration": duration_text(run.started_at, run.finished_at),
        "times_href": link(request, f"/scans/{run.id}/times") if run.status != "running" else None,
    }


def _form(request: Request, sent: dict | None = None) -> dict:
    """Each form field's value and its "saved: X" hint, from the UI's saved settings; ``sent`` keeps what was posted."""
    s = request.app.state.settings
    form = {
        "namespaces": ", ".join(s.namespaces),
        "namespaces_saved": ", ".join(s.namespaces) or "all namespaces",
        "exclude_namespaces": ", ".join(s.exclude_namespaces),
        "exclude_namespaces_saved": ", ".join(s.exclude_namespaces) or "none",
        "namespace_selector": s.namespace_selector or "",
        "namespace_selector_saved": s.namespace_selector or "none",
        "selector": s.selector or "",
        "selector_saved": s.selector or "none",
        "exclude_images": ", ".join(s.exclude_images),
        "exclude_images_saved": ", ".join(s.exclude_images) or "none",
        "parallelism": str(s.parallelism),
        "parallelism_saved": str(s.parallelism),
        "pkg_types": s.pkg_types,
        "pkg_types_saved": describe_pkg_types(s.scan_level),
        "rescan": False,
    }
    return form if sent is None else {**form, **sent}


def eta_text(left: timedelta) -> str:
    """The time a scan has left: "less than a minute left", or "about N min left" rounded up to a whole minute."""
    if left < timedelta(minutes=1):
        return "less than a minute left"
    return f"about {ceil(left.total_seconds() / 60)} min left"


def short_ref(ref: str) -> str:
    """``ref`` with its digest cut short, as the findings table shows images."""
    name, at, digest = ref.partition("@")
    return short_image({"repo": name, "tag": None, "digest": digest, "image": ref}) if at else ref


def _job(request: Request, conn: sqlite3.Connection) -> dict | None:
    """What the progress readout shows of the current or last UI scan, or None before the first one."""
    view = request.app.state.scans.view()
    if view is None:
        return None
    p = view.progress
    active = view.state in ACTIVE
    finished = view.state == "finished"
    linked = finished and view.status in RESULT_STATUSES and view.run_id is not None
    other = view.context != getattr(request.state, "context", request.app.state.context)
    # A scan of another context says so, and links to that context's scans page and results.
    target = view.context if view.context != request.app.state.context else None
    where = f" of {view.context}" if other else ""
    titles = {"finished": f"Last scan{where}", "error": f"Scan{where} failed"}
    if view.retry_of is not None:
        number = run_number(conn, view.retry_of)
        titles = {"finished": f"Last retry of run {number}{where}", "error": f"Retry of run {number}{where} failed"}
    # The run's failures so far: each result is written as its image finishes, so they are there while it runs.
    run_id = p.run_id if p is not None else None
    failures, failures_total = (
        run_failures(conn, run_id, limit=READOUT_FAILURES, newest_first=True) if run_id is not None else ([], 0)
    )
    failures_href = f"/scans/{run_id}/failed" + ("?" + urlencode({"context": target}) if target else "")
    return {
        "state": view.state,
        "context": view.context,
        "title": titles.get(
            view.state,
            f"Retrying failed images of run {number}" if view.retry_of is not None else f"Scanning {view.context}",
        ),
        "elsewhere_href": scans_href(1, target) if other else None,
        "scans_href": scans_href(1, target),
        "phase": PHASES.get(p.phase, p.phase) if p is not None and active else None,
        "counted": p is not None and p.phase != "inventory" and (active or finished),
        "total": p.total if p else 0,
        "done": p.done if p else 0,
        "scanned": p.done - p.cached - p.errors if p else 0,
        "cached": p.cached if p else 0,
        "failed": p.errors if p else 0,
        "image": short_ref(p.current) if p is not None and p.current and active else None,
        "eta": eta_text(view.eta) if view.eta is not None and view.state == "running" else None,
        "status": view.status if finished else None,
        "chip": CHIP.get(view.status or "", ""),
        "run_number": run_number(conn, view.run_id) if view.run_id is not None else None,
        "href": findings_link(view.run_id, target) if linked else None,
        "error": (view.error or "the scan failed") if view.state == "error" else None,
        "cancellable": view.state in ("starting", "running"),
        "failures": [failure(row) for row in failures],
        "failures_total": failures_total,
        "failures_href": failures_href if failures_total else None,
    }


def findings_link(run_id: int, context: str | None) -> str:
    return "/findings?" + urlencode({k: v for k, v in {"context": context, "run_id": run_id}.items() if v})


def _page(
    request: Request,
    page: int = 1,
    *,
    error: str | None = None,
    sent: dict | None = None,
    status: int = 200,
    context: str | None = None,
) -> HTMLResponse:
    """The scans page of ``context``, from a POST's form, or else of the context the query string names."""
    with open_db(request) as conn:
        context = shown_context(request, conn, context)
        history, total = run_history(conn, context, page, PER_PAGE)
        run = newest_run(conn, context, cluster_scope=False)  # the sidebar's "scanned N ago"
        job = _job(request, conn)
    retryable_id = run.id if run is not None and run.status == "partial" else None
    last_page = max(1, ceil(total / PER_PAGE))
    first = (page - 1) * PER_PAGE + 1
    ctx = {
        "now": request.app.state.clock(),
        "run": run,
        "form": _form(request, sent),
        "form_error": error,
        "pkg_choices": PKG_TYPES,
        "job": job,
        "rows": [_row(request, r, retryable_id) for r in history],
        "total": total,
        "page": page,
        "first": first,
        "last": first + len(history) - 1,
        "last_page": last_page,
        "past_end": not history and total > 0,
        "prev_href": scans_href(page - 1, context_param(request)) if page > 1 and history else None,
        "next_href": scans_href(page + 1, context_param(request)) if page < last_page and history else None,
        "last_page_href": scans_href(last_page, context_param(request)),
        "scannable": context in scannable_contexts(request),
    }
    return render(request, "scans.html", ctx, status)


def _split(text: str) -> list[str]:
    """A comma or space separated list, without blanks."""
    return [item for item in re.split(r"[\s,]+", text) if item]


def _invalid(exc: ValidationError) -> str:
    """The first validation error, named by the form's label for its field."""
    error = exc.errors()[0]
    field = str(error["loc"][0]) if error.get("loc") else "form"
    return f"{FIELDS.get(field, field)}: {error['msg'].removeprefix('Value error, ')}"


@router.get("/scans", response_class=HTMLResponse)
def scans(request: Request, page: int = Query(1, ge=1, le=10**9)) -> HTMLResponse:
    return _page(request, page)


@router.post("/scans")
async def start(request: Request) -> Response:
    body = await request.body()  # the CSRF guard has read it already; the rest blocks, so it runs on a worker thread
    return await run_in_threadpool(_start, request, body)


def _start(request: Request, body: bytes) -> Response:
    if len(body) > _MAX_BODY:
        return _page(request, error=UNREADABLE, status=400)
    try:
        # Strict both ways, as the guard parses: neither raw bytes nor a %-escape may be anything but UTF-8.
        fields = parse_qs(body.decode(), keep_blank_values=True, max_num_fields=_MAX_FORM_FIELDS, errors="strict")
    except ValueError:  # not UTF-8, or too many fields: possible when the CSRF token came in the header
        return _page(request, error=UNREADABLE, status=400)
    default = request.app.state.context
    target = fields.get("context", [""])[0] or default
    text = {name: fields.get(name, [""])[0] for name in FIELDS if name != "pkg_types"}
    sent = {**text, "pkg_types": fields.get("pkg_types", []), "rescan": fields.get("rescan", [""])[0] == "on"}

    def page(error: str, status: int) -> HTMLResponse:
        """The posted context's page with ``error`` and what was typed; the startup context's if it is unknown."""
        try:
            return _page(request, error=error, sent=sent, status=status, context=target)
        except UnknownContext:
            return _page(request, error=error, sent=sent, status=status)

    # Checked at the click: only a context the kubeconfig has now may be scanned, never one known only from history.
    if target not in scannable_contexts(request):
        return page(f"{target} is not in your kubeconfig", 400)
    overrides = {
        **{name: _split(text[name]) for name in LIST_FIELDS},
        "namespace_selector": text["namespace_selector"].strip() or None,
        "selector": text["selector"].strip() or None,
        "parallelism": text["parallelism"].strip(),  # Settings parses it and keeps it to 1-32
        "pkg_types": sent["pkg_types"],
    }
    settings = request.app.state.settings
    try:
        valid = Settings.model_validate({**settings.model_dump(), **overrides})
    except ValidationError as exc:
        return page(_invalid(exc), 400)
    try:
        with open_db_rw(request) as conn:
            runlock.close_stale_runs(conn, settings.data_dir)
    except sqlite3.OperationalError:  # locked past the busy timeout, most likely by another scan writing results
        return page("the database is busy; try again", 503)
    try:
        request.app.state.scans.start(
            {name: getattr(valid, name) for name in FIELDS}, context=target, rescan=sent["rescan"]
        )
    except ScanBusy as exc:
        return page(str(exc), 409)
    return RedirectResponse(scans_href(1, target if target != default else None), status_code=303)


@router.post("/scans/cancel")
async def cancel(request: Request) -> RedirectResponse:
    request.app.state.scans.cancel()
    try:
        fields = parse_qs((await request.body()).decode(), max_num_fields=_MAX_FORM_FIELDS, errors="strict")
    except ValueError:
        fields = {}
    back = fields.get("context", [""])[0]
    # Back to the page the button was on; the value only ever lands in this local path's query string.
    return RedirectResponse(
        scans_href(1, back if back and back != request.app.state.context else None), status_code=303
    )


@router.get("/scans/progress", response_class=HTMLResponse)
def progress(request: Request) -> HTMLResponse:
    # Resolve the page's context as the page did, so the polled readout matches the one it replaces.
    with open_db(request) as conn:
        shown_context(request, conn)
        job = _job(request, conn)
    response = render(request, "partials/scan_progress.html", {"job": job})
    # The scan htmx was polling has ended: reload the page so the run history shows the run's final row too. The
    # reloaded page has no poller, since the job is no longer active, so this can't loop.
    if request.headers.get("HX-Request") == "true" and job is not None and job["state"] not in ACTIVE:
        response.headers["HX-Refresh"] = "true"
    return response
