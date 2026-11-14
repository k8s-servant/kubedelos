"""The scans page: start a scan of the UI's context, follow its progress, cancel it, and page through every run.

``GET /scans`` never writes to the database: it reads through ``open_db`` and never closes a run, though checking a
run's owner may delete an orphan lock file. A ``running`` row whose owner lock nobody holds reads "interrupted" there.
Only ``ok`` and ``partial`` runs link to their findings, since a failed or cancelled run has no results to show. The
form posts to ``/scans`` with the CSRF token; each field starts at the UI's saved settings and says what they are.

``POST /scans`` reads the urlencoded body itself (the CSRF guard has already cached it, and python-multipart is not a
dependency), validates the five fields against ``Settings`` and passes only the validated values to the app's
``ScanRunner``. Before it starts the scan it closes the stale ``running`` rows no live process owns, through
``open_db_rw``, the only writable connection these routes open. ``GET /scans/progress`` serves the progress readout
alone, for polling, and ``POST /scans/cancel`` asks the running scan to stop.
"""

import re
from datetime import datetime, timedelta
from math import ceil
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError

from kubedelos.config import Settings
from kubedelos.output import short_image
from kubedelos.store import runlock
from kubedelos.store.queries import RESULT_STATUSES, HistoryRow, newest_run, run_history
from kubedelos.web.jobs import ScanBusy
from kubedelos.web.pages import open_db, open_db_rw, render

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
# The form's fields, as Settings names them, with the labels the form shows them under.
FIELDS = {
    "namespaces": "Namespaces",
    "namespace_selector": "Namespace selector",
    "selector": "Label selector",
    "exclude_images": "Exclude images",
    "pkg_types": "Package types",
}
LIST_FIELDS = ("namespaces", "exclude_images")
PHASES = {"inventory": "inventory", "trivy-db": "Trivy DB", "scanning": "scanning", "saving": "saving"}
_MAX_FORM_FIELDS = 100


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


def _form(request: Request, sent: dict | None = None) -> dict:
    """Each form field's value and its "saved: X" hint, from the UI's saved settings; ``sent`` keeps what was posted."""
    s = request.app.state.settings
    form = {
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
    return form if sent is None else {**form, **sent}


def eta_text(left: timedelta) -> str:
    """The time a scan has left, as "about N min left", rounded up to a whole minute."""
    return f"about {max(1, ceil(left.total_seconds() / 60))} min left"


def short_ref(ref: str) -> str:
    """``ref`` with its digest cut short, as the findings table shows images."""
    name, at, digest = ref.partition("@")
    return short_image({"repo": name, "tag": None, "digest": digest, "image": ref}) if at else ref


def _job(request: Request) -> dict | None:
    """What the progress readout shows of the current or last UI scan, or None before the first one."""
    view = request.app.state.scans.view()
    if view is None:
        return None
    p = view.progress
    active = view.state in ("starting", "running", "stopping")
    finished = view.state == "finished"
    linked = finished and view.status in RESULT_STATUSES and view.run_id is not None
    titles = {"finished": "Last scan", "error": "Scan failed"}
    return {
        "state": view.state,
        "title": titles.get(view.state, "Scan in progress"),
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
        "run_id": view.run_id,
        "href": "/findings?" + urlencode({"run_id": view.run_id}) if linked else None,
        "error": (view.error or "the scan failed") if view.state == "error" else None,
        "cancellable": view.state in ("starting", "running"),
    }


def _page(
    request: Request, page: int = 1, *, error: str | None = None, sent: dict | None = None, status: int = 200
) -> HTMLResponse:
    context = request.app.state.context
    with open_db(request) as conn:
        history, total = run_history(conn, context, page, PER_PAGE)
        run = newest_run(conn, context, cluster_scope=False)  # the sidebar's "scanned N ago"
    last_page = max(1, ceil(total / PER_PAGE))
    first = (page - 1) * PER_PAGE + 1
    ctx = {
        "now": request.app.state.clock(),
        "run": run,
        "form": _form(request, sent),
        "form_error": error,
        "pkg_choices": PKG_TYPES,
        "job": _job(request),
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
    try:
        fields = parse_qs((await request.body()).decode(), keep_blank_values=True, max_num_fields=_MAX_FORM_FIELDS)
    except ValueError:  # not UTF-8, or too many fields: possible when the CSRF token came in the header
        return _page(request, error="the form could not be read", status=400)
    text = {name: fields.get(name, [""])[0] for name in FIELDS if name != "pkg_types"}
    sent = {**text, "pkg_types": fields.get("pkg_types", [])}
    overrides = {
        **{name: _split(text[name]) for name in LIST_FIELDS},
        "namespace_selector": text["namespace_selector"].strip() or None,
        "selector": text["selector"].strip() or None,
        "pkg_types": sent["pkg_types"],
    }
    settings = request.app.state.settings
    try:
        valid = Settings.model_validate({**settings.model_dump(), **overrides})
    except ValidationError as exc:
        return _page(request, error=_invalid(exc), sent=sent, status=400)
    with open_db_rw(request) as conn:
        runlock.close_stale_runs(conn, settings.data_dir)
    try:
        request.app.state.scans.start({name: getattr(valid, name) for name in FIELDS})
    except ScanBusy as exc:
        return _page(request, error=str(exc), sent=sent, status=409)
    return RedirectResponse("/scans", status_code=303)


@router.post("/scans/cancel")
def cancel(request: Request) -> RedirectResponse:
    request.app.state.scans.cancel()
    return RedirectResponse("/scans", status_code=303)


@router.get("/scans/progress", response_class=HTMLResponse)
def progress(request: Request) -> HTMLResponse:
    return render(request, "partials/scan_progress.html", {"job": _job(request)})
