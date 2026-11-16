"""The failures page (``GET /scans/{run_id}/failed``): every image of one run that failed to scan, and why.

It shows any run of the shown context, whatever its status, so a running, cancelled or narrow run's failures can be
read too; the dashboard's panel shows only its own run, capped. Each row gives the cause (``error_cause``, which
redacts credentials) and, folded away, the redacted error text; auth failures add the registry login hints. Paged in
SQL, 100 rows a page.

The newest result run of a context, once it finished ``partial``, also offers a retry of its failed images
(``POST /scans/{run_id}/retry``, with the CSRF token): the app's ``ScanRunner`` scans them again with the posted time
limit and parallelism and puts the results into the same run (see ``kubedelos.scan.service.retry_failed``). The page
lists the notes earlier retries left.
"""

import json
import sqlite3
from math import ceil
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Path, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from kubedelos.config import Settings
from kubedelos.hints import login_hints_for
from kubedelos.scan.service import CUSTOM_TRIVY
from kubedelos.store.queries import (
    RunLabel,
    RunNotShown,
    auth_failed_refs,
    newest_run,
    retry_notes,
    run_failures,
    run_label,
)
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.trivy.runner import RETRIED_PREFIX, error_cause, error_text
from kubedelos.web.jobs import ScanBusy
from kubedelos.web.pages import MAX_ID, context_param, link, open_db, render, shown_context

router = APIRouter()

PER_PAGE = 100
MIN_TIMEOUT_S, MAX_TIMEOUT_S = 60, 3600
RETRY_PARALLELISM = 2
_MAX_FORM_FIELDS = 20
_MAX_BODY = 4 * 1024
UNREADABLE = "the form could not be read"


def failed_href(request: Request, run_id: int, **params: object) -> str:
    """The failures page of ``run_id``, keeping the shown context."""
    return link(request, f"/scans/{run_id}/failed", **params)


def failure(row) -> dict:
    """One failed image as the failures page and the progress readout show it."""
    error = row["error"] or ""
    return {
        "ref": row["ref"],
        "platform": row["platform"],
        "kind": row["error_kind"] or "unknown",
        "cause": error_cause(error),
        "detail": error_text(error) or None,
        "retried": error.startswith(RETRIED_PREFIX),
        "namespaces": json.loads(row["namespaces"]),
    }


def retry_problem(request: Request, conn: sqlite3.Connection, context: str, run: RunLabel) -> str | None:
    """Why the failed images of ``run`` can't be retried, or None when they can."""
    newest = newest_run(conn, context, cluster_scope=False)
    if newest is None or newest.id != run.id:
        return f"only the newest run of {context} can be retried"
    if newest.status != "partial" or not run_failures(conn, run.id, limit=1)[1]:
        return f"run {run.number} has no failed images"
    trivy = CUSTOM_TRIVY if request.app.state.settings.trivy_path else TRIVY_VERSION
    if newest.trivy_version != trivy:
        return f"run {run.number} was scanned with Trivy {newest.trivy_version}, not {trivy}"
    return None


def default_timeout(settings: Settings) -> int:
    """The retry form's time limit: three times the scan's, as far as the cap allows."""
    return max(MIN_TIMEOUT_S, min(3 * settings.scan_timeout_s, MAX_TIMEOUT_S))


@router.get("/scans/{run_id}/failed", response_class=HTMLResponse)
def failed(request: Request, run_id: int = Path(ge=1, le=MAX_ID), page: int = Query(1, ge=1, le=10**9)) -> HTMLResponse:
    return _page(request, run_id, page)


def _page(
    request: Request,
    run_id: int,
    page: int = 1,
    *,
    error: str | None = None,
    sent: dict | None = None,
    status: int = 200,
    context: str | None = None,
) -> HTMLResponse:
    """The failures page of ``run_id``, with the retry form's ``error`` and what was ``sent`` after a refused POST."""
    with open_db(request) as conn:
        context = shown_context(request, conn, context)
        try:
            run = run_label(conn, context, run_id)
        except RunNotShown as exc:
            return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        rows, total = run_failures(conn, run.id, limit=PER_PAGE, offset=(page - 1) * PER_PAGE)
        auth_refs = auth_failed_refs(conn, run.id) if total else []
        newest = newest_run(conn, context, cluster_scope=False)  # the sidebar's "scanned N ago"
        retryable = retry_problem(request, conn, context, run) is None
        notes = retry_notes(conn, run.id)
    settings = request.app.state.settings
    last_page = max(1, ceil(total / PER_PAGE))
    first = (page - 1) * PER_PAGE + 1
    ctx = {
        "now": request.app.state.clock(),
        "run": newest,
        "shown_run": run,
        "rows": [failure(r) for r in rows],
        "total": total,
        "first": first,
        "last": first + len(rows) - 1,
        "page": page,
        "last_page": last_page,
        "prev_href": failed_href(request, run.id, page=page - 1 if page > 2 else None) if page > 1 else None,
        "next_href": failed_href(request, run.id, page=page + 1) if page < last_page else None,
        "login_hints": login_hints_for(auth_refs),
        "scans_href": link(request, "/scans"),
        "notes": notes,
        "retry": {
            "action": f"/scans/{run.id}/retry",
            "context": context_param(request) or (context if context != request.app.state.context else None),
            "timeout": str(default_timeout(settings)),
            "parallelism": str(min(RETRY_PARALLELISM, settings.parallelism)),
            "min_timeout": MIN_TIMEOUT_S,
            "max_timeout": MAX_TIMEOUT_S,
            "error": error,
            **(sent or {}),
        }
        if retryable or error
        else None,
    }
    return render(request, "failed.html", ctx, status)


@router.post("/scans/{run_id}/retry")
async def retry(request: Request, run_id: int = Path(ge=1, le=MAX_ID)) -> Response:
    body = await request.body()  # the CSRF guard has read it already; the rest blocks, so it runs on a worker thread
    return await run_in_threadpool(_retry, request, run_id, body)


def _retry(request: Request, run_id: int, body: bytes) -> Response:
    try:
        if len(body) > _MAX_BODY:
            raise ValueError
        # Strict both ways, as the guard parses: neither raw bytes nor a %-escape may be anything but UTF-8.
        fields = parse_qs(body.decode(), keep_blank_values=True, max_num_fields=_MAX_FORM_FIELDS, errors="strict")
    except ValueError:
        return _page(request, run_id, error=UNREADABLE, status=400)
    wanted = fields.get("context", [""])[0] or None
    sent = {name: fields.get(name, [""])[0] for name in ("timeout", "parallelism")}

    def page(error: str, status: int) -> HTMLResponse:
        return _page(request, run_id, error=error, sent=sent, status=status, context=wanted)

    with open_db(request) as conn:
        context = shown_context(request, conn, wanted)
        try:
            run = run_label(conn, context, run_id)
        except RunNotShown as exc:
            return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        problem = retry_problem(request, conn, context, run)
    if problem:
        return page(problem, 409)
    try:
        timeout = int(sent["timeout"].strip())
    except ValueError:
        timeout = 0
    if not MIN_TIMEOUT_S <= timeout <= MAX_TIMEOUT_S:
        return page(f"Time limit: must be between {MIN_TIMEOUT_S} and {MAX_TIMEOUT_S} seconds", 400)
    settings = request.app.state.settings
    try:
        valid = Settings.model_validate({**settings.model_dump(), "parallelism": sent["parallelism"].strip()})
    except ValidationError as exc:
        return page(f"Parallel images: {exc.errors()[0]['msg']}", 400)
    try:
        request.app.state.scans.retry(
            run.id, {"scan_timeout_s": timeout, "parallelism": valid.parallelism}, context=context
        )
    except ScanBusy as exc:
        return page(str(exc), 409)
    back = "" if context == request.app.state.context else "?" + urlencode({"context": context})
    return RedirectResponse("/scans" + back, status_code=303)
