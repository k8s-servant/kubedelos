"""The failures page (``GET /scans/{run_id}/failed``): every image of one run that failed to scan, and why.

It shows any run of the shown context, whatever its status, so a running, cancelled or narrow run's failures can be
read too; the dashboard's card only counts its own run's failures by kind. Each row names the image short
(``short_image``) and gives the cause in a few words (``short_cause``); the full ref and the redacted error text are
folded away. Auth failures add the registry login hints. ``?kind=`` narrows the list to one error kind, with a count
per kind to pick from. Paged in SQL, 100 rows a page.

The newest result run of a context, once it finished ``partial``, also offers a retry of its failed images
(``POST /scans/{run_id}/retry``, with the CSRF token): the app's ``ScanRunner`` scans them again with the posted time
limit and parallelism and puts the results into the same run (see ``kubedelos.scan.service.retry_failed``). It
retries only the ticked kinds of failure: all but ``not_found`` at first (a missing tag stays missing until someone
pushes it), or just the kind the page is narrowed to. The page lists the notes earlier retries left. In
``kubedelos serve`` the retry is queued for the worker instead, as ``POST /scans`` queues a scan.
"""

import json
import re
import sqlite3
from math import ceil
from typing import get_args
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
    failure_kinds,
    newest_run,
    retry_notes,
    run_failures,
    run_label,
)
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.trivy.runner import RETRIED_PREFIX, ErrorKind, error_cause, error_text
from kubedelos.web.jobs import ScanBusy
from kubedelos.web.pages import (
    MAX_ID,
    context_param,
    link,
    open_db,
    queue_ui_request,
    render,
    seconds_text,
    short_image,
    shown_context,
)

router = APIRouter()

PER_PAGE = 100
MIN_TIMEOUT_S, MAX_TIMEOUT_S = 60, 3600
RETRY_PARALLELISM = 2
_MAX_FORM_FIELDS = 20
_MAX_BODY = 4 * 1024
UNREADABLE = "the form could not be read"
NOT_TICKED = frozenset({"not_found"})  # kinds a retry rarely fixes, so the form leaves them unticked
NO_KIND = "Tick at least one kind of failure to retry"

# What each error kind means and what to do about it, as the dashboard's failed-images card says it.
KIND_HELP: dict[str, str] = {
    "timeout": "Trivy ran out of time, usually on a large image. A retry with a longer time limit fixes most.",
    "not_found": "The tag or digest is no longer in the registry, so the workload can't pull it either.",
    "auth": "The registry refused access. Log in to it and scan again.",
    "trivy": "Trivy could not read the image. The error text is on the failures page.",
    "unknown": "Something else went wrong. The error text is on the failures page.",
}
_FINISHED_WITHIN = re.compile(r"did not finish within (\d+)s")
_MISSING_TAG = re.compile(r'manifest tagged by "([^"]{1,128})" is not found')


def short_cause(kind: str | None, error: str | None) -> str:
    """What went wrong, in a few words: a plain sentence for the kinds that say it all, else ``error_cause``."""
    text = error or ""
    if kind == "timeout":
        limit = _FINISHED_WITHIN.search(text)
        return f"did not finish within {limit[1]} s" if limit else "ran out of time while analysing the image"
    if kind == "not_found":
        tag = _MISSING_TAG.search(text)
        return f"tag {tag[1]} is not in the registry" if tag else "the image is not in the registry"
    if kind == "auth":
        return "the registry refused access"
    return error_cause(text) if text else ""


def failed_href(request: Request, run_id: int, **params: object) -> str:
    """The failures page of ``run_id``, keeping the shown context."""
    return link(request, f"/scans/{run_id}/failed", **params)


def failure(row) -> dict:
    """One failed image as the failures page and the progress readout show it."""
    error = row["error"] or ""
    return {
        "ref": row["ref"],
        "short": short_image({"repo": row["repo"], "tag": row["tag"], "digest": row["digest"], "image": row["ref"]}),
        "platform": row["platform"],
        "kind": row["error_kind"] if row["error_kind"] in KIND_HELP else "unknown",
        "cause": short_cause(row["error_kind"], error),
        "detail": error_text(error) or None,
        "retried": error.startswith(RETRIED_PREFIX),
        "time": seconds_text(row["duration_s"]),
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
def failed(
    request: Request,
    run_id: int = Path(ge=1, le=MAX_ID),
    page: int = Query(1, ge=1, le=10**9),
    kind: ErrorKind | None = None,
) -> HTMLResponse:
    return _page(request, run_id, page, kind=kind)


def _page(
    request: Request,
    run_id: int,
    page: int = 1,
    *,
    error: str | None = None,
    sent: dict | None = None,
    status: int = 200,
    context: str | None = None,
    kind: str | None = None,
    sent_kinds: frozenset[str] | None = None,
) -> HTMLResponse:
    """The failures page of ``run_id``, narrowed to ``kind`` if given, with the retry form's ``error`` and what was
    ``sent`` (and ``sent_kinds``) after a refused POST.
    """
    with open_db(request) as conn:
        context = shown_context(request, conn, context)
        try:
            run = run_label(conn, context, run_id)
        except RunNotShown as exc:
            return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        kinds = failure_kinds(conn, run.id)
        rows, shown = run_failures(conn, run.id, limit=PER_PAGE, offset=(page - 1) * PER_PAGE, kind=kind)
        total = sum(n for _, n in kinds)
        auth_refs = auth_failed_refs(conn, run.id) if total else []
        newest = newest_run(conn, context, cluster_scope=False)  # the sidebar's "scanned N ago"
        retryable = retry_problem(request, conn, context, run) is None
        notes = retry_notes(conn, run.id)
    settings = request.app.state.settings
    present = {k for k, _ in kinds}
    if sent_kinds is not None:
        ticked = sent_kinds
    elif kind is not None:
        ticked = {kind}
    else:
        ticked = (present - NOT_TICKED) or present
    last_page = max(1, ceil(shown / PER_PAGE))
    first = (page - 1) * PER_PAGE + 1
    ctx = {
        "now": request.app.state.clock(),
        "run": newest,
        "shown_run": run,
        "rows": [failure(r) for r in rows],
        "total": total,
        "shown": shown,
        "kind": kind,
        "kinds": [
            {"label": "all", "count": total, "current": kind is None, "href": failed_href(request, run.id)},
            *(
                {"label": k, "count": n, "current": k == kind, "href": failed_href(request, run.id, kind=k)}
                for k, n in kinds
            ),
        ],
        "first": first,
        "last": first + len(rows) - 1,
        "page": page,
        "last_page": last_page,
        "prev_href": failed_href(request, run.id, kind=kind, page=page - 1 if page > 2 else None) if page > 1 else None,
        "next_href": failed_href(request, run.id, kind=kind, page=page + 1) if page < last_page else None,
        "login_hints": login_hints_for(auth_refs),
        "scans_href": link(request, "/scans"),
        "times_href": link(request, f"/scans/{run.id}/times"),
        "notes": notes,
        "retry": {
            "action": f"/scans/{run.id}/retry",
            "context": context_param(request) or (context if context != request.app.state.context else None),
            "timeout": str(default_timeout(settings)),
            "parallelism": str(min(RETRY_PARALLELISM, settings.parallelism)),
            "min_timeout": MIN_TIMEOUT_S,
            "max_timeout": MAX_TIMEOUT_S,
            "kinds": [{"name": k, "count": n, "checked": k in ticked} for k, n in kinds],
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
    chosen = frozenset(k for k in fields.get("kind", []) if k in get_args(ErrorKind))

    def page(error: str, status: int) -> HTMLResponse:
        return _page(request, run_id, error=error, sent=sent, status=status, context=wanted, sent_kinds=chosen)

    with open_db(request) as conn:
        context = shown_context(request, conn, wanted)
        try:
            if request.app.state.serve and context != request.app.state.context:
                # serve scans only its own cluster, so a run kept from another context can't be retried here.
                raise RunNotShown(f"only runs of {request.app.state.context} can be retried here")
            run = run_label(conn, context, run_id)
        except RunNotShown as exc:
            return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        problem = retry_problem(request, conn, context, run)
        present = {k for k, _ in failure_kinds(conn, run.id)}
    if problem:
        return page(problem, 409)
    if not chosen:
        return page(NO_KIND, 400)
    if missing := sorted(chosen - present):
        return page(f"Run {run.number} has no {', '.join(missing)} failures to retry", 400)
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
    if request.app.state.serve:
        wanted = {"scan_timeout_s": timeout, "parallelism": valid.parallelism, "kinds": sorted(chosen)}
        return queue_ui_request(request, kind="retry", overrides=wanted, target_run_id=run.id, on_error=page)
    try:
        request.app.state.scans.retry(
            run.id, {"scan_timeout_s": timeout, "parallelism": valid.parallelism}, context=context, kinds=set(chosen)
        )
    except ScanBusy as exc:
        return page(str(exc), 409)
    back = "" if context == request.app.state.context else "?" + urlencode({"context": context})
    return RedirectResponse("/scans" + back, status_code=303)
