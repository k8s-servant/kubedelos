"""The failures page (``GET /scans/{run_id}/failed``): every image of one run that failed to scan, and why.

It shows any run of the shown context, whatever its status, so a running, cancelled or narrow run's failures can be
read too; the dashboard's panel shows only its own run, capped. Each row gives the cause (``error_cause``, which
redacts credentials) and, folded away, the redacted error text; auth failures add the registry login hints. Paged in
SQL, 100 rows a page.
"""

import json
from math import ceil

from fastapi import APIRouter, Path, Query, Request
from fastapi.responses import HTMLResponse

from kubedelos.hints import login_hints_for
from kubedelos.store.queries import RunNotShown, auth_failed_refs, newest_run, run_failures, run_label
from kubedelos.trivy.runner import RETRIED_PREFIX, error_cause, error_text
from kubedelos.web.pages import MAX_ID, link, open_db, render, shown_context

router = APIRouter()

PER_PAGE = 100


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


@router.get("/scans/{run_id}/failed", response_class=HTMLResponse)
def failed(request: Request, run_id: int = Path(ge=1, le=MAX_ID), page: int = Query(1, ge=1, le=10**9)) -> HTMLResponse:
    with open_db(request) as conn:
        context = shown_context(request, conn)
        try:
            run = run_label(conn, context, run_id)
        except RunNotShown as exc:
            return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        rows, total = run_failures(conn, run.id, limit=PER_PAGE, offset=(page - 1) * PER_PAGE)
        auth_refs = auth_failed_refs(conn, run.id) if total else []
        newest = newest_run(conn, context, cluster_scope=False)  # the sidebar's "scanned N ago"
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
    }
    return render(request, "failed.html", ctx)
