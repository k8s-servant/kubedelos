"""Reports: a CSV of the findings view as filtered (``GET /findings.csv``), a print sheet of a run (``GET /report``),
and the Reports page (``GET /reports``) that picks a run and the filters for either.

The CSV takes the findings page's query parameters (``findings.view_filter`` reads them the same way), holds every row
of the view rather than one page, and is streamed from SQL in batches, so a run of 100,000 findings never sits in
memory. Every cell is formula-safe: one that a spreadsheet would run as a formula gets a leading ``'``. The stream has a
read-only connection of its own, opened after the run was checked: the response is produced on worker threads.

The print sheet shows the dashboard's run (or the pinned ``run_id``): its numbers, the fix-first list with the accepted
findings it leaves out, and the failed images. A print stylesheet drops the UI around it; the browser saves it as PDF.

The Reports page only holds GET forms that send what the two reports already take, so it can never drift from them.
"""

import csv
import io
import json
import re
from collections.abc import Iterator
from dataclasses import replace

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from kubedelos.models import Severity
from kubedelos.store import db
from kubedelos.store.queries import (
    FindingFilter,
    RunNotShown,
    failed_images,
    findings_export,
    fix_by_fix,
    get_run,
    kpis,
    newest_run,
    result_runs,
    run_namespaces,
)
from kubedelos.trivy.runner import error_cause
from kubedelos.web.pages import MAX_ID, open_db, render, risk_view, shown_context
from kubedelos.web.routes.findings import view_filter

router = APIRouter()

CSV_SEVERITIES = ("CRITICAL", "HIGH")  # ticked on the Reports page's CSV form
COLUMNS = (
    "severity",
    "cve",
    "package",
    "installed",
    "fixed_in",
    "class",
    "image",
    "namespaces",
    "accepted",
    "title",
    "url",
    "risk",
)
BATCH = 1000
REPORT_FIXES = 50
REPORT_FAILED = 100
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_cell(value: object) -> str:
    """``value`` as CSV cell text that no spreadsheet runs as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def _line(cells: list[object]) -> str:
    out = io.StringIO()
    csv.writer(out).writerow([safe_cell(c) for c in cells])
    return out.getvalue()


def _cells(r) -> list[object]:
    """One export row's cells, in ``COLUMNS`` order."""
    namespaces = "; ".join(json.loads(r["namespaces"]))
    accepted = "yes" if r["accepted"] else "no"
    return [
        r["severity"], r["vuln_id"], r["pkg_name"], r["installed_version"], r["fixed_version"], r["pkg_class"],
        r["ref"], namespaces, accepted, r["title"], r["primary_url"], r["score"],
    ]  # fmt: skip


def _not_shown(request: Request, exc: RunNotShown) -> HTMLResponse:
    return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)


@router.get("/findings.csv", response_model=None)
def findings_csv(
    request: Request,
    run_id: int = Query(ge=1, le=MAX_ID),
    flt: FindingFilter = Depends(view_filter),  # noqa: B008 - FastAPI declares dependencies this way
) -> Response:
    with open_db(request) as conn:
        context = shown_context(request, conn)
        cluster = request.state.cluster
        try:
            run = get_run(conn, cluster, run_id)
        except RunNotShown as exc:
            return _not_shown(request, exc)
        flt = replace(flt, scored=risk_view(conn, run.id)["risk_shown"])
    path = request.app.state.settings.db_path
    today = request.app.state.clock().date()

    def rows() -> Iterator[str]:
        conn = db.connect_readonly(path, check_same_thread=False)  # used by one stream, a batch at a time
        try:
            cursor = findings_export(conn, run.id, flt, today=today)
            yield _line(list(COLUMNS))
            while batch := cursor.fetchmany(BATCH):
                yield "".join(_line(_cells(r)) for r in batch)
        finally:
            conn.close()

    name = f"kubedelos-{_UNSAFE_NAME.sub('_', context)}-run{run.number}.csv"
    return StreamingResponse(
        rows(), media_type="text/csv; charset=utf-8", headers={"content-disposition": f'attachment; filename="{name}"'}
    )


@router.get("/report", response_class=HTMLResponse)
def report(request: Request, run_id: int | None = Query(None, ge=1, le=MAX_ID)) -> HTMLResponse:
    now = request.app.state.clock()
    ctx: dict = {"now": now, "run": None, "shown": None}
    with open_db(request) as conn:
        shown_context(request, conn)
        cluster = request.state.cluster
        try:
            run = get_run(conn, cluster, run_id) if run_id else newest_run(conn, cluster, cluster_scope=True)
        except RunNotShown as exc:
            return _not_shown(request, exc)
        ctx["run"] = newest_run(conn, cluster, cluster_scope=False)
        if run is None:
            return render(request, "report.html", ctx)
        counts = kpis(conn, run.id)
        risk = risk_view(conn, run.id)
        fixes = fix_by_fix(conn, run.id, REPORT_FIXES, today=now.date(), scored=risk["risk_shown"])
        failed, failed_total = failed_images(conn, run.id, REPORT_FAILED) if counts.images_failed else ([], 0)
    ctx.update(
        risk,
        shown=run,
        kpis=counts,
        fixes=fixes,
        failed=[(r["ref"], r["platform"], r["error_kind"], error_cause(r["error"])) for r in failed],
        failed_total=failed_total,
    )
    return render(request, "report.html", ctx)


@router.get("/reports", response_class=HTMLResponse)
def reports(request: Request) -> HTMLResponse:
    with open_db(request) as conn:
        shown_context(request, conn)
        cluster = request.state.cluster
        choices = result_runs(conn, cluster)
        namespaces = run_namespaces(conn, choices[0].id) if choices else []
        newest = newest_run(conn, cluster, cluster_scope=False)  # the sidebar's "scanned N ago"
    ctx = {
        "now": request.app.state.clock(),
        "run": newest,
        "choices": choices,
        "namespaces": namespaces,
        "severities": [(s.value, s.value in CSV_SEVERITIES) for s in Severity],
    }
    return render(request, "reports.html", ctx)
