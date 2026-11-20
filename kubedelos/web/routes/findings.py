"""The findings page (``GET /findings``): every finding unit of one run, filtered, sorted and paged through the URL.

All state lives in the query string so a filtered view can be bookmarked or linked from the dashboard. Filtering,
ordering and paging happen in SQL, so a run of 100,000 findings renders one page of 100 rows. Accepted findings are left
out by default (``accepted=hide``) and the page says how many; each row links to the Accept… form, prefilled.
"""

import json
from dataclasses import replace
from math import ceil
from typing import Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from kubedelos.models import Severity
from kubedelos.store.queries import (
    FindingFilter,
    RunNotShown,
    findings_page,
    get_run,
    newest_run,
    run_namespaces,
)
from kubedelos.web.pages import MAX_ID, context_param, link, open_db, render, risk_view, short_name, shown_context

router = APIRouter()

PER_PAGE = 100
NAMESPACES_SHOWN = 3
COLUMNS = (
    ("severity", "Severity"),
    ("cve", "CVE"),
    ("package", "Package"),
    (None, "Installed"),
    ("fixed", "Fixed in"),
    (None, "Class"),
    ("image", "Image"),
    ("namespace", "Namespaces"),
    (None, "Status"),
)
# The first column, as on the dashboard, when the run's score says more than its severity.
RISK_COLUMN = ("risk", "Risk")


def _row(request: Request, r, namespace: str | None) -> dict:
    namespaces = json.loads(r["namespaces"])
    return {
        "accepted": bool(r["accepted"]),
        "accepted_href": link(request, "/accepted", cve=r["vuln_id"]),
        "accept_href": link(
            request, "/accepted/new", cve=r["vuln_id"], package=r["pkg_name"], image=r["repo"], namespace=namespace
        ),
        "severity": r["severity"],
        "vuln_id": r["vuln_id"],
        "primary_url": r["primary_url"],
        "pkg_name": r["pkg_name"],
        "installed": r["installed_version"],
        "fixed": r["fixed_version"],
        "pkg_class": r["pkg_class"],
        "ref": r["ref"],
        "image": short_name(r["ref"]),
        "namespaces": namespaces[:NAMESPACES_SHOWN],
        "more_namespaces": max(0, len(namespaces) - NAMESPACES_SHOWN),
        "score": r["score"],
    }


Sort = Literal["severity", "cve", "package", "image", "namespace", "fixed", "risk"]


def view_filter(
    severity: list[Severity] = Query([]),  # noqa: B008 - FastAPI declares query parameters this way
    namespace: str | None = None,
    cve: str | None = None,
    package: str | None = None,
    has_fix: Literal["any", "yes", "no"] = "any",
    pkg: Literal["all", "os", "library"] = "all",
    q: str | None = None,
    sort: Sort | None = None,
    accepted: Literal["hide", "only", "all"] = "hide",
    direction: Literal["asc", "desc"] | None = Query(None, alias="dir"),
) -> FindingFilter:
    """The findings view the query string asks for; the findings page and its CSV read it the same way."""
    sort_key = sort or "severity"
    return FindingFilter(
        severities=tuple(s.value for s in severity),
        namespace=namespace or None,
        cve=cve or None,
        package=package or None,
        has_fix=has_fix,
        pkg=pkg,
        q=q or None,
        sort=sort_key,
        desc=direction == "desc" if direction else sort_key in ("severity", "risk"),
        accepted=accepted,
    )


@router.get("/findings", response_class=HTMLResponse)
def findings(
    request: Request,
    run_id: int | None = Query(None, ge=1, le=MAX_ID),
    severity: list[Severity] = Query([]),  # noqa: B008 - FastAPI declares query parameters this way
    namespace: str | None = None,
    cve: str | None = None,
    package: str | None = None,
    has_fix: Literal["any", "yes", "no"] = "any",
    pkg: Literal["all", "os", "library"] = "all",
    q: str | None = None,
    sort: Sort | None = None,
    accepted: Literal["hide", "only", "all"] = "hide",
    direction: Literal["asc", "desc"] | None = Query(None, alias="dir"),
    page: int = Query(1, ge=1, le=10**9),
) -> HTMLResponse:
    ctx: dict = {"now": request.app.state.clock(), "run": None, "pinned": run_id is not None}
    with open_db(request) as conn:
        context = shown_context(request, conn)
        if run_id is not None:
            try:
                run = get_run(conn, context, run_id)
            except RunNotShown as exc:
                return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        else:
            run = newest_run(conn, context, cluster_scope=False)
        if run is None:
            return render(request, "findings.html", ctx)
        risk = risk_view(conn, run.id)
        flt = replace(
            view_filter(severity, namespace, cve, package, has_fix, pkg, q, sort, accepted, direction),
            scored=risk["risk_shown"],
        )
        sort_key, desc = flt.sort, flt.desc
        today = request.app.state.clock().date()
        rows, total, left_out = findings_page(conn, run.id, flt, page, PER_PAGE, today=today)
        all_namespaces = run_namespaces(conn, run.id)

    def href(**over: object) -> str:
        """This view's URL with ``over`` replacing its parameters; a None value drops the parameter."""
        state: dict[str, object] = {
            "context": context_param(request),
            "run_id": run.id,
            "severity": [s.value for s in severity],
            "namespace": flt.namespace,
            "cve": flt.cve,
            "package": flt.package,
            "has_fix": has_fix if has_fix != "any" else None,
            "pkg": pkg if pkg != "all" else None,
            "q": flt.q,
            "sort": sort,
            "dir": direction,
            "accepted": accepted if accepted != "hide" else None,
            "page": page if page > 1 else None,
        }
        state.update(over)
        return "/findings?" + urlencode([(k, v) for k, v in state.items() if v is not None and v != []], doseq=True)

    last_page = max(1, ceil(total / PER_PAGE))
    start = (page - 1) * PER_PAGE + 1
    filtered = (
        bool(severity or flt.namespace or flt.cve or flt.package or flt.q or has_fix != "any" or pkg != "all")
        or accepted != "hide"
    )
    headers = [
        {
            "label": label,
            "href": href(sort=key, dir=("asc" if desc else "desc") if key == sort_key else None, page=None)
            if key
            else None,
            "aria_sort": ("descending" if desc else "ascending") if key == sort_key else None,
        }
        for key, label in ((RISK_COLUMN, *COLUMNS) if risk["risk_shown"] else COLUMNS)
    ]
    ctx.update(
        risk,
        run=run,
        rows=[_row(request, r, flt.namespace) for r in rows],
        left_out=left_out if accepted == "hide" else 0,
        accepted_only_href=href(accepted="only", page=None),
        csv_href=href(page=None).replace("/findings?", "/findings.csv?", 1),
        total=total,
        page=page,
        first=start,
        last=start + len(rows) - 1,
        past_end=not rows and total > 0,
        filtered=filtered,
        headers=headers,
        clear_href=link(request, "/findings", run_id=run.id),
        prev_href=href(page=page - 1 if page > 2 else None) if page > 1 and rows else None,
        next_href=href(page=page + 1) if page < last_page and rows else None,
        last_page_href=href(page=last_page if last_page > 1 else None),
        last_page=last_page,
        os_only=run.pkg_types == "os",
        namespaces=all_namespaces,
        selected={
            "severity": [s.value for s in severity],
            "namespace": flt.namespace,
            "cve": flt.cve or "",
            "package": flt.package or "",
            "has_fix": has_fix,
            "pkg": pkg,
            "q": flt.q or "",
            "accepted": accepted,
        },
        severities=[s.value for s in Severity],
        sort=sort,
        direction=direction,
    )
    return render(request, "findings.html", ctx)
