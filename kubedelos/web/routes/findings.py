"""The findings page (``GET /findings``): every finding unit of one run, filtered, sorted and paged through the URL.

All state lives in the query string so a filtered view can be bookmarked or linked from the dashboard. Filtering,
ordering and paging happen in SQL, so a run of 100,000 findings renders one page of 100 rows.
"""

import json
from math import ceil
from typing import Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from kubedelos.models import Severity
from kubedelos.output import short_image
from kubedelos.store.queries import (
    FindingFilter,
    RunNotShown,
    findings_page,
    get_run,
    newest_run,
    run_namespaces,
)
from kubedelos.web.app import MAX_ID, open_db, render

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
)


def _row(r) -> dict:
    namespaces = json.loads(r["namespaces"])
    return {
        "severity": r["severity"],
        "vuln_id": r["vuln_id"],
        "primary_url": r["primary_url"],
        "pkg_name": r["pkg_name"],
        "installed": r["installed_version"],
        "fixed": r["fixed_version"],
        "pkg_class": r["pkg_class"],
        "ref": r["ref"],
        "image": short_image({"repo": r["repo"], "tag": r["tag"], "digest": r["digest"], "image": r["ref"]}),
        "namespaces": namespaces[:NAMESPACES_SHOWN],
        "more_namespaces": max(0, len(namespaces) - NAMESPACES_SHOWN),
    }


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
    sort: Literal["severity", "cve", "package", "image", "namespace", "fixed"] | None = None,
    direction: Literal["asc", "desc"] | None = Query(None, alias="dir"),
    page: int = Query(1, ge=1, le=10**9),
) -> HTMLResponse:
    context = request.app.state.context
    ctx: dict = {"now": request.app.state.clock(), "run": None, "pinned": run_id is not None}
    with open_db(request) as conn:
        if run_id is not None:
            try:
                run = get_run(conn, context, run_id)
            except RunNotShown as exc:
                return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        else:
            run = newest_run(conn, context, cluster_scope=False)
        if run is None:
            return render(request, "findings.html", ctx)
        sort_key = sort or "severity"
        desc = direction == "desc" if direction else sort_key == "severity"
        flt = FindingFilter(
            severities=tuple(s.value for s in severity),
            namespace=namespace or None,
            cve=cve or None,
            package=package or None,
            has_fix=has_fix,
            pkg=pkg,
            q=q or None,
            sort=sort_key,
            desc=desc,
        )
        rows, total = findings_page(conn, run.id, flt, page, PER_PAGE)
        all_namespaces = run_namespaces(conn, run.id)

    def href(**over: object) -> str:
        """This view's URL with ``over`` replacing its parameters; a None value drops the parameter."""
        state: dict[str, object] = {
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
            "page": page if page > 1 else None,
        }
        state.update(over)
        return "/findings?" + urlencode([(k, v) for k, v in state.items() if v is not None and v != []], doseq=True)

    last_page = max(1, ceil(total / PER_PAGE))
    start = (page - 1) * PER_PAGE + 1
    filtered = bool(severity or flt.namespace or flt.cve or flt.package or flt.q or has_fix != "any" or pkg != "all")
    headers = [
        {
            "label": label,
            "href": href(sort=key, dir=("asc" if desc else "desc") if key == sort_key else None, page=None)
            if key
            else None,
            "aria_sort": ("descending" if desc else "ascending") if key == sort_key else None,
        }
        for key, label in COLUMNS
    ]
    ctx.update(
        run=run,
        rows=[_row(r) for r in rows],
        total=total,
        page=page,
        first=start,
        last=start + len(rows) - 1,
        past_end=not rows and total > 0,
        filtered=filtered,
        headers=headers,
        clear_href=f"/findings?{urlencode({'run_id': run.id})}",
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
        },
        severities=[s.value for s in Severity],
        sort=sort,
        direction=direction,
    )
    return render(request, "findings.html", ctx)
