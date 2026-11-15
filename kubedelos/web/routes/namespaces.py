"""The namespaces page: one row per namespace of the shown run, worst first, each count a link to its findings.

It shows the run the dashboard shows (the newest whole-cluster run of the shown context, or the pinned ``run_id``), so a
one-namespace scan is never read as the cluster. A namespace counts a finding when the finding's image runs in it, as
the findings page's namespace filter does, so each count equals the findings its link opens. Sorting and the filters
work on the run's rows in memory: a run has at most a few hundred namespaces, and every one is listed.
"""

from typing import Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from kubedelos.models import Severity
from kubedelos.store.queries import NamespaceRow, RunNotShown, get_run, namespace_counts, newest_run
from kubedelos.web.pages import MAX_ID, context_param, link, open_db, render, shown_context

router = APIRouter()

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
Sort = Literal["namespace", "owner", "team", "critical", "high", "medium", "low", "unknown", "total", "images"]
COLUMNS: tuple[tuple[Sort, str], ...] = (
    ("namespace", "Namespace"),
    ("owner", "Owner"),
    ("team", "Team"),
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("unknown", "Unknown"),
    ("total", "Total"),
    ("images", "Images"),
)
_TEXT = ("namespace", "owner", "team")


def _worst_first(row: NamespaceRow) -> tuple:
    return (-row.counts["CRITICAL"], -row.counts["HIGH"], -row.total, row.namespace)


def _ordered(rows: list[NamespaceRow], sort: Sort | None, desc: bool) -> list[NamespaceRow]:
    """``rows`` in the page's order: worst first by default; by text with blanks last, or by a number, otherwise."""
    if sort is None:
        return sorted(rows, key=_worst_first)
    if sort in _TEXT:
        present = [r for r in rows if getattr(r, sort)]
        blank = [r for r in rows if not getattr(r, sort)]
        present.sort(key=lambda r: (getattr(r, sort).casefold(), r.namespace), reverse=desc)
        return present + sorted(blank, key=lambda r: r.namespace)

    def number(row: NamespaceRow) -> int:
        return getattr(row, sort) if sort in ("total", "images") else row.counts[sort.upper()]

    return sorted(rows, key=lambda r: (-number(r) if desc else number(r), r.namespace))


@router.get("/namespaces", response_class=HTMLResponse)
def namespaces(
    request: Request,
    run_id: int | None = Query(None, ge=1, le=MAX_ID),
    q: str | None = None,
    has: Severity | None = None,
    sort: Sort | None = None,
    direction: Literal["asc", "desc"] | None = Query(None, alias="dir"),
) -> HTMLResponse:
    now = request.app.state.clock()
    ctx: dict = {"now": now, "run": None, "pinned": run_id is not None}
    with open_db(request) as conn:
        context = shown_context(request, conn)
        if run_id is not None:
            try:
                run = get_run(conn, context, run_id)
            except RunNotShown as exc:
                return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        else:
            run = newest_run(conn, context, cluster_scope=True)
        if run is None:
            newest_any = newest_run(conn, context, cluster_scope=False)
            ctx["narrower_href"] = link(request, "/findings", run_id=newest_any.id) if newest_any else None
            return render(request, "namespaces.html", ctx)
        all_rows = namespace_counts(conn, run.id)

    text = (q or "").strip().casefold()
    rows = [
        r
        for r in all_rows
        if (not text or any(text in (getattr(r, f) or "").casefold() for f in _TEXT))
        and (has is None or r.counts[has.value] > 0)
    ]
    # Numbers read best biggest first, names A to Z, so a column's first click goes that way.
    desc = direction == "desc" if direction else sort not in _TEXT

    def href(**over: object) -> str:
        """This view's URL with ``over`` replacing its parameters; a None value drops the parameter."""
        state: dict[str, object] = {
            "context": context_param(request),
            "run_id": run_id,
            "q": q or None,
            "has": has.value if has else None,
            "sort": sort,
            "dir": direction,
        }
        state.update(over)
        query = urlencode([(k, v) for k, v in state.items() if v is not None])
        return "/namespaces?" + query if query else "/namespaces"

    def findings(row: NamespaceRow, severity: str | None = None) -> str:
        return link(request, "/findings", run_id=run.id, namespace=row.namespace, severity=severity)

    headers = [
        {
            "label": label,
            "numeric": key not in _TEXT,
            "href": href(sort=key, dir=("asc" if desc else "desc") if key == sort else None),
            "aria_sort": ("descending" if desc else "ascending") if key == sort else None,
        }
        for key, label in COLUMNS
    ]
    ctx.update(
        run=run,
        rows=[
            {
                "namespace": r.namespace,
                "owner": r.owner,
                "team": r.team,
                "cells": [(r.counts[s], findings(r, s) if r.counts[s] else None) for s in SEVERITIES],
                "total": r.total,
                "total_href": findings(r) if r.total else None,
                "images": r.images,
            }
            for r in _ordered(rows, sort, desc)
        ],
        shown=len(rows),
        all=len(all_rows),
        headers=headers,
        severities=SEVERITIES,
        selected={"q": q or "", "has": has.value if has else ""},
        sort=sort,
        direction=direction,
        clear_href=href(q=None, has=None),
    )
    return render(request, "namespaces.html", ctx)
