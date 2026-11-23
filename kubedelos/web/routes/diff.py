"""The compare page (``GET /diff``): what changed between two result runs of the shown context.

By default it compares the dashboard's run (the newest whole-cluster run) with its previous comparable run; ``from``
and ``to`` pick any two result runs of the context, in either order (the older one is always "from"). Differences in
what was scanned, failed images and coverage gaps are named above the numbers, since each can make a finding look new
or gone when nothing changed. ``kubedelos.store.diff`` does the comparing.
"""

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from kubedelos.analytics import describe_pkg_types, describe_scope
from kubedelos.store.diff import compare
from kubedelos.store.queries import Run, RunNotShown, get_run, newest_run, previous_comparable, result_runs
from kubedelos.web.pages import MAX_ID, link, open_db, plural, render, shown_context

router = APIRouter()

LIMIT = 100


def _cautions(old: Run, new: Run) -> list[str]:
    """What, besides real change, can make a finding look new or gone between ``old`` and ``new``."""
    notes = []
    if old.scope != new.scope or old.pkg_types != new.pkg_types:
        notes.append(
            "These runs scanned different things, so some differences come from that, not from the cluster: "
            f"run {old.number} covered {describe_scope(old.scope)}, {describe_pkg_types(old.pkg_types)}; "
            f"run {new.number} covered {describe_scope(new.scope)}, {describe_pkg_types(new.pkg_types)}."
        )
    for run in (old, new):
        if run.images_failed:
            notes.append(
                f"Run {run.number} had {run.images_failed} failed {plural(run.images_failed, 'image')}: "
                "their findings are missing from it, so they can look gone or new."
            )
        if run.gaps:
            notes.append(f"Run {run.number} could not list everything: {'; '.join(run.gaps)}.")
    return notes


@router.get("/diff", response_class=HTMLResponse)
def diff(
    request: Request,
    from_id: int | None = Query(None, alias="from", ge=1, le=MAX_ID),
    to_id: int | None = Query(None, alias="to", ge=1, le=MAX_ID),
) -> HTMLResponse:
    now = request.app.state.clock()
    ctx: dict = {"now": now, "run": None, "old": None, "new": None, "result": None}
    with open_db(request) as conn:
        shown_context(request, conn)
        cluster = request.state.cluster
        try:
            new = get_run(conn, cluster, to_id) if to_id else newest_run(conn, cluster, cluster_scope=True)
            new = new or newest_run(conn, cluster, cluster_scope=False)
            old = get_run(conn, cluster, from_id) if from_id else (previous_comparable(conn, new) if new else None)
        except RunNotShown as exc:
            return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        ctx.update(run=newest_run(conn, cluster, cluster_scope=False), choices=result_runs(conn, cluster))
        if new is None:
            return render(request, "diff.html", ctx)
        if old is not None and old.id > new.id:
            old, new = new, old
        ctx.update(old=old, new=new)
        if old is None or old.id == new.id:
            return render(request, "diff.html", ctx)
        result = compare(conn, old.id, new.id, LIMIT)

    def findings(run: Run, f) -> str:
        return link(request, "/findings", run_id=run.id, cve=f.vuln_id, package=f.pkg_name)

    ctx.update(
        result=result,
        cautions=_cautions(old, new),
        new_rows=[(f, findings(new, f)) for f in result.new],
        gone_rows=[(f, findings(old, f)) for f in result.gone],
        limit=LIMIT,
        tiles=[
            ("new", "New findings", result.new_total),
            ("gone", "Fixed or gone", result.gone_total),
            ("added", "Images added", result.images_added_total),
            ("removed", "Images gone", result.images_gone_total),
            ("changed", "Images changed", result.images_changed_total),
        ],
    )
    return render(request, "diff.html", ctx)
