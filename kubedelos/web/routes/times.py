"""The scan times page (``GET /scans/{run_id}/times``): where a run's scanning time went.

Each image's scan is timed (retry included) and stored with its result, so this page lists the run's slowest images
and sums up: how many were timed, how many came from the cache, the times added up, the longest, and the part the ten
slowest took. It answers whether a slow run is a few huge images or many ordinary ones. Times overlap when images scan
in parallel, so they add up to more than the run took. Runs scanned before times were recorded have none.
"""

from fastapi import APIRouter, Path, Request
from fastapi.responses import HTMLResponse

from kubedelos.store.queries import SLOWEST_SHARE_OF, RunNotShown, newest_run, run_label, scan_times
from kubedelos.web.pages import MAX_ID, link, open_db, plural, render, seconds_text, short_image, shown_context

router = APIRouter()

SHOWN = 50


@router.get("/scans/{run_id}/times", response_class=HTMLResponse)
def times(request: Request, run_id: int = Path(ge=1, le=MAX_ID)) -> HTMLResponse:
    with open_db(request) as conn:
        context = shown_context(request, conn)
        try:
            run = run_label(conn, context, run_id)
        except RunNotShown as exc:
            return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        rows, summary = scan_times(conn, run.id, SHOWN)
        newest = newest_run(conn, context, cluster_scope=False)  # the sidebar's "scanned N ago"
    chips = [f"{summary.timed} {plural(summary.timed, 'image')} scanned"]
    if summary.cached:
        chips.append(f"{summary.cached} cached")
    if summary.timed:
        chips.append(f"{seconds_text(summary.total_s)} of scanning")
        chips.append(f"longest {seconds_text(summary.longest_s)}")
    if summary.slowest_share is not None and summary.timed > SLOWEST_SHARE_OF:
        chips.append(f"the {SLOWEST_SHARE_OF} slowest took {round(summary.slowest_share * 100)}%")
    ctx = {
        "now": request.app.state.clock(),
        "run": newest,
        "shown_run": run,
        "chips": chips,
        "timed": summary.timed,
        "parallel_note": summary.timed > 1,
        "rows": [
            {
                "ref": r["ref"],
                "short": short_image({"repo": r["repo"], "tag": r["tag"], "digest": r["digest"], "image": r["ref"]}),
                "platform": r["platform"],
                "status": (r["error_kind"] or "unknown") if r["status"] == "error" else r["status"],
                "failed": r["status"] == "error",
                "time": seconds_text(r["duration_s"]),
            }
            for r in rows
        ],
        "shown": SHOWN,
        "failed_href": link(request, f"/scans/{run.id}/failed"),
        "scans_href": link(request, "/scans"),
    }
    return render(request, "times.html", ctx)
