"""The dashboard (``GET /``): which run is shown, the KPI tiles, the severity bar, the fix-first list and the worst images.

The page answers "how is this cluster doing", so it shows the newest whole-cluster run and never lets an incomplete run
read as a clean cluster: coverage gaps and failed images mark the run line and the tiles.
"""

from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from kubedelos.analytics import ago, delta, describe_scope
from kubedelos.hints import login_hint
from kubedelos.kube.inventory import parse_image_id
from kubedelos.models import registry_host
from kubedelos.output import short_image
from kubedelos.store.queries import (
    SAMPLE_CAP,
    Kpis,
    Run,
    RunNotShown,
    WorstImage,
    auth_failed_refs,
    failed_images,
    fix_by_fix,
    fix_by_image,
    get_run,
    kpis,
    newest_run,
    previous_comparable,
    worst_images,
)
from kubedelos.trivy.runner import error_cause
from kubedelos.web.pages import MAX_ID, open_db, render

router = APIRouter()

CAUTION = "either run had failed images or skipped namespaces"


@dataclass(frozen=True)
class Tile:
    key: str
    label: str
    value: int
    suffix: str
    change: str
    change_caution: bool
    caution: bool
    error: bool = False


@dataclass(frozen=True)
class SeverityShare:
    """One severity in the all-findings tile: a legend entry and, when ``count`` is non-zero, a bar segment.

    ``x`` and ``width`` are percentages of the bar, drawn as SVG attributes (the CSP allows no inline style).
    """

    severity: str
    count: int
    x: float
    width: float
    href: str


@dataclass(frozen=True)
class WorstBar:
    """One row of the worst images panel: a bar as wide as its Critical plus High against the worst image's."""

    ref: str
    short: str
    critical: int
    high: int
    width: float
    href: str


def findings_href(**params: object) -> str:
    return "/findings?" + urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)


def dashboard_href(**params: object) -> str:
    """A link back to the dashboard that keeps the pinned run, if any."""
    query = urlencode({k: v for k, v in params.items() if v is not None})
    return "/?" + query if query else "/"


def _shares(run_id: int, by_severity: dict[str, int]) -> list[SeverityShare]:
    """Critical, High, Medium and Low always, Unknown only when non-zero; each placed after the ones before it."""
    total = sum(by_severity.values())
    shares: list[SeverityShare] = []
    x: float = 0  # an int, so the first segment starts at x="0"
    for sev, count in by_severity.items():
        if sev == "UNKNOWN" and not count:
            continue
        width = round(100 * count / total, 1) if total else 0.0
        shares.append(SeverityShare(sev, count, x, width, findings_href(run_id=run_id, severity=sev)))
        if count:
            x = round(x + width, 1)
    return shares


def _short_ref(ref: str) -> str:
    """``short_image`` of a bare ref: a digest ref keeps its repo and the first 8 hex of the digest."""
    repo, at, digest = ref.partition("@")
    return short_image({"repo": repo if at else "", "tag": None, "digest": digest or None, "image": ref})


def _worst(run_id: int, rows: list[WorstImage]) -> list[WorstBar]:
    """The worst images as bars scaled to the first (worst) one; empty when the run has no Critical or High."""
    if not rows:
        return []
    top = rows[0].critical + rows[0].high
    return [
        WorstBar(
            ref=w.ref,
            short=_short_ref(w.ref),
            critical=w.critical,
            high=w.high,
            width=round(100 * (w.critical + w.high) / top, 1),
            href=findings_href(run_id=run_id, q=w.ref),
        )
        for w in rows
    ]


def _change(current: int, previous: int | None) -> str:
    diff = delta(current, previous)
    if diff is None:
        return "no earlier comparable run"
    if diff == 0:
        return "±0"
    return f"+{diff}" if diff > 0 else f"\N{MINUS SIGN}{-diff}"


def _tiles(run: Run, now: Kpis, before: tuple[Run, Kpis] | None) -> list[Tile]:
    prev_run, prev = before if before else (None, None)
    noisy = bool(run.gaps or run.images_failed or (prev_run and (prev_run.gaps or prev_run.images_failed)))
    specs = [
        ("critical", "Critical findings", now.critical, "", prev and prev.critical, False),
        ("high", "High findings", now.high, "", prev and prev.high, False),
        (
            "images-critical",
            "Images with a Critical",
            now.images_with_critical,
            f"of {now.images - now.images_failed} images scanned",
            prev and prev.images_with_critical,
            False,
        ),
        ("findings", "All findings", now.findings, "", prev and prev.findings, False),
    ]
    if now.images_failed > 0:
        specs.append(("failed", "Images that failed to scan", now.images_failed, "", prev and prev.images_failed, True))
    return [
        Tile(
            key=key,
            label=label,
            value=value,
            suffix=suffix,
            change=_change(value, previous if prev is not None else None),
            change_caution=noisy,
            caution=bool(run.gaps),
            error=error,
        )
        for key, label, value, suffix, previous, error in specs
    ]


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request, run_id: int | None = Query(None, ge=1, le=MAX_ID), by: Literal["fix", "image"] = "fix"
) -> HTMLResponse:
    context = request.app.state.context
    now = request.app.state.clock()
    ctx: dict = {"now": now, "run": None, "pinned": run_id is not None, "caution": CAUTION}
    with open_db(request) as conn:
        if run_id is not None:
            try:
                run = get_run(conn, context, run_id)
            except RunNotShown as exc:
                return render(request, "error.html", {"title": "Run not shown", "message": exc.reason}, 404)
        else:
            run = newest_run(conn, context, cluster_scope=True)
        newest_any = newest_run(conn, context, cluster_scope=False)
        if run is None:
            ctx["narrower_href"] = findings_href(run_id=newest_any.id) if newest_any else None
            return render(request, "dashboard.html", ctx)
        current = kpis(conn, run.id)
        previous = previous_comparable(conn, run)
        before = (previous, kpis(conn, previous.id)) if previous else None
        fixes = fix_by_fix(conn, run.id) if by == "fix" else fix_by_image(conn, run.id)
        failed_rows, failed_total = failed_images(conn, run.id) if current.images_failed else ([], 0)
        auth_refs = auth_failed_refs(conn, run.id) if failed_total else []
        worst = worst_images(conn, run.id)
    ctx.update(run=run, kpis=current, tiles=_tiles(run, current, before))
    hosts = sorted({registry_host(parse_image_id(ref, "")) for ref in auth_refs})
    ctx.update(
        failed=[(r["ref"], r["platform"], r["error_kind"], error_cause(r["error"])) for r in failed_rows],
        failed_total=failed_total,
        login_hints=[login_hint(host) for host in hosts],
    )
    if run_id is None and newest_any is not None and newest_any.id > run.id:
        ctx["newer"] = {
            "scope": describe_scope(newest_any.scope),
            "when": ago(newest_any.finished_at, now) if newest_any.finished_at else "an unknown time ago",
            "href": findings_href(run_id=newest_any.id),
        }
    fix_links = {"severity": ["CRITICAL", "HIGH"]}
    ctx.update(
        by=by,
        fix_rows=fixes.rows,
        fix_total=fixes.total,
        sample_cap=SAMPLE_CAP,
        by_fix_href=dashboard_href(run_id=run_id),
        by_image_href=dashboard_href(run_id=run_id, by="image"),
        all_fix_href=findings_href(run_id=run.id, **fix_links, has_fix="yes"),
        no_fix=fixes.no_fix,
        no_fix_images=fixes.no_fix_images,
        no_fix_href=findings_href(run_id=run.id, **fix_links, has_fix="no"),
        more_href=lambda row: findings_href(run_id=run.id, cve=row.vuln_id, package=row.pkg_name),
    )
    ctx.update(shares=_shares(run.id, current.by_severity), worst=_worst(run.id, worst))
    return render(request, "dashboard.html", ctx)
