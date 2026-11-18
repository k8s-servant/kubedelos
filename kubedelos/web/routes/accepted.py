"""Accepted risk in the UI: the register (``GET /accepted``), the Accept… form, create and revoke.

The register lists the shown context's entries and the all-cluster ones, with each entry's state, days left and how
many findings it covers in the dashboard's run (the newest whole-cluster run). The form is prefilled from the findings
row that links to it; the owner defaults to the signed-in name in serve (an empty posted owner becomes it) and to the
OS user otherwise, and the expiry to 90 days ahead, at most 365. An entry belongs to the posted context, or to all
clusters. In read-only serve the form and the revoke buttons are not offered.

``POST /accepted`` and ``POST /accepted/{id}/revoke`` read the urlencoded body themselves, as ``POST /scans`` does (the
CSRF guard has checked it), and write through ``open_db_rw``. A context in a form must be one the UI knows; revoke only
touches an entry that applies to the posted context. Matching happens on read (``kubedelos.store.accepted``), so both
take effect on the next page.
"""

import getpass
from datetime import date, timedelta
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Path, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from kubedelos.store import accepted
from kubedelos.store.queries import newest_run
from kubedelos.web.identity import identity
from kubedelos.web.pages import MAX_ID, open_db, open_db_rw, render, shown_context

router = APIRouter()

DEFAULT_DAYS = 90
MAX_DAYS = 365
MAX_REASON = 500
NARROWING = ("namespace", "image", "package")
_MAX_FORM_FIELDS = 50
_MAX_BODY = 16 * 1024


def _os_user() -> str:
    try:
        return getpass.getuser()
    except (OSError, KeyError):  # no login name and no passwd entry, as in some containers
        return ""


def days_text(days: int) -> str:
    if days > 1:
        return f"{days} days left"
    if days == 1:
        return "1 day left"
    if days == 0:
        return "last day"
    return "expired yesterday" if days == -1 else f"expired {-days} days ago"


def register_href(context: str, default: str) -> str:
    return "/accepted" + ("?" + urlencode({"context": context}) if context != default else "")


@router.get("/accepted", response_class=HTMLResponse)
def register(request: Request, cve: str | None = None) -> HTMLResponse:
    now = request.app.state.clock()
    today = now.date()
    with open_db(request) as conn:
        context = shown_context(request, conn)
        run = newest_run(conn, context, cluster_scope=True)
        entries = accepted.register(conn, context, run.id if run else None, today, vuln_id=(cve or "").strip() or None)
    rows = [{"entry": e, "days": days_text(e.days_left)} for e in entries]
    return render(request, "accepted.html", {"now": now, "run": run, "rows": rows, "cve": cve or ""})


def _form(request: Request, values: dict[str, str], error: str | None = None, status: int = 200) -> HTMLResponse:
    now = request.app.state.clock()
    today = now.date()
    ctx = {
        "now": now,
        "values": values,
        "error": error,
        "min": today.isoformat(),
        "max": (today + timedelta(days=MAX_DAYS)).isoformat(),
        "max_reason": MAX_REASON,
        "back": register_href(request.state.context, request.app.state.context),
    }
    return render(request, "accept_form.html", ctx, status)


@router.get("/accepted/new", response_class=HTMLResponse)
def new(
    request: Request,
    cve: str = "",
    package: str = "",
    image: str = "",
    namespace: str = "",
) -> HTMLResponse:
    with open_db(request) as conn:
        shown_context(request, conn)
    today = request.app.state.clock().date()
    values = {
        "cve": cve,
        "package": package,
        "image": image,
        "namespace": namespace,
        "reason": "",
        "owner": identity(request) or ("" if request.app.state.serve else _os_user()),
        "expires": (today + timedelta(days=DEFAULT_DAYS)).isoformat(),
        "scope": "context",
    }
    return _form(request, values)


def _fields(body: bytes) -> dict[str, str] | None:
    """The form's fields, the first value of each, or None when the body can't be read."""
    if len(body) > _MAX_BODY:
        return None
    try:
        parsed = parse_qs(body.decode(), keep_blank_values=True, max_num_fields=_MAX_FORM_FIELDS, errors="strict")
    except ValueError:
        return None
    return {name: values[0] for name, values in parsed.items()}


def _target(request: Request, conn, fields: dict[str, str]) -> str:
    """The posted context, or the startup one; raises UnknownContext (a 404 page) for a context the UI doesn't know."""
    return shown_context(request, conn, wanted=fields.get("context") or request.app.state.context)


def _expiry(text: str, today: date) -> date:
    try:
        expires = date.fromisoformat(text.strip())
    except ValueError:
        raise ValueError("the expiry is not a date (YYYY-MM-DD)") from None
    if expires < today:
        raise ValueError("the expiry date is in the past")
    if expires > today + timedelta(days=MAX_DAYS):
        raise ValueError(f"the expiry can be at most {MAX_DAYS} days ahead")
    return expires


@router.post("/accepted")
async def create(request: Request) -> Response:
    body = await request.body()
    return await run_in_threadpool(_create, request, body)


def _create(request: Request, body: bytes) -> Response:
    fields = _fields(body)
    with open_db(request) as conn:
        context = _target(request, conn, fields or {})
    if fields is None:
        return _form(request, {}, "the form could not be read", 400)
    names = ("cve", "reason", "owner", "expires", "scope", *NARROWING)
    values = {name: fields.get(name, "") for name in names}
    if not values["owner"].strip():  # in serve with a trusted identity the signed-in user owns what they leave unnamed
        values["owner"] = identity(request) or ""
    now = request.app.state.clock()
    try:
        if len(values["reason"].strip()) > MAX_REASON:
            raise ValueError(f"the reason can be at most {MAX_REASON} characters")
        if values["scope"] not in ("context", "all"):
            raise ValueError("pick this cluster or all clusters")
        expires = _expiry(values["expires"], now.date())
        with open_db_rw(request) as conn:
            accepted.add(
                conn,
                vuln_id=values["cve"],
                reason=values["reason"],
                owner=values["owner"],
                expires=expires,
                context=context if values["scope"] == "context" else None,
                namespace=values["namespace"],
                repo=values["image"],
                pkg_name=values["package"],
                now=now,
            )
    except ValueError as exc:
        return _form(request, values, str(exc), 400)
    return RedirectResponse(register_href(context, request.app.state.context), status_code=303)


@router.post("/accepted/{entry_id}/revoke")
async def revoke(request: Request, entry_id: int = Path(ge=1, le=MAX_ID)) -> Response:
    body = await request.body()
    return await run_in_threadpool(_revoke, request, entry_id, body)


def _revoke(request: Request, entry_id: int, body: bytes) -> Response:
    fields = _fields(body)
    if fields is None:  # never fall back to the startup context: the entry would be judged against the wrong cluster
        return render(request, "error.html", {"title": "Bad request", "message": "the form could not be read"}, 400)
    with open_db(request) as conn:
        context = _target(request, conn, fields)
    with open_db_rw(request) as conn:
        entry = accepted.get(conn, entry_id)
        applies = entry is not None and entry["context"] in (None, context)
        if not applies or not accepted.revoke(conn, entry_id, request.app.state.clock()):
            message = "There is no such acceptance for this cluster, or it was revoked already."
            return render(request, "error.html", {"title": "Not found", "message": message}, 404)
    return RedirectResponse(register_href(context, request.app.state.context), status_code=303)
