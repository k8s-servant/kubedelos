"""Security controls for the local UI, applied to every request by one HTTP middleware.

The UI listens on loopback only, but any web page the user visits can still send requests to it. These controls stop
that: a Host check (DNS rebinding), a startup token exchanged for a session cookie, an Origin check plus an HMAC token on every non-GET (CSRF), and a
strict CSP with a per-response nonce. Cookies are not scoped to a port, so any server on another loopback port receives
this cookie; its name carries the port so two instances do not clash. HttpOnly, the Host check and the Origin and CSRF
checks still guard the routes. The access log never records query strings, because the startup token travels in one.
"""

import hashlib
import hmac
import logging
import secrets
from collections.abc import Awaitable, Callable
from urllib.parse import parse_qs, parse_qsl, quote, urlencode, urlsplit

from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse, RedirectResponse

CSRF_HEADER = "x-csrf-token"
CSRF_FIELD = "csrf_token"
SESSION_HINT = "Open the URL printed in the terminal where you started kubedelos ui."
CSP = (
    "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self' data:; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
_SAFE_METHODS = frozenset({"GET", "HEAD"})
_FORM_TYPE = "application/x-www-form-urlencoded"
_MAX_FORM_FIELDS = 100

logger = logging.getLogger("kubedelos.web")


def _same(expected: str, sent: str | None) -> bool:
    """Constant-time string comparison that is False, rather than an error, for a missing or non-ASCII value."""
    return sent is not None and hmac.compare_digest(expected.encode(), sent.encode())


class Guard:
    """The secrets of one UI process: the startup token, the live sessions and the key the CSRF tokens derive from."""

    def __init__(self, token: str, port: int) -> None:
        self._token = token
        self._sessions: set[str] = set()
        self.csrf_secret = secrets.token_bytes(32)
        self.cookie_name = f"kubedelos_session_{port}"
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    def valid_token(self, sent: str | None) -> bool:
        return _same(self._token, sent)

    def new_session(self) -> str:
        sid = secrets.token_urlsafe(32)
        self._sessions.add(sid)
        return sid

    def valid_session(self, sid: str | None) -> bool:
        return sid is not None and sid in self._sessions

    def csrf_token(self, sid: str) -> str:
        return hmac.new(self.csrf_secret, sid.encode(), hashlib.sha256).hexdigest()

    def check_csrf(self, sid: str, sent: str | None) -> bool:
        return _same(self.csrf_token(sid), sent)


def _raw_path(request: Request) -> str:
    """The path as the client sent it, still percent-encoded, so a decoded CR, LF or ``?`` cannot appear in it."""
    raw = request.scope.get("raw_path")
    if raw is None:
        return quote(request.url.path)
    return raw.decode("latin-1").split("?", 1)[0]


def _without_token(request: Request) -> str:
    """The request's path and query, minus the ``token`` parameter, as a same-origin redirect target."""
    # Collapse leading slashes and backslashes, which a browser reads as a protocol-relative URL to another host.
    path = "/" + _raw_path(request).lstrip("/\\")
    query = urlencode([(k, v) for k, v in parse_qsl(request.url.query, keep_blank_values=True) if k != "token"])
    return f"{path}?{query}" if query else path


def _origin_ok(request: Request, guard: Guard) -> bool:
    """Whether the ``Origin`` header, or failing that the ``Referer``, names this server."""
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return False
    parts = urlsplit(source)
    return parts.scheme == "http" and parts.netloc.lower() in guard.allowed_hosts


async def _sent_csrf(request: Request) -> str | None:
    """The CSRF token from the header, or from an urlencoded form body. Any other body carries none."""
    if (header := request.headers.get(CSRF_HEADER)) is not None:
        return header
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != _FORM_TYPE:
        return None
    try:
        fields = parse_qs((await request.body()).decode(), max_num_fields=_MAX_FORM_FIELDS, errors="strict")
    except ValueError:  # UnicodeDecodeError is a ValueError, as is a body with too many fields
        return None
    values = fields.get(CSRF_FIELD)
    return values[0] if values and len(values) == 1 else None


def _forbidden(request: Request) -> Response:
    from kubedelos.web.app import render  # app imports this module; render is only needed once a request arrives

    return render(
        request,
        "error.html",
        {"title": "Not signed in", "message": SESSION_HINT, "context": None, "nav": []},
        status=403,
    )


def _set_headers(response: Response, nonce: str) -> None:
    response.headers["Content-Security-Policy"] = CSP.format(nonce=nonce)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers["Cache-Control"] = "no-store"


async def _check(request: Request, guard: Guard, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    """Steps 3 to 5: the token exchange, the session and CSRF. Returns the response to send."""
    if "token" in request.query_params:
        if not guard.valid_token(request.query_params["token"]):
            return _forbidden(request)
        response = RedirectResponse(_without_token(request), status_code=303)
        response.set_cookie(guard.cookie_name, guard.new_session(), httponly=True, samesite="strict", path="/")
        return response

    sid = request.cookies.get(guard.cookie_name)
    if not request.url.path.startswith("/static/") and not guard.valid_session(sid):
        return _forbidden(request)

    if request.method not in _SAFE_METHODS:
        csrf_ok = (
            guard.valid_session(sid) and _origin_ok(request, guard) and guard.check_csrf(sid, await _sent_csrf(request))
        )
        if not csrf_ok:
            return PlainTextResponse("CSRF check failed", status_code=403)

    return await call_next(request)


def install(app: FastAPI, guard: Guard) -> None:
    """Add the security middleware to ``app``. Every response, including the error ones, gets the security headers."""

    @app.middleware("http")
    async def security(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        nonce = secrets.token_urlsafe(16)
        if request.headers.get("host", "").lower() not in guard.allowed_hosts:
            response: Response = PlainTextResponse("invalid Host header", status_code=400)
        else:
            request.state.csp_nonce = nonce
            response = await _check(request, guard, call_next)
        _set_headers(response, nonce)
        # The path only: the query may hold the startup token. Percent-encoded, so it cannot forge log lines.
        logger.info("%s %s %d", request.method, _raw_path(request), response.status_code)
        return response
