import logging
import re

import pytest
from fastapi import Request
from fastapi.responses import PlainTextResponse

from kubedelos.web.pages import render
from kubedelos.web.security import MAX_SESSIONS, Guard

HINT = "Open the URL printed in the terminal where you started kubedelos ui."
CSP = (
    "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self' data:; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
ORIGIN = {"origin": "http://127.0.0.1:9370"}


@pytest.fixture(autouse=True)
def _test_routes(app):
    """Test-only routes: an HTML page and a POST that echoes its body, so the body is shown to reach the endpoint."""

    @app.get("/_page")
    def page(request: Request):
        return render(request, "base.html", {})

    @app.post("/_echo")
    async def echo(request: Request):
        return PlainTextResponse((await request.body()).decode())


def _nonce(response) -> str:
    match = re.search(r"'nonce-([^']+)'", response.headers["content-security-policy"])
    assert match
    return match.group(1)


# Guard


def test_guard_sessions_and_csrf_tokens():
    guard = Guard("tok", 9370)
    assert guard.allowed_hosts == {"127.0.0.1:9370", "localhost:9370", "[::1]:9370"}
    assert not guard.valid_session(None)
    assert not guard.valid_session("nope")
    first, second = guard.new_session(), guard.new_session()
    assert first != second and len(first) >= 43
    assert guard.valid_session(first) and guard.valid_session(second)
    assert guard.csrf_token(first) == guard.csrf_token(first)
    assert guard.csrf_token(first) != guard.csrf_token(second)
    assert re.fullmatch(r"[0-9a-f]{64}", guard.csrf_token(first))
    assert guard.check_csrf(first, guard.csrf_token(first))
    assert not guard.check_csrf(first, guard.csrf_token(second))
    assert not guard.check_csrf(first, None)
    assert not guard.check_csrf(first, "ünïcode")
    # Another process (another startup) has another secret, so its tokens are worthless here.
    assert Guard("tok", 9370).csrf_token(first) != guard.csrf_token(first)


def test_session_set_is_capped_and_drops_the_oldest():
    guard = Guard("tok", 9370)
    sids = [guard.new_session() for _ in range(MAX_SESSIONS + 1)]
    assert not guard.valid_session(sids[0])
    assert guard.valid_session(sids[1]) and guard.valid_session(sids[-1])


# Host


@pytest.mark.parametrize("host", ["127.0.0.1:9370.example.com", "localhost", "127.0.0.1:9371", "evil.example.com", ""])
def test_host_header_rejected(client, host):
    response = client.get("/_page", headers={"host": host})
    assert response.status_code == 400
    assert response.text == "invalid Host header"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("host", ["127.0.0.1:9370", "localhost:9370", "[::1]:9370", "LOCALHOST:9370"])
def test_host_header_accepted(client, host):
    assert client.get("/_page", headers={"host": host}).status_code == 200


def test_host_checked_before_token(anon, token):
    response = anon.get(f"/?token={token}", headers={"host": "evil.example.com"}, follow_redirects=False)
    assert response.status_code == 400
    assert "set-cookie" not in response.headers


# Token and session


def test_no_session_is_403_with_hint(anon):
    response = anon.get("/_page")
    assert response.status_code == 403
    assert HINT in response.text
    assert response.headers["content-type"].startswith("text/html")


def test_unknown_cookie_is_403(anon):
    anon.cookies.set(anon.app.state.guard.cookie_name, "forged")
    assert anon.get("/_page").status_code == 403


@pytest.mark.parametrize("sent", ["wrong", "", "ünïcode"])
def test_wrong_token_is_403(anon, sent):
    response = anon.get("/", params={"token": sent}, follow_redirects=False)
    assert response.status_code == 403
    assert "set-cookie" not in response.headers


def test_token_sets_strict_httponly_cookie_and_redirects_without_token(anon, token):
    response = anon.get(f"/?token={token}", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith(f"{anon.app.state.guard.cookie_name}=")
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie
    assert anon.get("/_page").status_code == 200


def test_token_on_deep_link_keeps_other_params(anon, token):
    response = anon.get(f"/findings?severity=HIGH&token={token}&page=2", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/findings?severity=HIGH&page=2"


def test_token_redirect_never_leaves_the_origin(anon, token):
    """A path like //evil.example.com would make the Location header protocol-relative."""
    for path in ("//evil.example.com", "/\\evil.example.com"):
        response = anon.get(f"http://127.0.0.1:9370{path}?token={token}", follow_redirects=False)
        assert response.status_code == 303
        location = response.headers["location"]
        assert location.startswith("/") and location[1:2] not in ("/", "\\"), location


def test_static_needs_no_session(anon):
    response = anon.get("/static/app.css")
    assert response.status_code == 200
    assert "prefers-color-scheme" in response.text


# Response headers


def test_csp_nonce_differs_per_response(client):
    first, second = client.get("/_page"), client.get("/_page")
    assert first.headers["content-security-policy"] == CSP.format(nonce=_nonce(first))
    assert second.headers["content-security-policy"] == CSP.format(nonce=_nonce(second))
    assert _nonce(first) != _nonce(second)
    assert len(_nonce(first)) >= 22


def test_security_headers_present(client):
    response = client.get("/_page")
    assert response.status_code == 200
    assert "content-security-policy" in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "same-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cache-control"] == "no-store"


def test_security_headers_on_non_html_responses(anon):
    response = anon.get("/static/app.css")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == CSP.format(nonce=_nonce(response))
    assert "no-store" not in response.headers.get("cache-control", "")


# CSRF


def _csrf(client) -> str:
    return client.app.state.guard.csrf_token(client.cookies[client.app.state.guard.cookie_name])


def test_csrf_rejects(client):
    good = _csrf(client)
    assert client.post("/_echo", headers=ORIGIN).status_code == 403
    assert client.post("/_echo", headers={**ORIGIN, "x-csrf-token": "bad"}).status_code == 403
    assert client.post("/_echo", headers={"origin": "http://evil.example.com", "x-csrf-token": good}).status_code == 403
    assert client.post("/_echo", headers={"origin": "null", "x-csrf-token": good}).status_code == 403
    assert client.post("/_echo", headers={"x-csrf-token": good}).status_code == 403  # neither Origin nor Referer
    referer = {"referer": "http://evil.example.com/", "x-csrf-token": good}
    assert client.post("/_echo", headers=referer).status_code == 403
    multipart = client.post("/_echo", headers=ORIGIN, data={"csrf_token": good}, files={"f": ("a.txt", b"x")})
    assert multipart.status_code == 403
    json_body = client.post("/_echo", headers=ORIGIN, json={"csrf_token": good})
    assert json_body.status_code == 403
    # A cross-site <form enctype="text/plain"> can send a body that parses as a form: only urlencoded bodies count.
    plain = client.post(
        "/_echo", headers={**ORIGIN, "content-type": "text/plain"}, content=f"csrf_token={good}".encode()
    )
    assert plain.status_code == 403


def test_csrf_rejects_without_session(anon, client):
    good = _csrf(client)
    assert anon.post("/_echo", headers={**ORIGIN, "x-csrf-token": good}).status_code == 403


def test_csrf_accepts(client):
    good = _csrf(client)
    header = client.post("/_echo", headers={**ORIGIN, "x-csrf-token": good})
    assert header.status_code == 200
    form = client.post("/_echo", headers=ORIGIN, data={"csrf_token": good, "name": "x"})
    assert form.status_code == 200
    assert form.text == f"csrf_token={good}&name=x"  # the endpoint still receives the body the middleware read
    referer = client.post("/_echo", headers={"referer": "http://127.0.0.1:9370/findings", "x-csrf-token": good})
    assert referer.status_code == 200


def test_csrf_garbled_form_is_403(client):
    headers = {**ORIGIN, "content-type": "application/x-www-form-urlencoded"}
    assert client.post("/_echo", headers=headers, content=b"\xff\xfe").status_code == 403


# Access log


def test_access_log_has_no_query_string(anon, token, caplog):
    caplog.set_level(logging.INFO, logger="kubedelos.web")
    anon.get(f"/?token={token}", follow_redirects=False)
    anon.get("/nowhere?q=x")
    messages = [record.getMessage() for record in caplog.records if record.name == "kubedelos.web"]
    assert messages == ["GET / 303", "GET /nowhere 404"]
    for record in caplog.records:
        assert token not in record.getMessage()
        assert "q=x" not in record.getMessage()


def test_access_log_path_cannot_forge_lines(anon, caplog):
    caplog.set_level(logging.INFO, logger="kubedelos.web")
    anon.get("/a%0Afake%20line")
    assert [r.getMessage() for r in caplog.records if r.name == "kubedelos.web"] == ["GET /a%0Afake%20line 403"]


def test_two_instances_on_different_ports_keep_both_sessions(seed, token):
    from fastapi.testclient import TestClient

    from kubedelos.web.app import create_app

    apps = [
        create_app(seed.settings, context="my-cluster", token=token, port=p, clock=seed.clock) for p in (9370, 9371)
    ]
    with (
        TestClient(apps[0], base_url="http://127.0.0.1:9370") as one,
        TestClient(apps[1], base_url="http://127.0.0.1:9371") as two,
    ):
        assert one.get(f"/?token={token}", follow_redirects=False).status_code == 303
        assert two.get(f"/?token={token}", follow_redirects=False).status_code == 303
        # A browser holds both cookies and sends both to either port.
        both = {**one.cookies, **two.cookies}
        for client in (one, two):
            client.cookies.clear()
            for name, value in both.items():
                client.cookies.set(name, value)
            assert client.get("/").status_code == 200


def test_signed_out_page_does_not_show_the_context(anon):
    response = anon.get("/_page")
    assert response.status_code == 403
    assert "my-cluster" not in response.text
