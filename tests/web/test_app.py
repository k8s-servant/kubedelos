import re

import pytest
from fastapi import Request
from fastapi.responses import PlainTextResponse

from kubedelos.web.pages import render


@pytest.fixture(autouse=True)
def _test_routes(app):
    @app.get("/_page")
    def page(request: Request):
        return render(request, "base.html", {})

    @app.get("/_int")
    def integer(request: Request, n: int):
        return PlainTextResponse(str(n))

    @app.get("/_csrf")
    def csrf(request: Request):
        # Rendered from the app's environment, to show the csrf_token global and the escaping.
        template = app.state.templates.env.from_string("{{ csrf_token(request) }} {{ '<b>' }}")
        return PlainTextResponse(template.render(request=request))


def test_app_state(app, seed):
    assert app.state.settings is seed.settings
    assert app.state.context == "my-cluster"
    assert app.state.clock is seed.clock


def test_docs_routes_disabled(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_base_page_has_nav_context_and_stylesheet(client):
    html = client.get("/_page").text
    assert '<link rel="stylesheet" href="/static/app.css">' in html
    assert 'href="/"' in html and "Dashboard" in html
    assert 'href="/findings"' in html and "Findings" in html
    assert "my-cluster" in html
    assert '<aside class="sidebar"' in html
    assert '<link rel="icon" type="image/svg+xml" href="/static/logo.svg">' in html
    assert '<img class="logo" src="/static/logo.svg" alt="" width="24" height="24">' in html
    assert "site-header" not in html
    assert "<script" not in html and "<style" not in html and "style=" not in html
    assert not re.search(r"\son[a-z]+\s*=", html)  # no event-handler attributes such as onclick=


def test_logo_is_served_without_a_session(anon):
    response = anon.get("/static/logo.svg")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert "<script" not in response.text


def test_csrf_token_global(client):
    body = client.get("/_csrf").text
    expected = client.app.state.guard.csrf_token(client.cookies[client.app.state.guard.cookie_name])
    assert body == f"{expected} &lt;b&gt;"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://example.com/CVE-1", "http://example.com/CVE-1"),
        ("https://example.com/a?b=c", "https://example.com/a?b=c"),
        ("HTTPS://example.com/", "HTTPS://example.com/"),
        ("javascript:alert(1)", None),
        (" javascript:alert(1)", None),
        ("java\tscript:alert(1)", None),
        ("data:x", None),
        ("//example.com", None),
        ("/relative", None),
        ("https://", None),
        ("", None),
        (None, None),
        (42, None),
    ],
)
def test_safe_url_filter(app, url, expected):
    assert app.state.templates.env.filters["safe_url"](url) == expected


def test_validation_error_renders_400_page(client):
    response = client.get("/_int?n=abc")
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("text/html")
    assert "invalid parameter: n" in response.text
    assert response.headers["cache-control"] == "no-store"
