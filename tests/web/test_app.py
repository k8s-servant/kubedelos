import re
import sqlite3

import pytest
from fastapi import Request
from fastapi.responses import PlainTextResponse

from kubedelos.web.app import open_db, render
from kubedelos.web.security import SESSION_COOKIE


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

    @app.get("/_db")
    def db(request: Request):
        with open_db(request) as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            try:
                conn.execute("CREATE TABLE t (x)")
            except sqlite3.OperationalError as exc:
                return PlainTextResponse(f"{version} {exc}")
        return PlainTextResponse("writable")


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
    assert "<script" not in html and "<style" not in html and "style=" not in html
    assert not re.search(r"\son[a-z]+\s*=", html)  # no event-handler attributes such as onclick=


def test_render_escapes_context(app, client):
    app.state.context = "<script>alert(1)</script>"
    html = client.get("/_page").text
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_csrf_token_global(client):
    body = client.get("/_csrf").text
    expected = client.app.state.guard.csrf_token(client.cookies[SESSION_COOKIE])
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


def test_open_db_is_read_only(client):
    response = client.get("/_db")
    assert response.status_code == 200
    version, _, error = response.text.partition(" ")
    assert int(version) > 0
    assert "readonly" in error
