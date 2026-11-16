import hashlib
import re
from pathlib import Path

import pytest
from fastapi import Request
from fastapi.responses import PlainTextResponse

import kubedelos.web
import kubedelos.web.app as app_module
from kubedelos.web.jobs import ScanRunner
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


def _versioned(name):
    """The URL a page uses for a static file: its content hash in the query string, so an upgrade is never stale."""
    content = (Path(kubedelos.web.__file__).parent / "static" / name).read_bytes()
    return f"/static/{name}?v={hashlib.sha256(content).hexdigest()[:12]}"


def test_base_page_has_nav_context_and_stylesheet(client):
    html = client.get("/_page").text
    assert f'<link rel="stylesheet" href="{_versioned("app.css")}">' in html
    assert 'href="/"' in html and "Dashboard" in html
    assert 'href="/findings"' in html and "Findings" in html
    assert "my-cluster" in html
    assert '<aside class="sidebar"' in html
    assert f'<link rel="icon" type="image/svg+xml" href="{_versioned("logo.svg")}">' in html
    assert f'<img class="logo" src="{_versioned("logo.svg")}" alt="" width="32" height="32">' in html
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


def test_app_has_an_idle_scan_runner(seed):
    app = app_module.create_app(seed.settings, context="my-cluster", token="t", port=9370)
    assert isinstance(app.state.scans, ScanRunner)
    assert app.state.scans.view() is None
    assert not hasattr(app_module, "atexit")  # the exit hook is server.serve's, once per process


def test_the_400_page_keeps_the_shown_context(client, kube_contexts):
    kube_contexts.append("prod-eu")
    response = client.get("/namespaces", params={"context": "prod-eu", "has": "SEVERE"})
    assert response.status_code == 400 and "invalid parameter: has" in response.text
    assert 'href="/findings?context=prod-eu"' in response.text  # the nav stays on the cluster the page was for
    unknown = client.get("/namespaces", params={"context": "nowhere", "has": "SEVERE"})
    assert unknown.status_code == 400 and 'href="/findings"' in unknown.text  # an unknown one falls back
