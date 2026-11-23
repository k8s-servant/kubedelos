import hashlib
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Request
from fastapi.responses import PlainTextResponse

import kubedelos.web
import kubedelos.web.app as app_module
from kubedelos.web.jobs import ScanRunner
from kubedelos.web.pages import render
from kubedelos.web.security import READ_ONLY_NOTICE, ServeGuard


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
    assert app.state.serve is False


def test_serve_app_state(serve_app, worker, sweeper):
    assert serve_app.state.serve is True
    assert serve_app.state.context == "my-cluster"
    assert serve_app.state.list_contexts() == ["my-cluster"]
    assert serve_app.state.worker is worker and serve_app.state.sweeper is sweeper
    assert isinstance(serve_app.state.scans, ScanRunner)
    assert not hasattr(serve_app.state, "guard")
    assert isinstance(serve_app.state.serve_guard, ServeGuard)
    assert serve_app.state.serve_guard.read_only is False


def test_serve_app_has_the_same_pages(app, serve_app):
    paths = {getattr(route, "path", None) for route in app.routes} - {"/_page", "/_int", "/_csrf"}
    assert paths <= {getattr(route, "path", None) for route in serve_app.routes}


def test_serve_app_renders_every_page(serve_client):
    for path in ("/", "/findings", "/namespaces", "/diff", "/reports", "/accepted", "/scans", "/settings", "/about"):
        assert serve_client.get(path).status_code == 200, path


def test_serve_forms_carry_the_token(serve_client, serve_app):
    html = serve_client.get("/scans").text
    cookie = serve_client.cookies.get(ServeGuard.CSRF_COOKIE)
    token = serve_app.state.serve_guard.csrf_token(cookie, None)
    assert 'action="/scans"' in html
    assert f'name="csrf_token" value="{token}"' in html


class _RunningScan:
    """A runner whose scan is running, so the progress readout would offer Cancel."""

    def view(self):
        fields = ("progress", "retry_of", "eta", "status", "run_id", "error")
        return SimpleNamespace(state="running", context="my-cluster", **dict.fromkeys(fields))


@pytest.mark.parametrize(("read_only", "shown"), [(True, False), (False, True)])
def test_read_only_hides_the_scan_form_and_cancel(make_serve_client, read_only, shown):
    client = make_serve_client(read_only=read_only)
    client.app.state.scans = _RunningScan()
    html = client.get("/scans").text
    assert "Scanning my-cluster" in html
    assert ('action="/scans"' in html) is shown
    assert ('action="/scans/cancel"' in html) is shown
    assert ('name="csrf_token"' in html) is shown


def test_laptop_can_always_write(app, client):
    @app.get("/_can_write")
    def can_write(request: Request):
        return PlainTextResponse(
            app.state.templates.env.from_string("{{ can_write(request) }}").render(request=request)
        )

    assert client.get("/_can_write").text == "True"


def test_serve_app_handles_bad_parameters(serve_client):
    assert serve_client.get("/scans?page=x").status_code == 400
    assert serve_client.get("/?context=nope").status_code == 404


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


@pytest.mark.parametrize("path", ["/", "/findings", "/scans", "/accepted"])
def test_read_only_pages_show_the_notice(make_serve_client, path):
    html = make_serve_client(read_only=True).get(path).text
    assert '<p class="notice">View-only: this kubedelos is read-only.</p>' in html


def test_writable_serve_and_laptop_never_show_the_notice(serve_client, client):
    assert READ_ONLY_NOTICE not in serve_client.get("/").text
    assert READ_ONLY_NOTICE not in client.get("/").text


def test_laptop_scans_store_the_run_under_the_contexts_cluster_as_the_kubeconfig_has_it(seed, monkeypatch):
    built = {}

    class Runner:
        def __init__(self, settings, context, **kwargs):
            built.update(kwargs)

    keys = {"prod": "https://prod.example.com:6443"}
    monkeypatch.setattr(app_module, "ScanRunner", Runner)
    app_module.create_app(seed.settings, context="prod", token="t", port=9370, cluster_keys=lambda: dict(keys))
    cluster_of = built["cluster_of"]
    assert cluster_of("prod") == "https://prod.example.com:6443"
    assert cluster_of("dev") == "dev"  # not in the kubeconfig: its own name
    keys["dev"] = "https://dev.example.com"  # added while the UI runs
    assert cluster_of("dev") == "https://dev.example.com"


def test_the_serve_app_keys_its_cluster_by_its_name(serve_client):
    app = serve_client.app
    assert app.state.cluster_keys() == {app.state.context: app.state.context}
