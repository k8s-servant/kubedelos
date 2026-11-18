import json
import re
import types
from html import unescape

import pytest

from kubedelos.config import Settings
from kubedelos.models import ImageRef, ImageResult
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.web.routes import settings as settings_routes
from tests.web.conftest import TOKEN, serve_cookie, serve_headers, signed_post


def _rows(html):
    body = html.split('<table class="settings">', 1)[1].split("</table>", 1)[0]
    return {
        name: (unescape(value).strip(), source)
        for name, value, source in re.findall(
            r'<tr data-setting="(\w+)">.*?<td class="value">(.*?)</td>\s*<td class="source">(\w+)</td>', body, re.S
        )
    }


def test_lists_every_setting_with_its_value_and_source(client, app, monkeypatch):
    monkeypatch.setenv("KUBEDELOS_PARALLELISM", "4")
    app.state.flags = frozenset({"context"})
    html = client.get("/settings").text
    rows = _rows(html)
    assert set(rows) == set(Settings.model_fields)
    assert rows["parallelism"] == ("4", "environment")
    assert rows["context"][1] == "flag"
    assert rows["scan_timeout_s"] == ("600", "default")
    assert rows["layer_cache"] == ("true", "default")
    assert rows["namespaces"] == ("none (every namespace)", "default")
    assert rows["pkg_types"] == ("library, os", "default")
    assert rows["selector"] == ("not set", "default")
    assert "<code>KUBEDELOS_SCAN_TIMEOUT_S</code>" in html and "<code>--context</code>" in html


def test_shows_the_files_trivy_and_log_level(client, app, monkeypatch):
    monkeypatch.setenv("KUBEDELOS_LOG_LEVEL", "info")
    settings = app.state.settings
    html = unescape(client.get("/settings").text)
    assert str(settings.db_path) in html and str(settings.data_dir) in html and str(settings.cache_dir) in html
    assert f"v{TRIVY_VERSION} (pinned)" in html
    assert "info (an access line per request)" in html.split("Log level", 1)[1].split("</tr>", 1)[0]


def test_log_level_says_what_the_ui_does_with_it(client, monkeypatch):
    def level():
        return unescape(client.get("/settings").text).split("Log level", 1)[1].split("</tr>", 1)[0]

    monkeypatch.delenv("KUBEDELOS_LOG_LEVEL", raising=False)
    assert "default (no access log)" in level()
    monkeypatch.setenv("KUBEDELOS_LOG_LEVEL", "debug")
    assert "debug (no effect: only info is used)" in level()


def test_names_a_custom_trivy(client, app):
    app.state.settings = app.state.settings.model_copy(update={"trivy_path": "/opt/trivy"})
    html = client.get("/settings").text
    assert "custom: /opt/trivy" in html and "(pinned)" not in html


def test_values_are_escaped_and_no_secret_is_shown(client, app):
    app.state.settings = app.state.settings.model_copy(update={"exclude_images": ["<b>x</b>"]})
    html = client.get("/settings").text
    assert "<b>x</b>" not in html and "&lt;b&gt;x&lt;/b&gt;" in html
    assert TOKEN not in html


def test_nav_has_settings_before_about(client):
    nav = client.get("/settings").text.split('<nav aria-label="Main">', 1)[1].split("</nav>", 1)[0]
    labels = re.findall(r">([A-Z][a-z]+)</a>", nav)
    assert labels[-2:] == ["Settings", "About"]
    assert '<a href="/settings" aria-current="page">Settings</a>' in nav


def test_an_unset_setting_names_what_is_used_instead(client):
    rows = _rows(client.get("/settings").text)
    assert rows["kubeconfig"][0] == "not set: $KUBECONFIG or ~/.kube/config"
    assert rows["trivy_path"][0] == "not set: the pinned Trivy"


# The Registries card and "Test an image".

HOST = "registry.example.com"
SECRET = "regcred-sentinel"


class FakeCache:
    dir = "cache"

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def scanned(monkeypatch):
    """Stub out Trivy: the calls ``scan_image`` got, and the result it answers with (``scanned.result``)."""
    calls = []
    box = types.SimpleNamespace(calls=calls, result=None, seen_config=None, timeout=None)

    def fake_scan(trivy, ref, platform, timeout_s, docker_config=None, **kwargs):
        calls.append(ref.ref)
        box.timeout = timeout_s
        if docker_config is not None:
            box.seen_config = json.loads((docker_config / "config.json").read_text())
        return box.result or ImageResult(image=ref, platform=platform, status="ok")

    monkeypatch.setattr(settings_routes, "ensure_trivy", lambda settings: "trivy")
    monkeypatch.setattr(settings_routes, "TrivyCache", FakeCache)
    monkeypatch.setattr(settings_routes, "scan_image", fake_scan)
    return box


def _card(client):
    html = unescape(client.get("/settings").text)
    return html.split('id="registries-title"', 1)[1].split("</section>", 1)[0]


def test_registries_card_shows_identity_not_tokens(make_serve_client, tmp_path, monkeypatch):
    token_file = tmp_path / "azure-token"
    token_file.write_text("tok3n")
    monkeypatch.setenv("AZURE_FEDERATED_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("AZURE_CLIENT_ID", "env-client-id")
    client = make_serve_client(cloud_provider="azure", cloud_identity="client-id-123")
    html = client.get("/settings").text
    card = _card(client)
    assert "client-id-123" in card and "azure" in card
    assert "*.azurecr.io" in card and "*.azurecr.cn" in card
    assert "tok3n" not in html and "env-client-id" not in html


@pytest.mark.parametrize(
    ("provider", "hosts"),
    [
        ("gcp", ["gcr.io", "*.gcr.io", "*-docker.pkg.dev"]),
        ("aws", ["<account>.dkr.ecr.<region>.amazonaws.com", ".amazonaws.com.cn"]),
    ],
)
def test_registries_card_names_the_hosts_per_provider(make_serve_client, provider, hosts):
    card = _card(make_serve_client(cloud_provider=provider, cloud_identity="id-1"))
    assert all(host in card for host in hosts)


def test_registries_card_without_a_cloud_identity(client, make_serve_client):
    assert "none: your own cloud logins apply" in _card(client)
    assert "not configured" in _card(make_serve_client())


def test_registries_card_lists_config_secret_names_and_namespaces(make_serve_client, tmp_path):
    path = tmp_path / "dc" / "my-regcred" / ".dockerconfigjson"
    client = make_serve_client(
        secrets_dir=tmp_path / "secrets", docker_configs=[path], pod_pull_secret_namespaces=["web", "api"]
    )
    card = _card(client)
    assert "my-regcred" in card and str(tmp_path) not in card
    assert "web, api" in card
    assert "off" in _card(make_serve_client())


def test_registry_test_form_is_served_only(client, make_serve_client):
    assert 'action="/settings/registry-test"' in make_serve_client().get("/settings").text
    assert "registry-test" not in client.get("/settings").text
    assert "registry-test" not in make_serve_client(read_only=True).get("/settings").text


def test_registry_test_absent_in_ui_mode(client, scanned):
    guard = client.app.state.guard
    token = guard.csrf_token(client.cookies[guard.cookie_name])
    response = client.post(
        "/settings/registry-test",
        data={"image": f"{HOST}/a:1", "csrf_token": token},
        headers={"origin": "http://127.0.0.1:9370"},
    )
    assert response.status_code == 404 and scanned.calls == []


def test_registry_test_refused_in_read_only(make_serve_client, scanned):
    response = signed_post(make_serve_client(read_only=True), "/settings/registry-test", {"image": f"{HOST}/a:1"})
    assert response.status_code == 403 and scanned.calls == []


def test_registry_test_needs_csrf(serve_client, scanned):
    serve_cookie(serve_client)
    response = serve_client.post(
        "/settings/registry-test", data={"image": f"{HOST}/a:1"}, headers=serve_headers(), follow_redirects=False
    )
    assert response.status_code == 403 and scanned.calls == []


@pytest.mark.parametrize("image", ["", "-x", "a b", f"{HOST}/a@sha256:nope"])
def test_registry_test_rejects_bad_ref(serve_client, scanned, image):
    response = signed_post(serve_client, "/settings/registry-test", {"image": image})
    assert response.status_code == 400 and "invalid image reference" in response.text and scanned.calls == []


def test_registry_test_reports_a_readable_image(serve_client, scanned):
    response = signed_post(serve_client, "/settings/registry-test", {"image": f"{HOST}/team/app:1"})
    assert response.status_code == 200
    assert f"ok: {HOST}/team/app:1 is readable" in response.text
    assert scanned.timeout == 120  # min(scan_timeout_s, 120)


def test_registry_test_busy(serve_client, scanned):
    assert settings_routes._LOCK.acquire(blocking=False)
    try:
        response = signed_post(serve_client, "/settings/registry-test", {"image": f"{HOST}/a:1"})
    finally:
        settings_routes._LOCK.release()
    assert "A test is already running" in response.text and scanned.calls == []


def test_registry_test_uses_mounted_configs(make_serve_client, scanned, tmp_path):
    path = tmp_path / "dc" / "regcred" / ".dockerconfigjson"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"auths": {HOST: {"username": "u", "password": SECRET}}}))
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    client = make_serve_client(secrets_dir=secrets, docker_configs=[path])
    response = signed_post(client, "/settings/registry-test", {"image": f"{HOST}/team/app:1"})
    assert "is readable" in response.text and SECRET not in response.text
    assert scanned.seen_config is not None and HOST in scanned.seen_config["auths"]
    assert list(secrets.iterdir()) == []  # the temporary config is gone


@pytest.mark.parametrize(
    ("host", "page"),
    [
        ("myacr.azurecr.io", "acr"),
        ("gcr.io", "gar"),
        ("eu-docker.pkg.dev", "gar"),
        ("1.dkr.ecr.eu-west-1.amazonaws.com", "ecr"),
    ],
)
def test_registry_test_auth_failure_points_at_the_docs(serve_client, scanned, host, page):
    ref = ImageRef(ref=f"{host}/a:1", repo=f"{host}/a")
    scanned.result = ImageResult(image=ref, platform="linux/amd64", status="error", error_kind="auth", error="denied")
    text = signed_post(serve_client, "/settings/registry-test", {"image": f"{host}/a:1"}).text
    assert "auth" in text and "denied" in text and f"docs/registries/{page}.md" in text and "log in to" in text


def test_registry_test_auth_failure_on_another_host_points_at_pull_secrets(serve_client, scanned):
    ref = ImageRef(ref=f"{HOST}/a:1", repo=f"{HOST}/a")
    scanned.result = ImageResult(image=ref, platform="linux/amd64", status="error", error_kind="auth", error="denied")
    text = signed_post(serve_client, "/settings/registry-test", {"image": f"{HOST}/a:1"}).text
    assert "docs/registries/pull-secrets.md" in text


def test_registry_test_other_errors_show_kind_and_cause(serve_client, scanned):
    ref = ImageRef(ref=f"{HOST}/a:1", repo=f"{HOST}/a")
    scanned.result = ImageResult(
        image=ref, platform="linux/amd64", status="error", error_kind="not_found", error="nope"
    )
    text = signed_post(serve_client, "/settings/registry-test", {"image": f"{HOST}/a:1"}).text
    assert "not_found" in text and "nope" in text and "docs/registries" not in text
