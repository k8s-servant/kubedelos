import json
import re
import types
from html import unescape

import pytest

from kubedelos.config import Settings
from kubedelos.models import ImageRef, ImageResult, InventoryItem
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
def strict_hosts():
    """Marks a test that runs with the real host check."""


@pytest.fixture
def scanned(monkeypatch, request):
    """Stub out Trivy: the calls ``scan_image`` got, and the result it answers with (``scanned.result``). Any host
    may be tested, unless the test asks for ``strict_hosts``."""
    calls = []
    box = types.SimpleNamespace(calls=calls, result=None, seen_config=None, timeout=None)

    def fake_scan(trivy, ref, platform, timeout_s, docker_config=None, **kwargs):
        calls.append(ref.ref)
        box.timeout = timeout_s
        if docker_config is not None:
            box.seen_config = json.loads((docker_config / "config.json").read_text())
        return box.result or ImageResult(image=ref, platform=platform, status="ok")

    if "strict_hosts" not in request.fixturenames:
        monkeypatch.setattr(settings_routes, "_host_source", lambda *args: "mounted")
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
    assert response.status_code == 200 and "invalid image reference" in response.text and scanned.calls == []


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
    assert response.status_code == 200  # htmx swaps only 2xx
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
        ("1.dkr.ecr-fips.us-east-1.amazonaws.com", "ecr"),
        ("1.dkr-ecr.eu-west-1.on.aws", "ecr"),
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


def test_registry_test_shows_a_trivy_failure_cause_and_logs_it(serve_client, scanned, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise RuntimeError("download of the Trivy DB failed")

    monkeypatch.setattr(settings_routes, "scan_image", fail)
    with caplog.at_level("WARNING"):
        response = signed_post(serve_client, "/settings/registry-test", {"image": f"{HOST}/a:1"})
    assert response.status_code == 200 and "download of the Trivy DB failed" in response.text
    assert "download of the Trivy DB failed" in caplog.text


def test_registry_test_hides_an_unexpected_error_but_the_type(serve_client, scanned, monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("internal-detail")

    monkeypatch.setattr(settings_routes, "scan_image", fail)
    response = signed_post(serve_client, "/settings/registry-test", {"image": f"{HOST}/a:1"})
    assert response.status_code == 200 and "ValueError" in response.text and "internal-detail" not in response.text


def test_registry_test_scans_the_default_platform(serve_client, scanned, monkeypatch):
    seen = []
    monkeypatch.setattr(settings_routes, "DEFAULT_PLATFORM", "linux/arm64")

    def fake(trivy, ref, platform, *args, **kwargs):
        seen.append(platform)
        return ImageResult(image=ref, platform=platform, status="ok")

    monkeypatch.setattr(settings_routes, "scan_image", fake)
    signed_post(serve_client, "/settings/registry-test", {"image": f"{HOST}/a:1"})
    assert seen == ["linux/arm64"]


# Which registries the Test box may contact: a configured one, a cloud one, or one the cluster runs.

REFUSED = "is not a registry this instance uses: test an image from a configured registry or one the cluster runs"


@pytest.mark.parametrize("image", ["10.0.0.5:5000/x:1", "internal.example.com/x:1", "evil.azurecr.io.example.com/x:1"])
def test_registry_test_refuses_an_unlisted_host(strict_hosts, make_serve_client, scanned, image):
    client = make_serve_client(cloud_provider="azure", cloud_identity="id-1")
    response = signed_post(client, "/settings/registry-test", {"image": image})
    host = image.split("/")[0]
    assert response.status_code == 200 and f"error: {host} {REFUSED}" in unescape(response.text)
    assert scanned.calls == []


def test_registry_test_allows_a_host_in_a_mounted_config(strict_hosts, make_serve_client, scanned, tmp_path):
    path = tmp_path / "dc" / "regcred" / ".dockerconfigjson"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"auths": {"Internal.Example.com:5000": {"auth": "eDp5"}}}))
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    client = make_serve_client(secrets_dir=secrets, docker_configs=[path])
    response = signed_post(client, "/settings/registry-test", {"image": "internal.example.com:5000/x:1"})
    assert "is readable" in response.text and scanned.calls == ["internal.example.com:5000/x:1"]


@pytest.mark.parametrize(
    ("provider", "host"),
    [
        ("azure", "myacr.azurecr.io"),
        ("azure", "myacr.azurecr.cn"),
        ("gcp", "gcr.io"),
        ("gcp", "eu.gcr.io"),
        ("gcp", "europe-docker.pkg.dev"),
        ("aws", "123456789012.dkr.ecr.eu-west-1.amazonaws.com"),
        ("aws", "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn"),
        ("aws", "123456789012.dkr.ecr-fips.us-east-1.amazonaws.com"),
        ("aws", "123456789012.dkr-ecr.eu-west-1.on.aws"),
        ("aws", "123456789012.dkr.ecr.us-isob-east-1.sc2s.sgov.gov"),
    ],
)
def test_registry_test_allows_the_cloud_providers_hosts(strict_hosts, make_serve_client, scanned, provider, host):
    client = make_serve_client(cloud_provider=provider, cloud_identity="id-1")
    assert "is readable" in signed_post(client, "/settings/registry-test", {"image": f"{host}/x:1"}).text


@pytest.mark.parametrize(
    "host",
    ["evil.example.com", "123456789012.dkr.ecr.eu-west-1.amazonaws.com.evil.example", "dkr.ecr.eu-west-1.on.aws"],
)
def test_registry_test_aws_pattern_is_anchored(strict_hosts, make_serve_client, scanned, host):
    client = make_serve_client(cloud_provider="aws", cloud_identity="id-1")
    assert REFUSED in unescape(signed_post(client, "/settings/registry-test", {"image": f"{host}/x:1"}).text)
    assert scanned.calls == []


def test_registry_test_cloud_hosts_need_the_matching_provider(strict_hosts, make_serve_client, scanned):
    client = make_serve_client(cloud_provider="gcp", cloud_identity="id-1")
    assert REFUSED in unescape(signed_post(client, "/settings/registry-test", {"image": "myacr.azurecr.io/x:1"}).text)
    assert scanned.calls == []


def test_registry_test_allows_a_host_the_cluster_runs(strict_hosts, make_serve_client, seed, scanned):
    run_id = seed.repo.start_run("my-cluster", "my-cluster", "ui", "0.76.1", scan_level="library,os", scope="{}")
    ref = ImageRef(ref="cluster.example.com/team/app:1", repo="cluster.example.com/team/app", tag="1", digest=None)
    item = InventoryItem(image=ref, platform="linux/amd64")
    seed.repo.add_result(run_id, item, ImageResult(image=ref, platform="linux/amd64", status="ok"))
    seed.repo.finish_run(run_id, "ok")
    client = make_serve_client()
    assert "is readable" in signed_post(client, "/settings/registry-test", {"image": "cluster.example.com/y:2"}).text


def _seed_cluster_host(seed):
    run_id = seed.repo.start_run("my-cluster", "my-cluster", "ui", "0.76.1", scan_level="library,os", scope="{}")
    ref = ImageRef(ref="cluster.example.com/team/app:1", repo="cluster.example.com/team/app", tag="1", digest=None)
    seed.repo.add_result(
        run_id,
        InventoryItem(image=ref, platform="linux/amd64"),
        ImageResult(image=ref, platform="linux/amd64", status="ok"),
    )
    seed.repo.finish_run(run_id, "ok")
    return ref


def test_registry_test_auth_error_on_a_run_only_host_says_pull_secrets_are_not_tried(
    strict_hosts, make_serve_client, seed, scanned
):
    ref = _seed_cluster_host(seed)
    scanned.result = ImageResult(image=ref, platform="linux/amd64", status="error", error_kind="auth", error="denied")
    text = signed_post(make_serve_client(), "/settings/registry-test", {"image": "cluster.example.com/y:2"}).text
    assert "auth" in text and "pod pull secrets are not tried here" in text


def test_registry_test_auth_error_on_a_configured_host_has_no_pull_secret_note(
    strict_hosts, make_serve_client, scanned
):
    ref = ImageRef(ref="myacr.azurecr.io/a:1", repo="myacr.azurecr.io/a")
    scanned.result = ImageResult(image=ref, platform="linux/amd64", status="error", error_kind="auth", error="denied")
    client = make_serve_client(cloud_provider="azure")
    text = signed_post(client, "/settings/registry-test", {"image": "myacr.azurecr.io/a:1"}).text
    assert "auth" in text and "pod pull secrets are not tried here" not in text


def test_registry_test_hint_names_the_access_it_uses(make_serve_client):
    text = make_serve_client().get("/settings").text
    assert "cloud identity and the mounted Docker configs" in text and "pod pull secrets" in text


def test_registry_test_host_check_ignores_case_and_a_trailing_dot(strict_hosts, make_serve_client, seed, scanned):
    _seed_cluster_host(seed)
    client = make_serve_client()
    assert "is readable" in signed_post(client, "/settings/registry-test", {"image": "Cluster.Example.com/y:2"}).text


def test_shows_the_threat_feeds_switch_and_each_feeds_last_fetch(client, seed):
    def feed_row(html, label):
        return html.split(label, 1)[1].split("</tr>", 1)[0]

    html = unescape(client.get("/settings").text)
    assert _rows(html)["threat_feeds"] == ("false", "environment")  # tests/conftest.py turns the feeds off
    assert "never fetched" in feed_row(html, "CISA KEV last fetched")
    assert "never fetched" in feed_row(html, "EPSS last fetched")
    seed.repo._conn.execute(
        "INSERT INTO threat_feed (name, fetched_at, version, rows) VALUES ('kev', '2026-11-20T08:00:00+00:00', 'v', 3)"
    )
    seed.repo._conn.commit()
    html = unescape(client.get("/settings").text)
    assert "2026-11-20 08:00 UTC" in feed_row(html, "CISA KEV last fetched")
    assert "never fetched" in feed_row(html, "EPSS last fetched")
