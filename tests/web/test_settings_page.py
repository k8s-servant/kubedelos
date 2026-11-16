import re
from html import unescape

from kubedelos.config import Settings
from kubedelos.trivy.pins import TRIVY_VERSION
from tests.web.conftest import TOKEN


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


def test_nav_ends_with_settings(client):
    nav = client.get("/settings").text.split('<nav aria-label="Main">', 1)[1].split("</nav>", 1)[0]
    labels = re.findall(r">([A-Z][a-z]+)</a>", nav)
    assert labels[-1] == "Settings"
    assert '<a href="/settings" aria-current="page">Settings</a>' in nav


def test_an_unset_setting_names_what_is_used_instead(client):
    rows = _rows(client.get("/settings").text)
    assert rows["kubeconfig"][0] == "not set: $KUBECONFIG or ~/.kube/config"
    assert rows["trivy_path"][0] == "not set: the pinned Trivy"
