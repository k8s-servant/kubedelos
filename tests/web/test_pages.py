import contextlib
import sqlite3
from datetime import UTC, datetime

import pytest
from fastapi import Request
from fastapi.responses import PlainTextResponse

from kubedelos.mcp_server import tools
from kubedelos.store.db import connect_readonly
from kubedelos.web.pages import open_db, open_db_rw, render, seconds_text, short_image, short_name, shown_context


@pytest.fixture(autouse=True)
def _test_routes(app):
    @app.get("/_page")
    def page(request: Request):
        return render(request, "base.html", {})

    @app.get("/_db")
    def db(request: Request):
        with open_db(request) as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            try:
                conn.execute("CREATE TABLE t (x)")
            except sqlite3.OperationalError as exc:
                return PlainTextResponse(f"{version} {exc}")
        return PlainTextResponse("writable")

    @app.get("/_cluster")
    def cluster(request: Request):
        with open_db(request) as conn:
            shown_context(request, conn)
        names = ",".join(entry.name for entry in request.state.contexts)
        return PlainTextResponse(f"{request.state.cluster} {names}")


def test_render_escapes_context(app, client):
    app.state.context = "<script>alert(1)</script>"
    html = client.get("/_page").text
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_open_db_is_read_only(client):
    response = client.get("/_db")
    assert response.status_code == 200
    version, _, error = response.text.partition(" ")
    assert int(version) > 0
    assert "readonly" in error


def test_open_db_rw_writes(app, client):
    @app.post("/_db_rw")
    def db_rw(request: Request):
        with open_db_rw(request) as conn:
            conn.execute("CREATE TABLE t (x)")
        return PlainTextResponse("written")

    guard = app.state.guard
    token = guard.csrf_token(client.cookies[guard.cookie_name])
    response = client.post("/_db_rw", headers={"origin": "http://127.0.0.1:9370", "x-csrf-token": token})
    assert response.text == "written"
    with contextlib.closing(connect_readonly(app.state.settings.db_path)) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name = 't'").fetchone()


def test_short_image_cuts_the_digest():
    row = {"repo": "reg.example.com/app", "tag": "1", "digest": "sha256:" + "a" * 64, "image": "ref"}
    assert short_image(row) == "reg.example.com/app:1@sha256:aaaaaaaa"
    assert short_image({"repo": "reg.example.com/app", "tag": None, "digest": None, "image": "ref"}) == (
        "reg.example.com/app"
    )
    assert short_image({"repo": "", "image": "ref"}) == "ref"


def test_short_name_keeps_the_last_path_segment_and_a_short_tag():
    assert short_name("reg.example.com:5000/team/app:1.2") == "app:1.2"
    assert short_name("reg.example.com/app:1.2@sha256:" + "a" * 64) == "app:1.2"
    assert short_name("reg.example.com/app@sha256:" + "b" * 64) == "app@sha256:bbbbbbbb"
    assert short_name("app") == "app"
    long = "reg.example.com/kindnetd:v20251212-v0.29.0-alpha-105-g20ccfc88"
    assert short_name(long) == "kindnetd:v20251212-\u2026"


def _ok_run(seed, context):
    run_id = seed.repo.start_run(context, context, "ui", "0.76.1", scan_level="library,os", scope=seed.settings.scope)
    seed.repo.finish_run(run_id, "ok")
    return run_id


@pytest.mark.parametrize("path", ["/", "/findings", "/scans"])
def test_unknown_context_is_404(client, path):
    response = client.get(path, params={"context": "<nope>"})
    assert response.status_code == 404
    assert "Unknown context" in response.text and "&lt;nope&gt;" in response.text and "<nope>" not in response.text


def test_kubeconfig_is_read_on_each_page(client, kube_contexts):
    assert client.get("/", params={"context": "prod-eu"}).status_code == 404
    kube_contexts.append("prod-eu")  # added to the kubeconfig while the UI runs
    response = client.get("/", params={"context": "prod-eu"})
    assert response.status_code == 200 and "No scans of <strong>prod-eu</strong>" in response.text


def test_a_context_known_only_from_history_is_shown(client, seed):
    _ok_run(seed, "old-cluster")
    response = client.get("/findings", params={"context": "old-cluster"})
    assert response.status_code == 200 and "old-cluster" in response.text


def test_default_context_links_carry_no_context(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    _ok_run(seed, seed.context)
    html = client.get("/").text
    nav = html[html.index('<nav aria-label="Main">') : html.index("</nav>")]
    assert "context=" not in nav


def test_links_carry_the_shown_context(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    _ok_run(seed, "prod-eu")
    html = client.get("/", params={"context": "prod-eu"}).text
    nav = html[html.index('<nav aria-label="Main">') : html.index("</nav>")]
    for path in ("/", "/findings", "/scans"):
        assert f'href="{path}?context=prod-eu"' in nav
    assert '<a class="wordmark" href="/?context=prod-eu"' in html


def test_awkward_context_names_are_escaped_and_encoded(client, kube_contexts):
    name = 'arn:aws:eks:eu-west-1:1:cluster/a b&c"><script>x</script>'
    kube_contexts.append(name)
    html = client.get("/scans", params={"context": name}).text
    assert "<script>x</script>" not in html
    assert "arn:aws:eks:eu-west-1:1:cluster/a b&amp;c&#34;&gt;&lt;script&gt;" in html
    encoded = "arn%3Aaws%3Aeks%3Aeu-west-1%3A1%3Acluster%2Fa+b%26c%22%3E%3Cscript%3Ex%3C%2Fscript%3E"
    assert f'href="/findings?context={encoded}"' in html  # the nav link keeps it intact
    assert client.get("/findings", params={"context": name}).status_code == 200


@pytest.mark.parametrize(
    "seconds, text",
    [
        (None, "—"),
        (0, "0 s"),
        (0.4, "0 s"),
        (42.6, "43 s"),
        (60, "1 min 0 s"),
        (630.2, "10 min 30 s"),
        (3725, "62 min 5 s"),
    ],
)
def test_seconds_text(seconds, text):
    assert seconds_text(seconds) == text


def test_a_history_only_cluster_opens_by_its_newest_context(client, seed, kube_contexts):
    server = "https://gone.example.com"
    for context in ("gone", "gone-admin"):  # both contexts have left the kubeconfig since
        run_id = seed.repo.start_run(server, context, "ui", "0.76.1", scan_level="library,os", scope=None)
        seed.repo.finish_run(run_id, "ok")
    _ok_run(seed, seed.context)
    kube_contexts.append("other")  # a second entry, so the switcher shows
    html = client.get("/").text
    switcher = html[html.index('<details class="context context-switch"') :]
    switcher = switcher[: switcher.index("</details>")]
    assert 'href="/?context=gone-admin">gone-admin</a>' in switcher  # one entry, named by its newest run's context
    assert ">gone</a>" not in switcher
    response = client.get("/scans", params={"context": "gone-admin"})
    assert response.status_code == 200
    rows = response.text[response.text.index("<tbody>") :]
    assert rows.count("<tr>") == 2  # the cluster's whole history
    assert "via gone</div>" in rows


def test_an_old_context_of_a_cluster_still_opens_its_history(client, seed, kube_contexts, kube_servers):
    server = "https://prod.example.com:6443"
    kube_contexts.append("prod")
    kube_servers["prod"] = server
    old = seed.repo.start_run(server, "prod-old", "ui", "0.76.1", scan_level="library,os", scope=seed.settings.scope)
    seed.repo.finish_run(old, "ok")  # through a context the kubeconfig no longer has
    newest = seed.repo.start_run(server, "prod", "ui", "0.76.1", scan_level="library,os", scope=seed.settings.scope)
    seed.repo.finish_run(newest, "ok")
    response = client.get("/", params={"context": "prod-old"})
    assert response.status_code == 200
    assert '<li class="chip">Run 2</li>' in response.text and f"run_id={newest}" in response.text
    assert client.get("/", params={"context": "never-seen"}).status_code == 404


def test_the_ui_and_the_mcp_server_resolve_a_reused_context_name_alike(client, seed, kube_contexts, app):
    old, new = "https://a.example.com", "https://b.example.com"  # "prod" now means the recreated cluster
    for key in (old, new):
        run_id = seed.repo.start_run(key, "prod", "ui", "0.76.1", scan_level="library,os", scope=None)
        seed.repo.finish_run(run_id, "ok")
    kube_contexts.append("other")  # neither cluster is in the kubeconfig any more
    db = tools.Db(seed.settings.db_path, None)
    conn = db.open()
    try:
        listed = {
            c["key"]: c["name"] for c in tools.list_clusters(conn, db, datetime(2026, 2, 1, tzinfo=UTC))["clusters"]
        }
        for given in listed.values():  # each name the switcher and list_clusters show
            cluster, names = client.get("/_cluster", params={"context": given}).text.split(" ")
            assert cluster == tools.resolve_cluster(conn, db, given)
            assert set(listed.values()) <= set(names.split(","))  # both surfaces list the same names
    finally:
        conn.close()
    assert listed == {old: old, new: "prod"}
