"""Tests for the scans page: the history, the start form, starting and cancelling a scan, and the progress fragment."""

import contextlib
import itertools
import json
import re
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from html import unescape
from pathlib import Path

import pytest

import kubedelos.store.db
from kubedelos.config import Settings
from kubedelos.kube.inventory import InventoryWarning
from kubedelos.models import ImageRef, ImageResult, InventoryItem, Workload
from kubedelos.scan.service import Progress, ScanOutcome
from kubedelos.store import queue, runlock
from kubedelos.web import pages
from kubedelos.web.jobs import ScanRunner
from kubedelos.web.routes import scans
from tests.web.conftest import signed_post

CLUSTER = Settings().scope


def _run(seed, status="ok", *, owner=None):
    run_id = seed.repo.start_run(seed.context, "cli", "0.76.1", scan_level="library,os", scope=CLUSTER, owner=owner)
    if status != "running":
        seed.repo.finish_run(run_id, status)
    return run_id


def _put(seed, run_id, ref, status="ok"):
    image = ImageRef(ref=ref, repo="reg.example.com/app", tag="1", digest="sha256:" + "a" * 64)
    item = InventoryItem(
        image=image,
        platform="linux/amd64",
        workloads=[Workload(namespace="ns", kind="Deployment", name="a", container="c")],
    )
    seed.repo.add_result(run_id, item, ImageResult(image=image, platform="linux/amd64", status=status, findings=[]))


def _rows(html):
    """The history table's body rows, as raw HTML."""
    body = html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    return re.findall(r"<tr>(.*?)</tr>", body, re.S)


def _hrefs(html):
    return [unescape(h) for h in re.findall(r'href="([^"]*)"', html)]


def test_scans_page_lists_every_status_but_links_only_results(client, seed):
    ids = {status: _run(seed, status) for status in ("ok", "partial", "cancelled", "failed")}
    _put(seed, ids["partial"], "a")
    _put(seed, ids["partial"], "b", status="error")
    html = client.get("/scans").text
    rows = _rows(html)
    assert len(rows) == 4
    by_id = {status: next(r for r in rows if f"Run {run_id}<" in r) for status, run_id in ids.items()}
    for status, row in by_id.items():
        assert re.search(rf'class="chip[^"]*">{status}<', row), status
        linked = f"/findings?run_id={ids[status]}" in _hrefs(row)
        assert linked == (status in ("ok", "partial")), status
    assert "whole cluster" in by_id["ok"] and "os + library packages" in by_id["ok"]
    assert "1 min 0 s" in by_id["ok"]
    assert re.search(
        r"<td[^>]*>2</td>\s*<td[^>]*><a href=\"/scans/(\d+)/failed\">1</a>"
        r" · <a href=\"/scans/\1/failed#retry\">retry</a></td>",
        by_id["partial"],
    )  # 2 images, 1 failed, linked; the newest result run offers a retry
    assert "1\u20134 of 4" in html


def test_scans_page_marks_an_unowned_running_row_interrupted(client, seed):
    dead = _run(seed, "running", owner="deadbeef")
    legacy = _run(seed, "running")
    with runlock.hold(seed.settings.data_dir) as owner:
        live = _run(seed, "running", owner=owner)
        rows = _rows(client.get("/scans").text)
    by_id = {run_id: next(r for r in rows if f"Run {run_id}<" in r) for run_id in (dead, legacy, live)}
    assert "interrupted" in by_id[dead] and "interrupted" in by_id[legacy]
    assert "running" in by_id[live] and "interrupted" not in by_id[live]
    assert "—" in by_id[live]
    assert not any("/findings?run_id=" in r for r in rows)
    with contextlib.closing(kubedelos.store.db.connect_readonly(seed.settings.db_path)) as conn:
        statuses = {r[0] for r in conn.execute("SELECT status FROM scan_run")}
    assert statuses == {"running"}  # read-only: the page closes nothing


def test_scans_page_pages_with_the_real_total(client, seed):
    for _ in range(30):
        _run(seed)
    first = client.get("/scans").text
    assert "1\u201325 of 30" in first and len(_rows(first)) == 25 and "/scans?page=2" in _hrefs(first)
    second = client.get("/scans?page=2").text
    assert "26\u201330 of 30" in second and len(_rows(second)) == 5
    assert client.get("/scans?page=0").status_code == 400
    assert client.get(f"/scans?page={10**9 + 1}").status_code == 400


def test_scans_page_without_runs(client):
    html = client.get("/scans").text
    assert "No scans of" in html and "<tbody>" not in html
    assert 'action="/scans"' in html  # the start form shows anyway


def test_scan_form_shows_saved_values(client, app):
    app.state.settings = app.state.settings.model_copy(
        update={"namespaces": ["web"], "selector": "app=x", "pkg_types": ("os",)}
    )
    html = client.get("/scans").text
    form = html.split('<form method="post" action="/scans"', 1)[1].split("</form>", 1)[0]
    assert re.search(r'name="namespaces"[^>]*value="web"', form)
    assert re.search(r'name="selector"[^>]*value="app=x"', form)
    assert re.search(r'name="pkg_types" value="os" checked', form)
    assert re.search(r'name="pkg_types" value="library">', form)
    assert "saved: web" in form and "saved: app=x" in form and "saved: OS packages only" in form
    token = re.search(r'name="csrf_token" value="([^"]+)"', form)
    assert token and token.group(1)


def test_scan_form_shows_saved_exclude_namespaces_and_parallelism(client, app):
    app.state.settings = app.state.settings.model_copy(update={"exclude_namespaces": ["kube-system"], "parallelism": 6})
    html = client.get("/scans").text
    form = html.split('<form method="post" action="/scans"', 1)[1].split("</form>", 1)[0]
    assert re.search(r'name="exclude_namespaces"[^>]*value="kube-system"', form)
    assert re.search(r'type="number" name="parallelism" value="6" min="1" max="32"', form)
    assert "saved: kube-system" in form and "saved: 6" in form
    app.state.settings = app.state.settings.model_copy(update={"exclude_namespaces": []})
    assert "saved: none" in client.get("/scans").text


def test_nav_has_scans(client):
    html = client.get("/findings").text
    assert html.index('href="/findings"') < html.index('href="/scans"')
    assert '<a href="/scans" aria-current="page">Scans</a>' in client.get("/scans").text


def test_scans_page_is_read_only(client, seed, monkeypatch):
    _run(seed)

    def refuse(*args, **kwargs):
        raise AssertionError("the scans page opened a read-write connection")

    monkeypatch.setattr(kubedelos.store.db, "connect", refuse)
    assert not hasattr(scans, "connect")  # it can't hold its own reference that the patch would miss
    assert client.get("/scans").status_code == 200


@pytest.mark.parametrize(
    "seconds, text",
    [(0, "0 s"), (13, "13 s"), (59, "59 s"), (60, "1 min 0 s"), (125, "2 min 5 s"), (3725, "62 min 5 s")],
)
def test_duration_text(seconds, text):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    assert scans.duration_text(start, start + timedelta(seconds=seconds)) == text
    assert scans.duration_text(start, None) == "—"


def test_scan_form_escapes_saved_values(client, app):
    app.state.settings = app.state.settings.model_copy(update={"selector": '"><script>x</script>'})
    html = client.get("/scans").text
    escaped = "&#34;&gt;&lt;script&gt;x&lt;/script&gt;"
    assert re.search(rf'name="selector"[^>]*value="{escaped}"', html)
    assert f"saved: {escaped}" in html
    assert "<script>x" not in html


def test_scans_page_hides_other_contexts(client, seed):
    mine = _run(seed)
    other = seed.repo.start_run("other-cluster", "cli", "0.76.1", scan_level="library,os", scope=CLUSTER)
    seed.repo.finish_run(other, "ok")
    rows = _rows(client.get("/scans").text)
    assert len(rows) == 1
    assert f"Run {mine}<" in rows[0]


# Starting, cancelling and the progress fragment

ORIGIN = {"origin": "http://127.0.0.1:9370"}
FORM = {
    "namespaces": "",
    "namespace_selector": "",
    "selector": "",
    "exclude_images": "",
    "exclude_namespaces": "",
    "parallelism": "4",
    "pkg_types": ["os", "library"],
}


class FakeScan:
    """A stand-in for ``run_scan`` that blocks until released (or cancelled), so each test controls the timing."""

    def __init__(self, *, status: str = "ok", run_id: int = 7) -> None:
        self.release = threading.Event()
        self.entered = threading.Event()
        self.status = status
        self.run_id = run_id
        self.calls: list[dict] = []
        self.honour_cancel = True  # False keeps the scan "stopping" until released, as a slow Trivy would

    def __call__(self, settings, **kw):
        self.calls.append({"settings": settings, **kw})
        self.on_progress = kw["on_progress"]
        self.entered.set()
        while not self.release.wait(0.01):
            if self.honour_cancel and kw["cancel"].is_set():
                return ScanOutcome(run_id=self.run_id, warnings=[], status="cancelled")
        return ScanOutcome(run_id=self.run_id, warnings=[], status=self.status)


@pytest.fixture
def fake(app):
    scan = FakeScan()
    runner = ScanRunner(app.state.settings, app.state.context, scan=scan)
    app.state.scans = runner
    yield scan
    scan.release.set()
    runner.shutdown(timeout=5)


def _csrf(client) -> str:
    guard = client.app.state.guard
    return guard.csrf_token(client.cookies[guard.cookie_name])


def _start(client, **fields):
    data = {**FORM, **fields, "csrf_token": _csrf(client)}
    return client.post("/scans", data=data, headers=ORIGIN, follow_redirects=False)


def _wait_for(app, state):
    for _ in range(500):
        view = app.state.scans.view()
        if view is not None and view.state == state:
            return view
        threading.Event().wait(0.01)
    raise AssertionError(f"the scan never reached {state!r}: {app.state.scans.view()}")


def _progress(client, **params):
    response = client.get("/scans/progress", params=params)
    assert response.status_code == 200
    return response.text


def test_start_requires_csrf(client, fake):
    response = client.post("/scans", data=FORM, headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 403
    assert not fake.calls and client.app.state.scans.view() is None


def test_start_runs_with_the_form_overrides(client, app, fake):
    response = _start(
        client,
        namespaces="web, api  jobs",
        namespace_selector=" ",
        selector="app=x,tier=web",
        exclude_images="*/pause:*,  reg.example.com/skip:*",
        exclude_namespaces="kube-system, local-path-storage",
        parallelism=" 8 ",
        pkg_types=["os"],
    )
    assert response.status_code == 303 and response.headers["location"] == "/scans"
    assert fake.entered.wait(5)
    settings = fake.calls[0]["settings"]
    assert settings.namespaces == ["web", "api", "jobs"]
    assert settings.namespace_selector is None
    assert settings.selector == "app=x,tier=web"
    assert settings.exclude_images == ["*/pause:*", "reg.example.com/skip:*"]
    assert settings.pkg_types == ("os",)
    assert settings.exclude_namespaces == ["kube-system", "local-path-storage"]
    assert settings.parallelism == 8
    assert settings.context == app.state.context
    assert fake.calls[0]["trigger"] == "ui"


def test_start_uses_the_result_cache_unless_rescan_is_ticked(client, app, fake):
    assert _start(client).status_code == 303
    assert fake.entered.wait(5)
    assert fake.calls[0]["rescan"] is False
    fake.release.set()
    _wait_for(app, "finished")
    fake.entered.clear()
    fake.release.clear()
    assert _start(client, rescan="on").status_code == 303
    assert fake.entered.wait(5)
    assert fake.calls[1]["rescan"] is True


def test_form_offers_rescan_unticked(client, fake):
    page = client.get("/scans").text
    assert '<input type="checkbox" name="rescan" value="on">' in page
    assert "Rescan every image" in page


def test_a_refused_start_keeps_rescan_ticked(client, fake):
    page = _start(client, parallelism="0", rescan="on").text
    assert '<input type="checkbox" name="rescan" value="on" checked>' in page


def test_second_start_is_refused(client, fake):
    assert _start(client).status_code == 303
    assert fake.entered.wait(5)
    response = _start(client, namespaces="web")
    assert response.status_code == 409
    assert "a scan is already running" in response.text
    assert re.search(r'name="namespaces"[^>]*value="web"', response.text)  # what was typed survives
    assert 'action="/scans"' in response.text  # the page itself, re-rendered
    assert len(fake.calls) == 1


def test_invalid_pkg_types_rerenders_with_400(client, fake):
    response = _start(client, namespaces="web", pkg_types=["windows"])
    assert response.status_code == 400
    assert re.search(r'name="namespaces"[^>]*value="web"', response.text)  # what was typed survives
    assert "Package types" in response.text and "must be a comma-separated list of library, os" in response.text
    assert 'action="/scans"' in response.text
    none_ticked = _start(client, pkg_types=[])
    assert none_ticked.status_code == 400 and "Package types" in none_ticked.text
    assert not fake.calls and client.app.state.scans.view() is None


@pytest.mark.parametrize("value", ["0", "33", "four", ""])
def test_invalid_parallelism_rerenders_with_400(client, fake, value):
    response = _start(client, namespaces="web", parallelism=value)
    assert response.status_code == 400
    assert "Parallel images:" in response.text
    assert re.search(r'name="namespaces"[^>]*value="web"', response.text)  # what was typed survives
    assert re.search(rf'name="parallelism" value="{value}"', response.text)
    assert not fake.calls and client.app.state.scans.view() is None


def test_cancel_switches_readout_at_once(client, app, fake):
    fake.honour_cancel = False  # else the scan may end before the readout is read, and the test races
    _start(client)
    assert fake.entered.wait(5)
    fake.on_progress(Progress(total=4, done=1, errors=0, current="reg.example.com/app:1", phase="scanning"))
    assert 'action="/scans/cancel"' in _progress(client)
    response = client.post("/scans/cancel", data={"csrf_token": _csrf(client)}, headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/scans"
    html = _progress(client)
    assert "stopping once the images in flight finish" in html
    assert 'action="/scans/cancel"' not in html
    assert client.post("/scans/cancel", headers=ORIGIN, follow_redirects=False).status_code == 403  # CSRF


def test_progress_fragment_shows_counts_and_image(client, app, fake):
    _start(client)
    assert fake.entered.wait(5)
    ref = "reg.example.com/app:1@sha256:" + "a" * 64
    fake.on_progress(Progress(total=12, done=6, errors=1, current=ref, phase="scanning", cached=2))
    html = _progress(client)
    assert "<html" not in html  # the fragment only
    assert "scanning" in html
    assert "6 of 12 images" in html
    assert re.search(r"3</\w+>\s*scanned", html) and re.search(r"2</\w+>\s*cached", html)
    assert re.search(r"1</\w+>\s*failed", html)
    assert re.search(r"last finished: <code>reg\.example\.com/app:1@sha256:aaaaaaaa</code>", html)
    assert "a" * 64 not in html
    assert 'name="csrf_token"' in html
    fake.on_progress(Progress(total=12, done=6, errors=1, current=None, phase="trivy-db", cached=2))
    assert "Trivy DB" in _progress(client)
    fake.on_progress(Progress(total=0, done=0, errors=0, current=None, phase="threat-feeds"))
    assert "threat feeds" in _progress(client)


def test_progress_fragment_shows_the_eta(client, app, monkeypatch):
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    clock = itertools.chain([t0], itertools.repeat(t0 + timedelta(minutes=5)))
    scan = FakeScan()
    runner = ScanRunner(app.state.settings, app.state.context, scan=scan, clock=lambda: next(clock))
    app.state.scans = runner
    try:
        _start(client)
        assert scan.entered.wait(5)
        scan.on_progress(Progress(total=10, done=0, errors=0, current=None, phase="trivy-db"))
        scan.on_progress(Progress(total=10, done=0, errors=0, current=None, phase="scanning"))
        scan.on_progress(Progress(total=10, done=5, errors=0, current="a", phase="scanning"))
        assert "about 5 min left" in _progress(client)  # 5 images in 5 min, 5 to go
    finally:
        scan.release.set()
        runner.shutdown(timeout=5)


def test_progress_fragment_before_any_scan(client, fake):
    html = _progress(client)
    assert 'id="scan-progress"' in html
    assert "images" not in html and 'action="/scans/cancel"' not in html


@pytest.mark.parametrize("status, linked", [("ok", True), ("partial", True), ("cancelled", False)])
def test_finished_ok_links_results_cancelled_does_not(client, app, fake, status, linked):
    fake.status = status
    _start(client)
    assert fake.entered.wait(5)
    fake.on_progress(Progress(total=1, done=1, errors=0, current="a", phase="saving"))
    fake.release.set()
    _wait_for(app, "finished")
    html = _progress(client)
    assert re.search(rf'class="chip[^"]*">{status}<', html)
    assert ("/findings?run_id=7" in _hrefs(html)) == linked
    assert ("see results" in html) == linked
    assert 'action="/scans/cancel"' not in html


def test_progress_fragment_shows_the_error(client, app):
    def broken(settings, **kw):
        raise RuntimeError("cannot reach https://user:hunter2@reg.example.com/v2/")

    runner = ScanRunner(app.state.settings, app.state.context, scan=broken)
    app.state.scans = runner
    try:
        _start(client)
        _wait_for(app, "error")
        html = _progress(client)
        assert re.search(r'class="callout[^"]*"[^>]*>.*RuntimeError', html, re.S)
        assert "hunter2" not in html
        assert "/findings?run_id=" not in html
    finally:
        runner.shutdown(timeout=5)


def test_start_sweeps_stale_runs_first(client, seed, fake):
    dead = _run(seed, "running", owner="deadbeef")
    assert _start(client).status_code == 303
    with contextlib.closing(kubedelos.store.db.connect_readonly(seed.settings.db_path)) as conn:
        assert conn.execute("SELECT status FROM scan_run WHERE id = ?", (dead,)).fetchone()[0] == "failed"


def test_busy_start_still_reports_409_after_the_sweep(client, seed, fake):
    assert _start(client).status_code == 303
    assert fake.entered.wait(5)
    dead = _run(seed, "running", owner="deadbeef")
    assert _start(client).status_code == 409
    with contextlib.closing(kubedelos.store.db.connect_readonly(seed.settings.db_path)) as conn:
        assert conn.execute("SELECT status FROM scan_run WHERE id = ?", (dead,)).fetchone()[0] == "failed"


def test_get_routes_stay_read_only(client, seed, fake, monkeypatch):
    _run(seed)
    _start(client)
    assert fake.entered.wait(5)

    def refuse(*args, **kwargs):
        raise AssertionError("a GET opened a read-write connection")

    monkeypatch.setattr(kubedelos.store.db, "connect", refuse)
    # Neither module may hold its own reference to connect, which the patch would miss.
    assert not hasattr(scans, "connect") and not hasattr(pages, "connect")
    assert client.get("/scans").status_code == 200
    assert client.get("/scans/progress").status_code == 200


def test_scans_page_includes_the_progress_fragment(client, fake):
    _start(client)
    assert fake.entered.wait(5)
    fake.on_progress(Progress(total=3, done=1, errors=0, current="a", phase="scanning"))
    html = client.get("/scans").text
    assert 'id="scan-progress"' in html and "1 of 3 images" in html


def test_unreadable_form_is_400(client, fake):
    headers = {**ORIGIN, "x-csrf-token": _csrf(client), "content-type": "application/x-www-form-urlencoded"}
    response = client.post("/scans", headers=headers, content=b"\xff\xfe", follow_redirects=False)
    assert response.status_code == 400 and "the form could not be read" in response.text
    many = "&".join(f"f{i}=x" for i in range(200)).encode()
    assert client.post("/scans", headers=headers, content=many, follow_redirects=False).status_code == 400
    bad_escape = client.post("/scans", headers=headers, content=b"namespaces=%ff&pkg_types=os", follow_redirects=False)
    assert bad_escape.status_code == 400 and "the form could not be read" in bad_escape.text
    huge = b"namespaces=" + b"a" * (64 * 1024) + b"&pkg_types=os"
    too_big = client.post("/scans", headers=headers, content=huge, follow_redirects=False)
    assert too_big.status_code == 400 and "the form could not be read" in too_big.text
    assert not fake.calls


def test_busy_database_is_503(client, fake, monkeypatch):
    def locked(conn, data_dir):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(scans.runlock, "close_stale_runs", locked)
    response = _start(client, namespaces="web")
    assert response.status_code == 503
    assert "the database is busy; try again" in response.text
    assert re.search(r'name="namespaces"[^>]*value="web"', response.text)
    assert not fake.calls


def test_start_runs_off_the_event_loop(client, fake, monkeypatch):
    threads = []
    sweep = scans.runlock.close_stale_runs

    def recording(conn, data_dir):
        threads.append(threading.current_thread())
        return sweep(conn, data_dir)

    monkeypatch.setattr(scans.runlock, "close_stale_runs", recording)
    loop_thread = []

    @client.app.get("/_loop_thread")
    async def loop_thread_route():
        loop_thread.append(threading.current_thread())
        return {}

    client.get("/_loop_thread")
    assert _start(client).status_code == 303
    assert threads and threads[0] is not loop_thread[0]


HTMX_CONFIG = (
    '<meta name="htmx-config" content=\'{"includeIndicatorStyles":false,"allowEval":false,"allowScriptTags":false}\'>'
)


def _nonce(response) -> str:
    match = re.search(r"'nonce-([^']+)'", response.headers["content-security-policy"])
    assert match
    return match.group(1)


def test_scans_page_loads_htmx_with_the_nonce_only_there(client, fake):
    response = client.get("/scans")
    nonce = _nonce(response)
    assert re.search(rf'<script src="/static/htmx\.min\.js\?v=[0-9a-f]{{12}}" nonce="{nonce}"', response.text)
    assert response.text.count("<script") == 1
    assert client.get("/static/htmx.min.js").status_code == 200
    for path in ("/", "/findings"):
        assert "<script" not in client.get(path).text, path


def test_no_inline_style_or_eval_config(client, fake):
    html = client.get("/scans").text
    assert HTMX_CONFIG in html
    assert html.index(HTMX_CONFIG) < html.index('<script src="/static/htmx.min.js?v=')  # read when htmx loads
    assert "<style" not in html and "style=" not in html


def test_progress_box_polls_only_while_active(client, app, fake):
    poll = 'hx-get="/scans/progress" hx-trigger="every 2s" hx-swap="outerHTML"'
    assert "hx-trigger" not in _progress(client)  # nothing to follow before the first scan
    _start(client)
    assert fake.entered.wait(5)
    fake.on_progress(Progress(total=2, done=1, errors=0, current="a", phase="scanning"))
    assert re.search(rf'<div id="scan-progress" class="scan-progress" {poll}>', _progress(client))
    assert poll in client.get("/scans").text
    assert poll in client.get("/scans/progress", headers={"HX-Request": "true"}).text  # htmx gets the same fragment
    fake.release.set()
    _wait_for(app, "finished")
    assert "hx-trigger" not in _progress(client)
    assert "hx-trigger" not in client.get("/scans").text


def test_noscript_refresh_link(client, fake):
    _start(client)
    assert fake.entered.wait(5)
    html = _progress(client)
    assert re.search(r'<noscript>\s*<p><a href="/scans">refresh</a>[^<]*</p>\s*</noscript>', html)
    fake.release.set()
    _wait_for(client.app, "finished")
    assert "<noscript>" not in _progress(client)  # nothing left to refresh for


def test_htmx_poll_refreshes_the_page_once_the_scan_ends(client, app, fake):
    htmx = {"HX-Request": "true"}
    assert "HX-Refresh" not in client.get("/scans/progress", headers=htmx).headers  # no scan yet
    _start(client)
    assert fake.entered.wait(5)
    fake.on_progress(Progress(total=2, done=1, errors=0, current="a", phase="scanning"))
    assert "HX-Refresh" not in client.get("/scans/progress", headers=htmx).headers  # still running
    fake.release.set()
    _wait_for(app, "finished")
    done = client.get("/scans/progress", headers=htmx)
    assert done.headers["HX-Refresh"] == "true"  # so the history row is reloaded too
    assert "hx-trigger" not in done.text
    assert "HX-Refresh" not in client.get("/scans/progress").headers  # a plain GET just gets the fragment
    page = client.get("/scans")
    assert "HX-Refresh" not in page.headers and "hx-trigger" not in page.text  # the reload can't loop


@pytest.mark.parametrize(
    "seconds, text",
    [
        (1, "less than a minute left"),
        (59, "less than a minute left"),
        (60, "about 1 min left"),
        (61, "about 2 min left"),
    ],
)
def test_eta_text(seconds, text):
    assert scans.eta_text(timedelta(seconds=seconds)) == text


def test_saved_pkg_types_hint_reads_as_words(client, app):
    html = client.get("/scans").text
    assert "saved: os + library packages" in html and "saved: library,os" not in html
    app.state.settings = app.state.settings.model_copy(update={"pkg_types": ("library",)})
    assert "saved: library packages only" in client.get("/scans").text


def test_start_title_keeps_the_context_case(client, app):
    html = client.get("/scans").text
    assert f'Start a scan of <code class="ctx">{app.state.context}</code>' in html


def test_live_region_is_a_stable_ancestor_of_the_swapped_box(client, fake):
    """htmx replaces #scan-progress on every poll, so the live region must sit outside it to be announced."""
    _start(client)
    assert fake.entered.wait(5)
    fake.on_progress(Progress(total=2, done=1, errors=0, current="a", phase="scanning"))
    page = client.get("/scans").text
    assert re.search(r'<div class="scan-live" aria-live="polite">\s*<div id="scan-progress"', page)
    assert "aria-live" not in _progress(client)  # the swapped fragment carries none of its own


# Other contexts


def test_scans_page_of_another_context_scans_that_context(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    _run(seed)
    theirs = seed.repo.start_run("prod-eu", "ui", "0.76.1", scan_level="library,os", scope=CLUSTER)
    seed.repo.finish_run(theirs, "ok")
    html = client.get("/scans", params={"context": "prod-eu"}).text
    form = html.split('<form method="post" action="/scans"', 1)[1].split("</form>", 1)[0]
    assert '<input type="hidden" name="context" value="prod-eu">' in form
    assert ">Scan prod-eu</button>" in form
    rows = _rows(html)
    assert theirs == 2 and len(rows) == 1 and "Run 1<" in rows[0]  # numbered within its cluster
    assert f'href="/findings?context=prod-eu&amp;run_id={theirs}"' in rows[0]


def test_start_scans_the_posted_context(client, kube_contexts, fake):
    kube_contexts.append("prod-eu")
    response = _start(client, context="prod-eu")
    assert response.status_code == 303 and response.headers["location"] == "/scans?context=prod-eu"
    assert fake.entered.wait(5)
    assert fake.calls[0]["settings"].context == "prod-eu"


def test_start_refuses_a_context_not_in_the_kubeconfig(client, seed, fake):
    gone = seed.repo.start_run("old-cluster", "ui", "0.76.1", scan_level="library,os", scope=CLUSTER)
    seed.repo.finish_run(gone, "ok")  # known from history, so the page renders
    response = _start(client, context="old-cluster")
    assert response.status_code == 400
    assert "old-cluster is not in your kubeconfig" in response.text
    assert not fake.calls and client.app.state.scans.view() is None
    assert _start(client, context="never-heard-of").status_code == 400


def test_history_only_context_offers_no_scan(client, seed):
    gone = seed.repo.start_run("old-cluster", "ui", "0.76.1", scan_level="library,os", scope=CLUSTER)
    seed.repo.finish_run(gone, "ok")
    html = client.get("/scans", params={"context": "old-cluster"}).text
    assert '<form method="post" action="/scans"' not in html
    assert "not in your kubeconfig" in html


def test_progress_names_a_scan_of_another_context(client, kube_contexts, fake):
    kube_contexts.append("prod-eu")
    _start(client, context="prod-eu")
    assert fake.entered.wait(5)
    mine = client.get("/scans").text  # the startup context's page, while prod-eu scans
    assert "Scanning prod-eu" in mine
    assert 'href="/scans?context=prod-eu"' in mine
    assert _start(client).status_code == 409  # still one scan at a time, across contexts


def test_cancel_returns_to_the_posted_context(client, kube_contexts, fake):
    kube_contexts.append("prod-eu")
    _start(client, context="prod-eu")
    assert fake.entered.wait(5)
    fake.on_progress(Progress(total=4, done=1, errors=0, current="reg.example.com/app:1", phase="scanning"))
    # The button returns to the page it was on: prod-eu's here, the startup context's on that page.
    form = _progress(client, context="prod-eu").split('action="/scans/cancel"', 1)[1].split("</form>", 1)[0]
    assert '<input type="hidden" name="context" value="prod-eu">' in form
    form = _progress(client).split('action="/scans/cancel"', 1)[1].split("</form>", 1)[0]
    assert 'name="context"' not in form
    response = client.post(
        "/scans/cancel",
        data={"csrf_token": _csrf(client), "context": "prod-eu"},
        headers=ORIGIN,
        follow_redirects=False,
    )
    assert response.status_code == 303 and response.headers["location"] == "/scans?context=prod-eu"


def _readout(html):
    start = html.index('<div id="scan-progress"')
    return html[start : html.index("</section>", start)]


@pytest.mark.parametrize("scanned", ["prod-eu", "my-cluster"])
@pytest.mark.parametrize("shown", ["prod-eu", "my-cluster"])
def test_progress_poll_keeps_the_page_context(client, kube_contexts, fake, scanned, shown):
    # The poll must render the readout the page did, or the title and the "go to its page" hint flip after 2 s.
    kube_contexts.append("prod-eu")
    _start(client, context=scanned)
    assert fake.entered.wait(5)
    fake.on_progress(Progress(total=4, done=1, errors=0, current="reg.example.com/app:1", phase="scanning"))
    page = client.get("/scans", params={"context": shown} if shown != "my-cluster" else {}).text
    poll = _progress(client, **({"context": shown} if shown != "my-cluster" else {}))
    assert _readout(page) == _readout(poll)
    assert ("Go to its page" in poll) is (scanned != shown)
    expected = "/scans/progress?context=prod-eu" if shown == "prod-eu" else "/scans/progress"
    assert f'hx-get="{expected}"' in poll


def test_kubeconfig_is_read_once_per_request(client, app, kube_contexts, fake):
    calls = []
    listing = app.state.list_contexts

    def counted():
        calls.append(1)
        return listing()

    app.state.list_contexts = counted
    client.get("/scans")
    assert len(calls) == 1
    calls.clear()
    _start(client, context="nowhere")  # the refusal re-renders the page
    assert len(calls) == 1


def test_progress_lists_the_newest_failures_while_scanning(client, app, fake, seed):
    run_id = _run(seed, "running")
    for i in range(7):
        _put(seed, run_id, f"reg.example.com/app{i}:1", status="error")
    _start(client)
    assert fake.entered.wait(5)
    fake.on_progress(Progress(total=9, done=7, errors=7, current="a", phase="scanning", run_id=run_id))
    html = _progress(client)
    listed = re.findall(r'<li class="failure">(.*?)</li>', html, re.S)
    assert len(listed) == 5 and "app6" in listed[0]  # the newest first
    assert f'href="/scans/{run_id}/failed">see all 7 failures</a>' in html


def _css() -> str:
    return (Path(pages.__file__).parent / "static" / "app.css").read_text()


def test_number_inputs_look_like_the_text_inputs():
    # Parallel images and the retry time limit are number inputs; unstyled they are shorter, light-edged and square.
    rule = re.search(r'input\[type="text"\],\s*input\[type="search"\],\s*input\[type="number"\],\s*select \{', _css())
    assert rule


def test_start_form_controls_share_one_row_height():
    css = _css()
    controls = r'\.scan-start :is\(input:not\(\[type="checkbox"\]\), \.pill, \.btn\) \{'
    assert re.search(controls + r"[^}]*min-height: 2\.0625rem", css)
    # The Scan button lines up with the inputs, not with the hints under them.
    assert re.search(r"\.scan-start \.filter-actions \{[^}]*align-self: start", css)


def test_rescan_hint_fits_on_one_line():
    assert "off: uses the 24 h cache" in Path(pages.__file__).parent.joinpath("templates", "scans.html").read_text()


# kubedelos serve: the queue card, the next sweep and who asked for each run


def _queue_sweep(seed, at):
    conn = kubedelos.store.db.connect(seed.settings.db_path)
    try:
        queue.enqueue(conn, kind="scan", trigger="schedule", overrides={"rescan": True}, now=at)
    finally:
        conn.close()


def test_serve_scans_page_lists_the_queue_and_next_sweep(serve_client, seed):
    seed.clock.now, seed.clock.step = datetime(2026, 1, 1, 12, 0, tzinfo=UTC), timedelta(0)
    _queue_sweep(seed, datetime(2026, 1, 1, 11, 50, tzinfo=UTC))
    html = serve_client.get("/scans").text
    card = html.split('id="queue-title"', 1)[1].split("</section>", 1)[0]
    assert "schedule" in card and "10 min ago" in card
    assert "2026-01-02 03:00 UTC" in html
    assert 'action="/scans/queue/1/cancel"' in card and 'name="csrf_token"' in card


def test_serve_scans_page_with_an_empty_queue_and_sweeps_off(serve_client, sweeper):
    sweeper.next = None
    html = serve_client.get("/scans").text
    assert 'id="queue-title"' in html and "Nothing is queued" in html
    assert "sweeps are off" in html


def test_read_only_serve_scans_page_offers_no_start_form(make_serve_client):
    html = make_serve_client(read_only=True).get("/scans").text
    assert 'id="queue-title"' in html
    assert 'action="/scans"' not in html and 'name="csrf_token"' not in html


def test_serve_scans_page_offers_the_start_form_and_the_queue(serve_client):
    html = serve_client.get("/scans").text
    assert 'id="queue-title"' in html and 'action="/scans"' in html


def test_serve_history_shows_requester(serve_client, seed):
    asked = seed.repo.start_run(
        seed.context, "ui", "0.76.1", scan_level="library,os", scope=CLUSTER, requested_by="a@example.com"
    )
    swept = seed.repo.start_run(seed.context, "schedule", "0.76.1", scan_level="library,os", scope=CLUSTER)
    old = seed.repo.start_run(seed.context, "cli", "0.76.1", scan_level="library,os", scope=CLUSTER)
    for run_id in (asked, swept, old):
        seed.repo.finish_run(run_id, "ok")
    html = serve_client.get("/scans").text
    assert '<th scope="col">By</th>' in html
    by = {run_id: next(r for r in _rows(html) if f"Run {run_id}<" in r) for run_id in (asked, swept, old)}
    assert "a@example.com" in by[asked]
    assert "<td>schedule</td>" in by[swept]
    assert "<td>\N{EN DASH}</td>" in by[old]


def test_laptop_scans_page_has_no_queue(client, seed):
    _run(seed)
    html = client.get("/scans").text
    assert 'id="queue-title"' not in html and "sweep" not in html
    assert '<th scope="col">By</th>' not in html
    assert 'action="/scans"' in html


def test_read_only_serve_progress_offers_no_cancel(make_serve_client):
    serve_client = make_serve_client(read_only=True)
    serve_app = serve_client.app
    scan = FakeScan()
    runner = ScanRunner(serve_app.state.settings, "my-cluster", scan=scan, fixed_cluster=True)
    serve_app.state.scans = runner
    try:
        runner.start({}, trigger="schedule")  # as the queue worker starts a sweep
        assert scan.entered.wait(5)
        scan.on_progress(Progress(total=4, done=1, errors=0, current="reg.example.com/app:1", phase="scanning"))
        html = _progress(serve_client)
        assert "Scanning my-cluster" in html
        assert 'action="/scans/cancel"' not in html and 'name="csrf_token"' not in html
    finally:
        scan.release.set()
        runner.shutdown(timeout=5)


# kubedelos serve: UI scans and cancels go through the queue


def _requests(seed):
    conn = kubedelos.store.db.connect(seed.settings.db_path)
    try:
        return conn.execute("SELECT * FROM scan_request ORDER BY id").fetchall()
    finally:
        conn.close()


def _overrides(row):
    return json.loads(row["overrides"])


def test_serve_scan_is_queued(serve_client, seed, worker):
    response = signed_post(serve_client, "/scans", {**FORM, "namespaces": "web, api"})
    assert response.status_code == 303 and response.headers["location"] == "/scans"
    [row] = _requests(seed)
    assert (row["kind"], row["trigger"], row["state"], row["requested_by"]) == ("scan", "ui", "queued", None)
    assert _overrides(row)["namespaces"] == ["web", "api"]
    assert set(_overrides(row)) == set(scans.FIELDS) | {"rescan"}  # never a context, kubeconfig or cluster name
    assert _overrides(row)["rescan"] is False
    assert worker.woken == 1
    assert serve_client.app.state.scans.view() is None  # the runner was not started: only the worker starts it


def test_serve_scan_records_the_trusted_identity(make_serve_client, seed):
    client = make_serve_client(trust_proxy_headers=True)
    assert signed_post(client, "/scans", FORM, identity="a@example.com").status_code == 303
    [row] = _requests(seed)
    assert row["requested_by"] == "a@example.com"


def test_serve_blank_namespaces_mean_the_configured_ones(make_serve_client, seed):
    client = make_serve_client(namespaces=["web"])
    assert signed_post(client, "/scans", {**FORM, "namespaces": " "}).status_code == 303
    [row] = _requests(seed)
    assert _overrides(row)["namespaces"] == ["web"]


def test_anonymous_ui_run_shows_anonymous(serve_client, seed):
    run_id = seed.repo.start_run(seed.context, "ui", "0.76.1", scan_level="library,os", scope=CLUSTER)
    seed.repo.finish_run(run_id, "ok")
    html = serve_client.get("/scans").text
    row = next(r for r in _rows(html) if f"Run {run_id}<" in r)
    assert "<td>anonymous</td>" in row


def test_serve_queue_card_shows_who_asked(serve_client, seed):
    assert signed_post(serve_client, "/scans", FORM).status_code == 303
    card = serve_client.get("/scans").text.split('id="queue-title"', 1)[1].split("</section>", 1)[0]
    assert "<td>anonymous</td>" in card


def test_serve_same_scan_twice_says_already_queued(serve_client, seed):
    assert signed_post(serve_client, "/scans", FORM).headers["location"] == "/scans"
    response = signed_post(serve_client, "/scans", FORM)
    assert response.status_code == 303 and response.headers["location"] == "/scans?notice=queued"
    assert "already queued" in serve_client.get(response.headers["location"]).text
    assert len(_requests(seed)) == 1


def test_serve_ignores_an_unknown_notice(serve_client):
    html = serve_client.get("/scans?notice=<b>hi</b>").text
    assert "already queued" not in html and "<b>hi</b>" not in html


def test_serve_full_queue_is_409(serve_client, seed):
    for n in range(queue.MAX_QUEUED):
        assert signed_post(serve_client, "/scans", {**FORM, "namespaces": f"ns-{n}"}).status_code == 303
    response = signed_post(serve_client, "/scans", {**FORM, "namespaces": "one-more"})
    assert response.status_code == 409 and "the queue is full" in response.text
    assert len(_requests(seed)) == queue.MAX_QUEUED


def test_serve_scan_outside_scope_is_rejected(make_serve_client, seed, worker):
    client = make_serve_client(namespaces=["web"])
    response = signed_post(client, "/scans", {**FORM, "namespaces": "kube-system"})
    assert response.status_code == 400
    assert "namespace kube-system is outside the configured scope" in response.text
    assert _requests(seed) == [] and worker.woken == 0


def test_serve_cancel_queued_request(serve_client, seed):
    signed_post(serve_client, "/scans", FORM)
    [row] = _requests(seed)
    response = signed_post(serve_client, f"/scans/queue/{row['id']}/cancel", {})
    assert response.status_code == 303 and response.headers["location"] == "/scans"
    assert _requests(seed)[0]["state"] == "cancelled"


def test_serve_cancel_started_request_changes_nothing(serve_client, seed):
    signed_post(serve_client, "/scans", FORM)
    conn = kubedelos.store.db.connect(seed.settings.db_path)
    try:
        started = queue.claim_next(conn)
    finally:
        conn.close()
    response = signed_post(serve_client, f"/scans/queue/{started.id}/cancel", {})
    assert response.status_code == 303 and response.headers["location"] == "/scans"
    assert _requests(seed)[0]["state"] == "started"


def test_serve_cancel_of_an_unknown_request_goes_back(serve_client):
    assert signed_post(serve_client, "/scans/queue/99/cancel", {}).headers["location"] == "/scans"
    assert signed_post(serve_client, "/scans/queue/0/cancel", {}).status_code == 400


def test_read_only_queue_card_has_no_cancel(make_serve_client, seed):
    _queue_sweep(seed, datetime(2026, 1, 1, 11, 50, tzinfo=UTC))
    html = make_serve_client(read_only=True).get("/scans").text
    card = html.split('id="queue-title"', 1)[1].split("</section>", 1)[0]
    assert "schedule" in card and "/cancel" not in card and "<button" not in card


def test_laptop_scan_still_starts_the_runner(client, fake, seed):
    assert _start(client).status_code == 303
    assert fake.entered.wait(5) and len(fake.calls) == 1
    assert _requests(seed) == []


def test_laptop_has_no_queue_cancel(client, seed):
    response = client.post("/scans/queue/1/cancel", data={"csrf_token": _csrf(client)}, headers=ORIGIN)
    assert response.status_code == 404


def test_serve_busy_database_is_503(serve_client, worker, monkeypatch):
    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(queue, "enqueue", locked)
    response = signed_post(serve_client, "/scans", FORM)
    assert response.status_code == 503 and "the database is busy" in response.text
    assert worker.woken == 0


def test_serve_cancel_with_a_busy_database_is_503(serve_client, monkeypatch):
    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(queue, "cancel", locked)
    response = signed_post(serve_client, "/scans/queue/1/cancel", {})
    assert response.status_code == 503 and "the database is busy" in response.text


def test_history_says_why_a_run_failed(client, seed):
    empty = _run(seed, "failed")
    seed.repo.add_warnings(
        empty, [InventoryWarning("no namespace matched the scope; nothing was scanned", coverage=False)]
    )
    plain = _run(seed, "failed")
    rows = _rows(client.get("/scans").text)
    row = next(r for r in rows if f"Run {empty}<" in r)
    assert '<div class="hint">no namespace matched the scope; nothing was scanned</div>' in row
    assert 'class="hint"' not in next(r for r in rows if f"Run {plain}<" in r)
