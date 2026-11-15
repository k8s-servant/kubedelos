"""Tests for the scans page: the history, the start form, starting and cancelling a scan, and the progress fragment."""

import contextlib
import itertools
import re
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from html import unescape

import pytest

import kubedelos.store.db
from kubedelos.config import Settings
from kubedelos.models import ImageRef, ImageResult, InventoryItem, Workload
from kubedelos.scan.service import Progress, ScanOutcome
from kubedelos.store import runlock
from kubedelos.web import pages
from kubedelos.web.jobs import ScanRunner
from kubedelos.web.routes import scans

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
    assert re.search(r"<td[^>]*>2</td>\s*<td[^>]*>1</td>", by_id["partial"])  # 2 images, 1 failed
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

    def __call__(self, settings, **kw):
        self.calls.append({"settings": settings, **kw})
        self.on_progress = kw["on_progress"]
        self.entered.set()
        while not self.release.wait(0.01):
            if kw["cancel"].is_set():
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


def _progress(client):
    response = client.get("/scans/progress")
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
    assert f'<script src="/static/htmx.min.js" nonce="{nonce}"' in response.text
    assert response.text.count("<script") == 1
    assert client.get("/static/htmx.min.js").status_code == 200
    for path in ("/", "/findings"):
        assert "<script" not in client.get(path).text, path


def test_no_inline_style_or_eval_config(client, fake):
    html = client.get("/scans").text
    assert HTMX_CONFIG in html
    assert html.index(HTMX_CONFIG) < html.index('<script src="/static/htmx.min.js"')  # read when htmx loads
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
