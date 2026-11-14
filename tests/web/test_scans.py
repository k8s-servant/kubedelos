import contextlib
import re
from datetime import UTC, datetime, timedelta
from html import unescape

import pytest

import kubedelos.store.db
from kubedelos.config import Settings
from kubedelos.models import ImageRef, ImageResult, InventoryItem, Workload
from kubedelos.store import runlock
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
    assert "saved: web" in form and "saved: app=x" in form and "saved: os" in form
    token = re.search(r'name="csrf_token" value="([^"]+)"', form)
    assert token and token.group(1)


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


@pytest.mark.parametrize("seconds, text", [(0, "0 min 0 s"), (59, "0 min 59 s"), (3725, "62 min 5 s")])
def test_duration_text(seconds, text):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    assert scans.duration_text(start, start + timedelta(seconds=seconds)) == text
    assert scans.duration_text(start, None) == "—"
