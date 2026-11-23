import re
from html import unescape

from kubedelos.config import Settings
from kubedelos.models import ImageRef, ImageResult, InventoryItem

CLUSTER = Settings().scope


def _run(seed, status="ok", context=None):
    context = context or seed.context
    run_id = seed.repo.start_run(context, context, "ui", "0.76.1", scan_level="library,os", scope=CLUSTER)
    if status != "running":
        seed.repo.finish_run(run_id, status)
    return run_id


def _put(seed, run_id, ref, seconds, *, status="ok", kind=None, digest=None):
    name, tag = ref.rsplit(":", 1)
    image = ImageRef(ref=ref, repo=name, tag=tag, digest=digest)
    item = InventoryItem(image=image, platform="linux/amd64", workloads=[])
    result = ImageResult(image=image, platform="linux/amd64", status=status, error_kind=kind, duration_s=seconds)
    seed.repo.add_result(run_id, item, result)


def _rows(html):
    body = html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    return re.findall(r"<tr>(.*?)</tr>", body, re.S)


def test_lists_the_slowest_images_with_a_summary(client, seed):
    run_id = _run(seed, "partial")
    _put(seed, run_id, "reg.example.com/small:1", 42.0)
    _put(seed, run_id, "reg.example.com/big:1", 630.0, status="error", kind="timeout")
    _put(seed, run_id, "reg.example.com/cached:1", None, status="cached")
    html = unescape(client.get(f"/scans/{run_id}/times").text)
    assert "Scan times of run 1" in html
    rows = _rows(html)
    assert len(rows) == 2
    assert "reg.example.com/big:1" in rows[0] and "10 min 30 s" in rows[0] and "timeout" in rows[0]
    assert "reg.example.com/small:1" in rows[1] and "42 s" in rows[1] and "ok" in rows[1]
    summary = html.split('<ul class="chips times-summary">', 1)[1].split("</ul>", 1)[0]
    assert "2 images scanned" in summary and "1 cached" in summary and "longest 10 min 30 s" in summary
    assert "11 min 12 s of scanning" in summary


def test_says_when_a_run_has_no_times(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "reg.example.com/a:1", None)
    html = client.get(f"/scans/{run_id}/times").text
    assert "No scan times for run 1" in html and "<tbody>" not in html


def test_only_runs_of_the_shown_context(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    theirs = _run(seed, context="prod-eu")
    assert client.get(f"/scans/{theirs}/times").status_code == 404
    assert client.get(f"/scans/{theirs}/times", params={"context": "prod-eu"}).status_code == 200
    assert client.get("/scans/999/times").status_code == 404


def test_history_links_each_finished_run_to_its_times(client, seed):
    done = _run(seed)
    running = _run(seed, "running")
    history = client.get("/scans").text
    assert f'href="/scans/{done}/times"' in history
    assert f'href="/scans/{running}/times"' not in history


def test_failures_page_shows_how_long_each_failure_took(client, seed):
    run_id = _run(seed, "partial")
    _put(seed, run_id, "reg.example.com/big:1", 630.0, status="error", kind="timeout")
    html = client.get(f"/scans/{run_id}/failed").text
    assert '<th scope="col">Time</th>' in html
    row = html.split("<tbody>", 1)[1].split("</tr>", 1)[0]
    assert '<td class="num">10 min 30 s</td>' in row
    assert f'href="/scans/{run_id}/times"' in html
