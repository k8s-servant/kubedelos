import re

from kubedelos.config import Settings
from kubedelos.models import ImageRef, ImageResult, InventoryItem, Workload
from kubedelos.trivy.runner import RETRIED_PREFIX

CLUSTER = Settings().scope
EOF_ERROR = "2026-11-16T09:15:44+02:00\tFATAL\tFatal error\trun error: failed to extract the archive: unexpected EOF"
AUTH_ERROR = "2026-11-16T09:15:44+02:00\tFATAL\tFatal error\tGET https://reg.example.com/v2/: UNAUTHORIZED: login"


def _run(seed, status="ok", context=None):
    run_id = seed.repo.start_run(context or seed.context, "ui", "0.76.1", scan_level="library,os", scope=CLUSTER)
    if status != "running":
        seed.repo.finish_run(run_id, status)
    return run_id


def _put(seed, run_id, ref, namespaces=("web",), *, kind=None, error=None, platform="linux/amd64"):
    image = ImageRef(ref=ref, repo=ref.split(":")[0], tag="1", digest=None)
    item = InventoryItem(
        image=image,
        platform=platform,
        workloads=[Workload(namespace=ns, kind="Deployment", name="w", container="c") for ns in namespaces],
    )
    status = "error" if kind else "ok"
    result = ImageResult(image=image, platform=platform, status=status, error_kind=kind, error=error, findings=[])
    seed.repo.add_result(run_id, item, result)


def _rows(html):
    body = html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    return re.findall(r"<tr>(.*?)</tr>", body, re.S)


def test_lists_every_failure_of_the_run_with_its_cause(client, seed):
    run_id = _run(seed, "partial")
    _put(seed, run_id, "reg.example.com/ok:1")
    _put(seed, run_id, "reg.example.com/b:1", ["web", "api"], kind="trivy", error=RETRIED_PREFIX + EOF_ERROR)
    _put(seed, run_id, "reg.example.com/a:1", kind="auth", error=AUTH_ERROR)
    html = client.get(f"/scans/{run_id}/failed").text
    rows = _rows(html)
    assert len(rows) == 2
    assert "reg.example.com/a:1" in rows[0] and "auth" in rows[0]  # by ref
    b = rows[1]
    assert "failed to extract the archive: unexpected EOF" in b and "api, web" in b
    assert "retried" in b and "<details>" in b
    assert "2 images failed to scan in run 1" in html
    assert "reg.example.com" in html.split("<tbody>")[0]  # the login hint names the registry


def test_any_status_of_the_shown_context_and_no_other(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    running = _run(seed, "running")
    _put(seed, running, "reg.example.com/a:1", kind="trivy", error=EOF_ERROR)
    assert len(_rows(client.get(f"/scans/{running}/failed").text)) == 1
    cancelled = _run(seed, "cancelled")
    assert "No image failed" in client.get(f"/scans/{cancelled}/failed").text
    theirs = _run(seed, context="prod-eu")
    assert client.get(f"/scans/{theirs}/failed").status_code == 404
    assert client.get(f"/scans/{theirs}/failed", params={"context": "prod-eu"}).status_code == 200
    assert client.get("/scans/999/failed").status_code == 404


def test_pages_through_many_failures(client, seed):
    run_id = _run(seed, "partial")
    for i in range(105):
        _put(seed, run_id, f"reg.example.com/app{i:03}:1", kind="trivy", error=EOF_ERROR)
    first = client.get(f"/scans/{run_id}/failed").text
    assert len(_rows(first)) == 100 and f'href="/scans/{run_id}/failed?page=2"' in first
    assert len(_rows(client.get(f"/scans/{run_id}/failed", params={"page": 2}).text)) == 5


def test_history_and_dashboard_link_to_the_failures(client, seed):
    run_id = _run(seed, "partial")
    _put(seed, run_id, "reg.example.com/ok:1")
    for i in range(30):
        _put(seed, run_id, f"reg.example.com/app{i:02}:1", kind="trivy", error=EOF_ERROR)
    history = client.get("/scans").text
    assert f'<a href="/scans/{run_id}/failed">30</a>' in history
    dashboard = client.get("/").text
    assert f'href="/scans/{run_id}/failed">see all 30</a>' in dashboard


def test_hostile_error_text_is_escaped(client, seed):
    run_id = _run(seed, "partial")
    _put(seed, run_id, "reg.example.com/a:1", kind="trivy", error="<script>alert(1)</script>")
    html = client.get(f"/scans/{run_id}/failed").text
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
