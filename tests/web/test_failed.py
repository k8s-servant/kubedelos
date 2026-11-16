import re
import threading

import pytest

from kubedelos.config import Settings
from kubedelos.hints import login_hint
from kubedelos.models import ImageRef, ImageResult, InventoryItem, Workload
from kubedelos.scan.service import ScanOutcome
from kubedelos.trivy.runner import RETRIED_PREFIX
from kubedelos.web.jobs import ScanRunner

CLUSTER = Settings().scope
ORIGIN = {"origin": "http://127.0.0.1:9370"}
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
    assert f"hint: {login_hint('reg.example.com')}" in html.split("<tbody>")[0]  # the registry's login hint


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


class FakeRetry:
    """A stand-in for ``retry_failed`` that blocks until released, so a test can look at the running job."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.entered = threading.Event()
        self.calls: list[dict] = []

    def __call__(self, settings, **kw):
        self.calls.append({"settings": settings, **kw})
        self.entered.set()
        self.release.wait(5)
        return ScanOutcome(run_id=kw["run_id"], warnings=[], status="ok")


@pytest.fixture
def retry(app):
    fake = FakeRetry()
    runner = ScanRunner(app.state.settings, app.state.context, scan=FakeRetry(), retry=fake)
    app.state.scans = runner
    yield fake
    fake.release.set()
    runner.shutdown(timeout=5)


def _retryable(seed, context=None):
    run_id = _run(seed, "partial", context=context)
    _put(seed, run_id, "reg.example.com/ok:1")
    _put(seed, run_id, "reg.example.com/a:1", kind="timeout", error="context deadline exceeded")
    return run_id


def _form(html):
    return html.split('<form method="post" action="/scans/', 1)[1].split("</form>", 1)[0]


def _csrf(client) -> str:
    guard = client.app.state.guard
    return guard.csrf_token(client.cookies[guard.cookie_name])


def _retry(client, run_id, **fields):
    data = {"timeout": "1800", "parallelism": "2", "csrf_token": _csrf(client), **fields}
    return client.post(f"/scans/{run_id}/retry", data=data, headers=ORIGIN, follow_redirects=False)


def test_the_newest_partial_run_offers_a_retry_with_longer_limits(client, seed):
    run_id = _retryable(seed)
    form = _form(client.get(f"/scans/{run_id}/failed").text)
    assert form.startswith(f'{run_id}/retry"')
    assert re.search(r'name="timeout"[^>]*value="1800"', form)  # 3x the 600 s setting
    assert re.search(r'name="parallelism"[^>]*value="2"', form)
    assert 'name="csrf_token"' in form and "Retry 1 failed image" in form


@pytest.mark.parametrize("which", ["older", "ok", "running"])
def test_no_retry_form_where_a_retry_is_not_allowed(client, seed, which):
    run_id = _retryable(seed)
    if which == "older":
        _run(seed, "ok")
    elif which != "ok":
        seed.repo._conn.execute("UPDATE scan_run SET status = ? WHERE id = ?", (which, run_id))
        seed.repo._conn.commit()
    else:
        seed.repo.finish_run(run_id, "ok")
    assert 'action="/scans/' not in client.get(f"/scans/{run_id}/failed").text


def test_retry_requires_csrf(client, seed, retry):
    run_id = _retryable(seed)
    response = client.post(f"/scans/{run_id}/retry", data={"timeout": "1800"}, headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 403 and retry.calls == []


def test_retry_starts_with_the_form_limits(client, app, seed, retry):
    run_id = _retryable(seed)
    response = _retry(client, run_id, timeout=" 2400 ", parallelism="3")
    assert response.status_code == 303 and response.headers["location"] == "/scans"
    assert retry.entered.wait(5)
    call = retry.calls[0]
    assert call["run_id"] == run_id
    assert (call["settings"].scan_timeout_s, call["settings"].parallelism) == (2400, 3)
    assert call["settings"].context == app.state.context
    progress = client.get("/scans/progress").text
    assert "Retrying failed images of run 1" in progress


def test_retry_of_another_contexts_run_goes_back_to_that_context(client, seed, retry, kube_contexts):
    kube_contexts.append("prod-eu")
    run_id = _retryable(seed, context="prod-eu")
    assert _retry(client, run_id).status_code == 404
    response = _retry(client, run_id, context="prod-eu")
    assert response.status_code == 303 and response.headers["location"] == "/scans?context=prod-eu"
    assert retry.entered.wait(5) and retry.calls[0]["settings"].context == "prod-eu"


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"timeout": "59"}, "Time limit: must be between 60 and 3600 seconds"),
        ({"timeout": "3601"}, "Time limit: must be between 60 and 3600 seconds"),
        ({"timeout": "soon"}, "Time limit: must be between 60 and 3600 seconds"),
        ({"parallelism": "0"}, "Parallel images:"),
    ],
)
def test_retry_with_bad_limits_rerenders_with_400(client, seed, retry, fields, message):
    run_id = _retryable(seed)
    response = _retry(client, run_id, **fields)
    assert response.status_code == 400 and message in response.text
    assert retry.calls == []


def test_retry_of_a_run_that_is_not_retryable_is_refused(client, seed, retry):
    run_id = _retryable(seed)
    _run(seed, "ok")
    response = _retry(client, run_id)
    assert response.status_code == 409 and "only the newest run of my-cluster can be retried" in response.text
    clean = _run(seed, "partial")
    response = _retry(client, clean)
    assert response.status_code == 409 and "run 3 has no failed images" in response.text
    assert retry.calls == []


def test_retry_while_a_scan_runs_is_refused(client, seed, retry):
    run_id = _retryable(seed)
    assert _retry(client, run_id).status_code == 303
    assert retry.entered.wait(5)
    response = _retry(client, run_id)
    assert response.status_code == 409 and "a scan is already running" in response.text


def test_failures_page_shows_the_retry_notes(client, seed):
    run_id = _retryable(seed)
    seed.repo.settle_retry(run_id, retried=1)
    html = client.get(f"/scans/{run_id}/failed").text
    assert re.search(r"retried 1 failed image at \d\d:\d\d UTC: 0 scanned, 1 still failing", html)


def test_history_offers_retry_on_the_newest_partial_run_only(client, seed):
    older = _retryable(seed)
    newest = _retryable(seed)
    history = client.get("/scans").text
    assert f'href="/scans/{newest}/failed#retry">retry</a>' in history
    assert f'href="/scans/{older}/failed#retry"' not in history
