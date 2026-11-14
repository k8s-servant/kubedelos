import time
from datetime import datetime, timedelta

from kubedelos.config import Settings
from kubedelos.kube.inventory import InventoryWarning
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.store.db import connect

CLUSTER = Settings().scope


def _run(seed, *, scope=CLUSTER, level="library,os", status="ok", context=None):
    run_id = seed.repo.start_run(context or seed.context, "cli", "0.76.1", scan_level=level, scope=scope)
    seed.repo.finish_run(run_id, status)
    return run_id


def _add(seed, run_id, ref, severities=(), *, status="ok", platform="linux/amd64"):
    image = ImageRef(ref=ref, repo="reg.example.com/app", tag="1", digest="sha256:" + "a" * 64)
    item = InventoryItem(
        image=image, platform=platform, workloads=[Workload(namespace="ns", kind="Deployment", name="a", container="c")]
    )
    findings = [
        Finding(
            vuln_id=f"CVE-{ref}-{i}",
            pkg_name="p",
            installed_version="1",
            severity=Severity(sev),
            target="t",
            pkg_type="os",
        )
        for i, sev in enumerate(severities)
    ]
    seed.repo.add_result(run_id, item, ImageResult(image=image, platform=platform, status=status, findings=findings))


def _tile(html, label):
    start = html.index(f'data-tile="{label}"')
    return html[start : html.index("</li>", start)]


def test_no_runs_empty_state(client):
    html = client.get("/").text
    assert "No scans of" in html and "my-cluster" in html and "kubedelos scan" in html


def test_only_narrower_runs(client, seed):
    _run(seed, scope=Settings(namespaces=["web"]).scope)
    html = client.get("/").text
    assert "no cluster-wide run" in html
    assert "/findings?run_id=1" in html


def test_uses_newest_cluster_run_and_mentions_newer_narrower(client, seed):
    _run(seed)
    _run(seed, scope=Settings(namespaces=["web"]).scope)
    html = client.get("/").text
    assert "Run 1 " in html
    assert "a newer run of namespace web exists" in html
    assert "/findings?run_id=2" in html


def test_pinned_run_and_404_reasons(client, seed):
    _run(seed)
    _run(seed, scope=Settings(namespaces=["web"]).scope)
    other = _run(seed, context="elsewhere")
    failed = _run(seed, status="failed")
    pinned = client.get("/?run_id=2")
    assert pinned.status_code == 200 and "pinned" in pinned.text
    assert "a newer run" not in pinned.text
    assert "Run 2 " in pinned.text
    foreign = client.get(f"/?run_id={other}")
    assert foreign.status_code == 404 and "belongs to context elsewhere" in foreign.text
    bad = client.get(f"/?run_id={failed}")
    assert bad.status_code == 404 and "is failed" in bad.text
    missing = client.get("/?run_id=99")
    assert missing.status_code == 404 and "no run 99" in missing.text
    assert client.get("/?run_id=abc").status_code == 400
    assert client.get("/?run_id=0").status_code == 400


def test_run_line_stale_and_scope_text(client, seed):
    run_id = _run(seed, scope=Settings(exclude_images=["busybox:*"]).scope)
    _add(seed, run_id, "a")
    _add(seed, run_id, "b", status="error")
    finished = seed.repo.get_run(run_id)["finished_at"]
    seed.clock.now = datetime.fromisoformat(finished) + timedelta(hours=25)
    html = client.get("/").text
    assert "stale" in html
    assert "whole cluster, excluding images busybox:*" in html
    assert "os + library packages" in html
    assert "2 images, 1 failed" in html
    assert "25 h ago" in html


def test_fresh_run_is_not_stale(client, seed):
    _run(seed)
    assert "badge-stale" not in client.get("/").text


def test_gaps_mark_incomplete(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["CRITICAL"], status="ok")
    seed.repo.add_warnings(run_id, [InventoryWarning("namespace secret-ns: forbidden", coverage=True)])
    html = client.get("/").text
    assert "incomplete: 1 namespaces or resources could not be listed" in html
    assert "namespace secret-ns: forbidden" in html
    assert "<details" in html
    for label in ("critical", "high", "images-critical", "findings"):
        assert "⚠" in _tile(html, label)


def test_no_gaps_no_caution(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["CRITICAL"])
    html = client.get("/").text
    assert "incomplete" not in html and "⚠" not in html


def test_kpi_deltas_against_previous_comparable(client, seed):
    first = _run(seed)
    for i in range(3):
        _add(seed, first, f"a{i}", ["CRITICAL"])
    other_scope = _run(seed, scope=Settings(namespaces=["web"]).scope)
    for i in range(9):
        _add(seed, other_scope, f"w{i}", ["CRITICAL"])
    last = _run(seed)
    for i in range(5):
        _add(seed, last, f"b{i}", ["CRITICAL"])
    html = client.get("/").text
    tile = _tile(html, "critical")
    assert "+2" in tile and "no earlier comparable run" not in tile


def test_delta_signs(client, seed):
    first = _run(seed)
    for i in range(3):
        _add(seed, first, f"a{i}", ["HIGH"])
    last = _run(seed)
    _add(seed, last, "a0", ["HIGH"])
    html = client.get("/").text
    assert "\N{MINUS SIGN}2" in _tile(html, "high")
    assert "±0" in _tile(html, "critical")


def test_delta_caution_when_either_run_failed(client, seed):
    first = _run(seed)
    _add(seed, first, "a", ["CRITICAL"], status="error")
    last = _run(seed)
    _add(seed, last, "a", ["CRITICAL"])
    tile = _tile(client.get("/").text, "critical")
    assert "either run had failed images or skipped namespaces" in tile


def test_no_comparable_run_text(client, seed):
    _add(seed, _run(seed), "a", ["CRITICAL"])
    assert "no earlier comparable run" in _tile(client.get("/").text, "critical")


def test_failed_tile_only_when_failures(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a")
    assert 'data-tile="failed"' not in client.get("/").text
    _add(seed, run_id, "b", status="error")
    html = client.get("/").text
    assert 'data-tile="failed"' in html
    assert "1" in _tile(html, "failed")


def test_images_with_critical_tile(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["CRITICAL", "LOW"])
    _add(seed, run_id, "b", ["LOW"])
    tile = _tile(client.get("/").text, "images-critical")
    assert "1" in tile and "of 2" in tile


def test_bricks_link_and_unknown_hidden_when_zero(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["CRITICAL", "LOW"])
    html = client.get("/").text
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert f"/findings?run_id={run_id}&amp;severity={sev}" in html
    assert "severity=UNKNOWN" not in html
    _add(seed, run_id, "b", ["UNKNOWN"])
    assert "severity=UNKNOWN" in client.get("/").text


def test_zero_findings_with_failures_is_not_called_clean(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a")
    _add(seed, run_id, "b", status="error")
    html = client.get("/").text
    assert "No vulnerabilities found" not in html


def test_zero_findings_clean_message(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a")
    assert "No vulnerabilities found in 1 images." in client.get("/").text


def test_page_renders_while_a_scan_is_writing(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["HIGH"])
    writer = connect(seed.settings.db_path)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "INSERT INTO scan_run (started_at, status, context, trigger, trivy_version) VALUES"
            " ('2026-01-02T00:00:00+00:00', 'running', 'my-cluster', 'cli', '0.76.1')"
        )
        start = time.monotonic()
        response = client.get("/")
        assert time.monotonic() - start < 2
        assert response.status_code == 200
        assert f"Run {run_id} " in response.text
    finally:
        writer.rollback()
        writer.close()
