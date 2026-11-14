import re
import time
from datetime import datetime, timedelta
from html import unescape
from pathlib import Path

import kubedelos.web
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


def _chips(html):
    start = html.index('<ul class="chips">')
    return html[start : html.index("</ul>", start)]


def _sidebar(html):
    start = html.index('<aside class="sidebar"')
    return html[start : html.index("</aside>", start)]


def _tile(html, label):
    start = html.index(f'data-tile="{label}"')
    return html[start : html.index("</li>", start)]


def _between(html, opener, closer):
    start = html.index(opener)
    return html[start : html.index(closer, start)]


def _hex_luminance(color):
    channels = [int(color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(a, b):
    high, low = sorted((_hex_luminance(a), _hex_luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _theme_tokens(css, block_start):
    start = css.index(block_start)
    block = css[start : css.index("}", start)]
    return dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-f]{6});", block))


def test_no_runs_empty_state(client):
    html = client.get("/").text
    assert "No scans of" in html and "my-cluster" in html and "kubedelos scan" in html


def test_only_narrower_runs(client, seed):
    _run(seed, scope=Settings(namespaces=["web"]).scope)
    html = client.get("/").text
    assert "no cluster-wide run" in html
    assert "/findings?run_id=1" in html
    sidebar = _sidebar(html)
    assert "no cluster-wide scan yet" in sidebar and "no scans yet" not in sidebar


def test_uses_newest_cluster_run_and_mentions_newer_narrower(client, seed):
    _run(seed)
    _run(seed, scope=Settings(namespaces=["web"]).scope)
    html = client.get("/").text
    assert '<li class="chip">Run 1</li>' in html
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
    assert '<li class="chip">Run 2</li>' in pinned.text
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
    assert "2 images · 1 failed" in html
    assert "25 h ago" in html


def test_fresh_run_is_not_stale(client, seed):
    _run(seed)
    assert "chip-stale" not in client.get("/").text


def test_sidebar_freshness_dot(client, seed):
    _run(seed)
    finished = datetime.fromisoformat(seed.repo.get_run(1)["finished_at"])
    seed.clock.now = finished + timedelta(minutes=5) - timedelta(minutes=1)  # the clock ticks a minute per call
    fresh = client.get("/").text
    sidebar = _sidebar(fresh)
    assert '<span class="fresh">scanned 5 min ago</span>' in sidebar
    seed.clock.now = finished + timedelta(hours=30) - timedelta(minutes=1)
    stale = client.get("/").text
    assert '<span class="stale">scanned 30 h ago</span>' in _sidebar(stale)
    assert "connected" not in fresh and "connected" not in stale


def test_sidebar_without_a_run_says_no_scans_yet(client):
    assert "no scans yet" in _sidebar(client.get("/").text)


def test_run_chips(client, seed):
    clean = _run(seed)
    for i in range(8):
        _add(seed, clean, f"a{i}")
    chips = _chips(client.get(f"/?run_id={clean}").text)
    assert '<li class="chip">Run 1</li>' in chips
    assert "whole cluster" in chips
    assert "os + library packages" in chips
    assert "finished " in chips and "ago" in chips
    assert '<li class="chip chip-ok">8 images · 0 failed</li>' in chips
    assert '<li class="chip chip-pinned">pinned</li>' in chips
    broken = _run(seed)
    _add(seed, broken, "b", status="error")
    chips = _chips(client.get("/").text)
    assert '<li class="chip chip-bad">1 image · 1 failed</li>' in chips
    assert "chip-ok" not in chips and "pinned" not in chips


def test_run_line_unknown_finish_time(client, seed):
    run_id = _run(seed)
    writer = connect(seed.settings.db_path)
    with writer:
        writer.execute("UPDATE scan_run SET finished_at = NULL WHERE id = ?", (run_id,))
    writer.close()
    response = client.get(f"/?run_id={run_id}")
    assert response.status_code == 200
    assert "finished at an unknown time" in _chips(response.text)
    assert '<span class="stale">scanned at an unknown time</span>' in _sidebar(response.text)


def test_page_title_shows_without_a_run(client):
    html = client.get("/").text
    assert '<div class="page-head">' in html and "<h1>Dashboard</h1>" in html
    assert '<ul class="chips">' not in html


def test_page_head_and_chips_sit_inside_main(client, seed):
    _run(seed)
    html = client.get("/").text
    before, main = html.split("<main", 1)
    assert "<h1>" not in before and '<ul class="chips">' not in before
    assert "<h1>Dashboard</h1>" in main and '<ul class="chips">' in main


def test_gaps_mark_incomplete(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["CRITICAL"], status="ok")
    seed.repo.add_warnings(run_id, [InventoryWarning("namespace secret-ns: forbidden", coverage=True)])
    html = client.get("/").text
    assert "incomplete: 1 namespace or resource could not be listed" in html
    assert "namespace secret-ns: forbidden" in html
    assert '<details class="callout">' in html
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
    assert "1" in tile and "of 2 images scanned" in tile


def test_images_with_critical_tile_counts_only_images_that_scanned(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["CRITICAL"])
    _add(seed, run_id, "b", status="error")
    assert "of 1 image scanned" in _tile(client.get("/").text, "images-critical")


def test_severity_legend_links_and_unknown_hidden_when_zero(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["CRITICAL", "LOW"])
    html = client.get("/").text
    legend = _between(html, '<ul class="legend">', "</ul>")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert f"/findings?run_id={run_id}&amp;severity={sev}" in html
        assert f">{sev.title()}</span>" in legend
    assert "severity=UNKNOWN" not in html
    _add(seed, run_id, "b", ["UNKNOWN"])
    html = client.get("/").text
    assert "severity=UNKNOWN" in html
    assert ">Unknown</span>" in _between(html, '<ul class="legend">', "</ul>")


def test_severity_bar_geometry(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["CRITICAL", "LOW", "LOW", "LOW"])
    bar = _between(_tile(client.get("/").text, "findings"), '<svg class="sevbar"', "</svg>")
    assert 'viewBox="0 0 100 10"' in bar and 'preserveAspectRatio="none"' in bar and 'role="img"' in bar
    label = re.search(r'aria-label="([^"]*)"', bar).group(1)
    for words in ("1 Critical", "0 High", "0 Medium", "3 Low"):
        assert words in label
    rects = re.findall(r"<rect [^>]*>", bar)
    assert len(rects) == 2
    assert 'class="sev-critical"' in rects[0] and 'x="0"' in rects[0] and 'width="25.0"' in rects[0]
    assert 'class="sev-low"' in rects[1] and 'x="25.0"' in rects[1] and 'width="75.0"' in rects[1]
    assert "sev-high" not in bar and "sev-medium" not in bar
    assert "style=" not in bar


def test_worst_images_panel(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "reg.example.com/b:1", ["HIGH", "LOW"])
    _add(seed, run_id, "reg.example.com/a:1", ["CRITICAL", "HIGH", "HIGH"])
    html = client.get("/").text
    assert "Worst images" in html
    panel = _between(html, '<ul class="worst">', "</ul>")
    assert panel.index("reg.example.com/a:1") < panel.index("reg.example.com/b:1")
    assert "1 Critical · 2 High" in panel and "0 Critical · 1 High" in panel
    rects = re.findall(r'<rect class="(sev-[a-z]+)" x="([0-9.]+)" y="0" width="([0-9.]+)"', panel)
    assert rects == [("sev-critical", "0", "33.3"), ("sev-high", "33.3", "66.7"), ("sev-high", "0", "33.3")]
    assert "Gradient" not in html and "url(#" not in html
    assert f'href="/findings?run_id={run_id}&amp;q=reg.example.com%2Fa%3A1"' in panel
    assert f'href="/findings?run_id={run_id}&amp;q=reg.example.com%2Fb%3A1"' in panel
    assert 'viewBox="0 0 100 6"' in panel and "style=" not in panel


def test_worst_images_shows_a_short_digest(client, seed):
    run_id = _run(seed)
    ref = "reg.example.com/app@sha256:" + "c" * 64
    _add(seed, run_id, ref, ["CRITICAL"])
    panel = _between(client.get("/").text, '<ul class="worst">', "</ul>")
    assert ">app@sha256:cccccccc<" in panel
    assert f'title="{ref}"' in panel


def test_worst_images_hidden_without_critical_or_high(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["MEDIUM", "LOW"])
    assert "Worst images" not in client.get("/").text


def test_unknown_word_is_readable_in_both_themes():
    css = (Path(kubedelos.web.__file__).parent / "static" / "app.css").read_text()
    for block in (":root {", "@media (prefers-color-scheme: light)"):
        tokens = _theme_tokens(css, block)
        for name in ("critical", "high", "medium", "low", "unknown-text", "ok"):
            assert _contrast(tokens[name], tokens["card"]) >= 4.5, (block, name)
    assert re.search(r"\.sev-unknown \{[^}]*color: var\(--unknown-text\);[^}]*fill: var\(--unknown\);", css)


def test_zero_findings_with_failures_is_not_called_clean(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a")
    _add(seed, run_id, "b", status="error")
    html = client.get("/").text
    assert "No vulnerabilities found in 2 images." not in html


def test_zero_findings_clean_vs_broken(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a")
    assert "No vulnerabilities found in 1 image." in client.get("/").text
    _add(seed, run_id, "b", status="error")
    html = client.get("/").text
    assert "No vulnerabilities found in the 1 image that scanned; 1 failed to scan." in html
    assert "No vulnerabilities found in 2 images." not in html


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
        assert f'<li class="chip">Run {run_id}</li>' in response.text
    finally:
        writer.rollback()
        writer.close()


def test_zero_findings_with_gaps_is_not_called_clean(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a")
    seed.repo.add_warnings(run_id, [InventoryWarning("namespace x: forbidden", coverage=True)])
    html = client.get("/").text
    assert "No vulnerabilities found in the 1 image that could be listed; 1 namespace or resource could not be" in html
    assert "No vulnerabilities found in 1 image." not in html


def _add_fix(
    seed, run_id, ref, vuln, severity="CRITICAL", *, pkg="openssl", fixed="1.2", url=None, ns="web", installed="1.1"
):
    image = ImageRef(ref=ref, repo="reg.example.com/app", tag="1", digest="sha256:" + "a" * 64)
    item = InventoryItem(
        image=image,
        platform="linux/amd64",
        workloads=[Workload(namespace=ns, kind="Deployment", name="a", container="c")],
    )
    finding = Finding(
        vuln_id=vuln,
        pkg_name=pkg,
        installed_version=installed,
        fixed_version=fixed,
        severity=Severity(severity),
        primary_url=url,
        target="os",
        pkg_type="os",
    )
    result = ImageResult(image=image, platform="linux/amd64", status="ok", findings=[finding])
    seed.repo.add_result(run_id, item, result)


def test_fix_list_default_and_by_image(client, seed):
    run_id = _run(seed)
    _add_fix(seed, run_id, "reg.example.com/app:1", "CVE-9", url="https://example.com/CVE-9")
    _add_fix(seed, run_id, "reg.example.com/app:2", "CVE-8", "HIGH", fixed=None)
    html = client.get("/").text
    assert 'data-fix="CVE-9"' in html and "1.1" in html and "1.2" in html
    assert 'href="https://example.com/CVE-9"' in html and 'rel="noopener noreferrer"' in html
    assert "1 Critical/High finding has no released fix yet, across 1 image" in html
    assert "/findings?run_id=1&severity=CRITICAL&severity=HIGH&has_fix=no" in unescape(html)
    by_image = client.get("/?by=image").text
    assert 'data-image="reg.example.com/app:1"' in by_image and 'data-fix="CVE-9"' not in by_image
    assert 'data-image="reg.example.com/app:2"' not in by_image
    assert client.get("/?by=bogus").status_code == 400


def test_fix_row_installed_shows_first_plus_n(client, seed):
    run_id = _run(seed)
    for i, version in enumerate(("1.2", "1.0", "1.1")):
        _add_fix(seed, run_id, f"img{i}", "CVE-9", fixed="2.0", installed=version)
    row = _between(client.get("/").text, 'data-fix="CVE-9"', "</details>")
    assert 'title="1.0, 1.1, 1.2"' in row
    installed = _between(row, 'title="1.0, 1.1, 1.2"', "</span></span>")
    assert ">1.0 <" in installed and "+2" in installed
    assert '<span class="fixed"><span class="v">2.0</span></span>' in row
    assert '<span class="sev sev-critical">Critical</span>' in row


def test_fix_list_unsafe_url_is_not_linked(client, seed):
    run_id = _run(seed)
    _add_fix(seed, run_id, "a", "CVE-9", url="javascript:alert(1)")
    html = client.get("/").text
    assert "javascript:" not in html and "CVE-9" in html


def test_fix_list_overflow_and_more_links(client, seed):
    run_id = _run(seed)
    for i in range(30):
        _add_fix(seed, run_id, f"img{i:02d}", "CVE-9")
        _add_fix(seed, run_id, f"img{i:02d}", f"CVE-L{i:02d}", "HIGH", pkg=f"p{i:02d}")
    html = client.get("/").text
    assert "showing 25 of 31" in html
    assert "/findings?run_id=1&severity=CRITICAL&severity=HIGH&has_fix=yes" in unescape(html)
    assert "and 10 more" in html
    assert "/findings?run_id=1&cve=CVE-9&package=openssl" in unescape(html)
    assert html.count('data-fix="') == 25


def test_dashboard_links_carry_run_id(client, seed):
    run_id = _run(seed)
    for i in range(30):
        _add_fix(seed, run_id, f"img{i:02d}", "CVE-9")
    _add_fix(seed, run_id, "x", "CVE-1", "HIGH", fixed=None)
    for query in ("/", "/?by=image", "/?run_id=1"):
        main = client.get(query).text.split("<main", 1)[1]  # the site nav's bare /findings link is not page content
        links = [unescape(link) for link in re.findall(r'href="(/findings[^"]*)"', main)]
        assert links and all("run_id=1" in link for link in links), query


FATAL = (
    "2026-01-01T00:00:00Z\tFATAL\tFatal error\trun error: image scan error: scan error: unable to inspect the image"
    " (registry.example.com/team/app:1): 2 errors occurred:\n\t* MANIFEST_UNKNOWN: manifest unknown\n"
    "\t* unable to find the image"
)


def _add_failed(seed, run_id, ref, kind, error, platform="linux/amd64"):
    image = ImageRef(ref=ref, repo="registry.example.com/team/app", tag="1", digest="sha256:" + "a" * 64)
    item = InventoryItem(image=image, platform=platform, workloads=[])
    seed.repo.add_result(
        run_id, item, ImageResult(image=image, platform=platform, status="error", error_kind=kind, error=error)
    )


def test_failed_images_show_cause_and_one_hint_per_host(client, seed):
    run_id = _run(seed)
    _add_failed(seed, run_id, "registry.example.com/team/a:1", "auth", FATAL)
    _add_failed(seed, run_id, "registry.example.com/team/b:1", "auth", FATAL)
    _add_failed(seed, run_id, "registry.example.com/team/c:1", "not_found", FATAL)
    html = unescape(client.get("/").text)
    assert "Failed images" in html
    assert "MANIFEST_UNKNOWN: manifest unknown; unable to find the image" in html
    assert "run error: image scan error" not in html
    assert html.count("docker login registry.example.com`") == 1
    assert "registry.example.com/team/c:1" in html


def test_failed_images_section_hidden_without_failures(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["HIGH"])
    assert "Failed images" not in client.get("/").text


def test_failed_images_over_the_cap_say_so(client, seed):
    run_id = _run(seed)
    for i in range(27):
        _add_failed(seed, run_id, f"registry.example.com/team/app{i:02d}:1", "timeout", "timed out")
    html = client.get("/").text
    assert "showing 25 of 27" in html
    assert "app24:1" in html
    assert "app26:1" not in html


def test_hostile_strings_are_escaped(client, seed):
    run_id = _run(seed)
    ref = "reg.example.com/<script>x</script>:1"
    image = ImageRef(ref=ref, repo="reg.example.com/x", tag="1", digest="sha256:" + "a" * 64)
    finding = Finding(
        vuln_id="CVE-1",
        pkg_name="p",
        installed_version="1",
        fixed_version="2",
        severity=Severity("CRITICAL"),
        title="<img src=x onerror=alert(1)>",
        primary_url="javascript:alert(1)",
        target="t",
        pkg_type="os",
    )
    item = InventoryItem(image=image, platform="linux/amd64", workloads=[])
    seed.repo.add_result(
        run_id, item, ImageResult(image=image, platform="linux/amd64", status="ok", findings=[finding])
    )
    _add_failed(seed, run_id, ref + "x", "unknown", "<script>x</script>")
    seed.repo.add_warnings(run_id, [InventoryWarning("<b>ns</b>", coverage=True)])
    for path in ("/", "/?by=image"):
        html = client.get(path).text
        assert "<script>x" not in html
        assert html.count("<img") == 1  # only the logo
        assert "<b>ns" not in html
        assert 'href="javascript:' not in html


def test_login_hint_covers_auth_failures_past_the_list_cap(client, seed):
    run_id = _run(seed)
    for i in range(26):
        _add_failed(seed, run_id, f"a-{i:02d}.example.com/team/app:1", "not_found", FATAL)
    _add_failed(seed, run_id, "zz.example.com/<b>x</b>:1", "auth", FATAL)
    _add_failed(seed, run_id, "zz.example.com/<b>y</b>:1", "auth", FATAL)
    html = client.get("/").text
    assert "showing 25 of 28" in html
    assert "<b>x" not in html
    assert unescape(html).count("docker login zz.example.com`") == 1


def test_fix_row_keeps_ids_and_versions_whole(client, seed):
    run_id = _run(seed)
    _add_fix(seed, run_id, "img", "GHSA-abcd-efgh-ijkl", fixed="1.24.13, 1.26.0-rc.3")
    row = _between(client.get("/").text, 'data-fix="GHSA-abcd-efgh-ijkl"', "</details>")
    assert '<span class="cve">GHSA-abcd-efgh-ijkl</span>' in row
    assert '<span class="fixed"><span class="v">1.24.13</span>, <span class="v">1.26.0-rc.3</span></span>' in row
    css = (Path(kubedelos.web.__file__).parent / "static" / "app.css").read_text()
    assert re.search(r"\.v \{[^}]*white-space: nowrap;", css)
    assert re.search(r"\.cve \{[^}]*font-family: var\(--mono\);[^}]*white-space: nowrap;", css)
    assert "overflow-wrap: anywhere" not in _between(css, ".fix-summary {", "}")
    assert "overflow-wrap: break-word" in _between(css, ".version {", "}")


def test_fix_row_labels_installed_and_fixed_in_on_narrow_screens(client, seed):
    run_id = _run(seed)
    _add_fix(seed, run_id, "img", "CVE-9")
    row = _between(client.get("/").text, 'data-fix="CVE-9"', "</details>")
    assert '<span class="fix-label">installed </span>1.1' in row
    assert '<span class="fix-label">fixed in </span><span class="fixed">' in row
    css = (Path(kubedelos.web.__file__).parent / "static" / "app.css").read_text()
    assert re.search(r"\.fix-unit,\s*\.fix-label \{[^}]*display: none;", css)
    narrow = css[css.index("@media (max-width: 40rem)") :]
    assert re.search(r"\.fix-unit,\s*\.fix-label \{[^}]*display: inline;", narrow)


def test_severity_bar_gives_a_tiny_share_a_visible_minimum(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["CRITICAL"] + ["HIGH"] * 2 + ["LOW"] * 2997)
    bar = _between(_tile(client.get("/").text, "findings"), '<svg class="sevbar"', "</svg>")
    rects = re.findall(r'<rect class="(sev-[a-z]+)" x="([0-9.]+)" y="0" width="([0-9.]+)"', bar)
    assert rects == [("sev-critical", "0", "2.5"), ("sev-high", "2.5", "2.5"), ("sev-low", "5.0", "95.0")]
    seps = re.findall(r'<line class="sevbar-sep" x1="([0-9.]+)" y1="0" x2="([0-9.]+)" y2="10"/>', bar)
    assert seps == [("2.5", "2.5"), ("5.0", "5.0")]
    css = (Path(kubedelos.web.__file__).parent / "static" / "app.css").read_text()
    assert ".sevbar rect" not in css
    assert re.search(r"\.sevbar-sep \{[^}]*stroke: var\(--card\);", css)


def test_worst_images_show_the_image_name_and_a_short_tag(client, seed):
    run_id = _run(seed)
    long = "reg.example.com/kindest/kindnetd:v20251212-v0.29.0-alpha-105-g20ccfc88"
    _add(seed, run_id, long, ["CRITICAL"])
    _add(seed, run_id, "reg.example.com:5000/coredns/coredns:v1.13.1", ["HIGH"])
    panel = _between(client.get("/").text, '<ul class="worst">', "</ul>")
    assert ">kindnetd:v20251212-\u2026<" in panel and f'title="{long}"' in panel
    assert ">coredns:v1.13.1<" in panel


def test_counts_are_pluralised(client, seed):
    run_id = _run(seed)
    _add_fix(seed, run_id, "img", "CVE-9")
    html = client.get("/").text
    row = _between(html, 'data-fix="CVE-9"', "</summary>")
    assert '1 <span class="fix-unit">image</span>' in row and '1 <span class="fix-unit">namespace</span>' in row
    assert "of 1 image scanned" in _tile(html, "images-critical")
    for i in range(2):
        _add_fix(seed, run_id, f"other{i}", f"CVE-N{i}", "HIGH", fixed=None, ns=f"ns{i}")
    html = client.get("/").text
    assert "2 Critical/High findings have no released fix yet, across 2 images" in html
    assert "of 3 images scanned" in _tile(html, "images-critical")


def test_narrow_top_bar_puts_the_context_on_its_own_full_row():
    css = (Path(kubedelos.web.__file__).parent / "static" / "app.css").read_text()
    narrow = css[css.index("@media (max-width: 479px)") :]
    assert re.search(r"\.context \{[^}]*flex-basis: 100%;[^}]*margin: 0;", narrow)
