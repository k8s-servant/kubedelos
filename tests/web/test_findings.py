import re
from html import unescape
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import kubedelos.web
from kubedelos.config import Settings
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload

CLUSTER = Settings().scope


def _run(seed, *, scope=CLUSTER, level="library,os", status="ok"):
    run_id = seed.repo.start_run(seed.context, "cli", "0.76.1", scan_level=level, scope=scope)
    seed.repo.finish_run(run_id, status)
    return run_id


def _put(seed, run_id, ref, findings, namespaces=("ns",)):
    image = ImageRef(ref=ref, repo="reg.example.com/app", tag="1", digest="sha256:" + "a" * 64)
    workloads = [Workload(namespace=ns, kind="Deployment", name="a", container="c") for ns in namespaces]
    item = InventoryItem(image=image, platform="linux/amd64", workloads=workloads)
    result = ImageResult(image=image, platform="linux/amd64", status="ok", findings=findings)
    seed.repo.add_result(run_id, item, result)


def _f(vuln, sev="HIGH", *, pkg="openssl", url=None, pkg_class="os"):
    return Finding(
        vuln_id=vuln,
        pkg_name=pkg,
        installed_version="1.0",
        fixed_version="1.1",
        severity=Severity(sev),
        target="t",
        pkg_type="os",
        pkg_class=pkg_class,
        primary_url=url,
    )


def _hrefs(html):
    return [unescape(h) for h in re.findall(r'href="([^"]*)"', html)]


def test_default_run_is_newest_any_scope(client, seed):
    first = _run(seed)
    _put(seed, first, "old", [_f("CVE-OLD")])
    second = _run(seed, scope=Settings(namespaces=["web"]).scope)
    _put(seed, second, "new", [_f("CVE-NEW")], namespaces=("web",))
    html = client.get("/findings").text
    assert '<li class="chip">Run 2</li>' in html and "CVE-NEW" in html and "CVE-OLD" not in html


def test_no_runs_and_unknown_run(client, seed):
    assert "No scans of" in client.get("/findings").text
    failed = _run(seed, status="failed")
    assert client.get(f"/findings?run_id={failed}").status_code == 404
    assert client.get("/findings?run_id=99").status_code == 404


def test_row_columns(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "reg.example.com/app:1", [_f("CVE-1", url="https://example.com/CVE-1")])
    _put(seed, run_id, "other", [_f("CVE-2", url="javascript:alert(1)")])
    html = client.get("/findings").text
    assert '<a href="https://example.com/CVE-1" rel="noopener noreferrer">CVE-1</a>' in html
    assert "javascript:" not in html
    assert ">High<" in html and "1.0" in html and "1.1" in html
    assert 'title="reg.example.com/app:1"' in html and "reg.example.com/<wbr>app:1@sha256:aaaaaaaa" in html


def test_filters_round_trip_in_links(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "img", [_f(f"CVE-{i:03}", pkg="lib-x") for i in range(250)])
    html = client.get(f"/findings?run_id={run_id}&severity=HIGH&q=lib").text
    assert "1\u2013100 of 250" in html
    nxt = [h for h in _hrefs(html) if "page=2" in h]
    assert nxt
    query = parse_qs(urlsplit(nxt[0]).query)
    assert query["severity"] == ["HIGH"] and query["q"] == ["lib"] and query["page"] == ["2"]
    assert query["run_id"] == [str(run_id)]
    page2 = client.get(nxt[0]).text
    assert "101\u2013200 of 250" in page2
    prev = [h for h in _hrefs(page2) if "page=" not in h and "severity=HIGH" in h and "q=lib" in h]
    assert prev


def test_filter_form_and_clear_link(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "img", [_f("CVE-1")], namespaces=("web", "db"))
    html = client.get(f"/findings?run_id={run_id}&severity=HIGH&namespace=web").text
    assert '<form method="get" action="/findings"' in html
    assert 'name="severity" value="HIGH" checked' in html
    assert '<option value="db"' in html and '<option value="web" selected' in html
    assert f"/findings?run_id={run_id}" in _hrefs(html)


def test_sort_header_toggles_dir(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "img", [_f("CVE-1")])

    def link(html, col):
        found = [h for h in _hrefs(html) if f"sort={col}" in h]
        assert found, col
        return parse_qs(urlsplit(found[0]).query)

    default = client.get(f"/findings?run_id={run_id}").text
    assert link(default, "severity")["dir"] == ["asc"]  # severity is active and descending, so it flips
    assert "dir" not in link(default, "cve")
    asc = client.get(f"/findings?run_id={run_id}&sort=cve&dir=asc").text
    assert link(asc, "cve")["dir"] == ["desc"]
    desc = client.get(f"/findings?run_id={run_id}&sort=cve&dir=desc").text
    assert link(desc, "cve")["dir"] == ["asc"]
    assert 'aria-sort="ascending"' in asc and 'aria-sort="descending"' in desc


def test_sort_applies(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "img", [_f("CVE-1", pkg="zzz"), _f("CVE-2", pkg="aaa")])
    html = client.get(f"/findings?run_id={run_id}&sort=package&dir=asc").text
    assert html.index("CVE-2") < html.index("CVE-1")


def test_invalid_params_400(client, seed):
    run_id = _run(seed)
    for query in ("severity=BAD", "page=0", "sort=x", "pkg=jar", "has_fix=maybe", "dir=up", "page=abc"):
        assert client.get(f"/findings?run_id={run_id}&{query}").status_code == 400, query


def test_os_only_note(client, seed):
    run_id = _run(seed, level="os")
    _put(seed, run_id, "img", [_f("CVE-1")])
    assert "this run scanned OS packages only; library findings were not collected" in client.get("/findings").text
    other = _run(seed)
    _put(seed, other, "img", [_f("CVE-1")])
    assert "library findings were not collected" not in client.get("/findings").text


def test_empty_and_past_end_states(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "img", [_f(f"CVE-{i:03}") for i in range(150)])
    empty = client.get(f"/findings?run_id={run_id}&q=zzz").text
    assert "No findings match these filters" in empty and f"/findings?run_id={run_id}" in _hrefs(empty)
    past = client.get(f"/findings?run_id={run_id}&page=9").text
    assert "page 9 is past the end (150 findings)" in past
    assert any("page=2" in h for h in _hrefs(past))
    clean = _run(seed)
    assert "No vulnerabilities found" in client.get(f"/findings?run_id={clean}").text


def test_namespaces_cell_truncates(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "img", [_f("CVE-1")], namespaces=("n1", "n2", "n3", "n4", "n5"))
    html = client.get(f"/findings?run_id={run_id}").text
    assert "n1, n2, n3" in html and "+2" in html and "n4" not in html.split("<tbody>")[1]


def test_dashboard_links_work(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "img", [_f("CVE-1", "CRITICAL"), _f("CVE-2", "LOW")])
    html = client.get(
        f"/findings?run_id={run_id}&severity=CRITICAL&severity=HIGH&has_fix=yes&cve=CVE-1&package=openssl"
    )
    assert "CVE-1" in html.text and "CVE-2" not in html.text
    assert "1\u20131 of 1" in html.text


def test_findings_table_scrolls_inside_its_own_container(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "reg.example.com/app:1", [_f("CVE-1")])
    html = client.get("/findings").text
    wrap = re.search(r'<div class="table-wrap">(.*?)</div>', html, re.S)
    assert wrap and '<table class="findings">' in wrap.group(1)


def test_oversized_integers_are_a_400_page_with_security_headers(client, seed):
    _run(seed)
    big = "1" + "0" * 20
    for path in (f"/findings?run_id={big}", f"/?run_id={big}", f"/findings?page={big}"):
        response = client.get(path)
        assert response.status_code == 400, path
        assert "Content-Security-Policy" in response.headers, path


def test_hostile_strings_are_escaped_on_the_findings_page(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "reg.example.com/<script>x</script>:1", [_f("CVE-1")], namespaces=("<b>ns</b>",))
    html = client.get("/findings").text
    assert "<script>x</script>" not in html and "<b>ns</b>" not in html
    assert 'title="reg.example.com/&lt;script&gt;x&lt;/script&gt;:1"' in html
    assert re.search(r"<option[^>]*>&lt;b&gt;ns&lt;/b&gt;</option>", html)


def test_filters_are_one_card_with_severity_pills(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "img", [_f(f"CVE-{n}") for n in range(120)])
    html = client.get(f"/findings?run_id={run_id}&severity=HIGH").text
    assert re.search(r'<form [^>]*class="card filters"', html)
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        pill = re.search(rf'<label class="pill sev-{name.lower()}">(.*?)</label>', html, re.S)
        assert pill, name
        assert f'<input type="checkbox" name="severity" value="{name}"' in pill.group(1)
        assert name.title() in pill.group(1)
    assert re.search(r'<input type="checkbox" name="severity" value="HIGH" checked>', html)
    assert '<button type="submit" class="btn">Apply filters</button>' in html
    assert re.search(r'<div class="card">\s*<div class="table-wrap">', html)
    pager = re.search(r'<nav class="pager".*?</nav>', html, re.S).group(0)
    assert pager.count('aria-current="page"') == 1
    assert re.search(r'aria-current="page">1<', pager)
    assert '<span class="sev sev-high">High</span>' in html
    assert '<td class="version fixed"><span class="v">1.1</span></td>' in html
    assert re.search(r'<td class="version">1\.0</td>', html)
    assert re.search(r'<td class="cve">\s*(<a [^>]*>)?CVE-0', html)


def test_image_column_keeps_a_readable_width_instead_of_collapsing():
    """overflow-wrap: anywhere alone shrinks the column's min-content to one character per line."""
    css = (Path(kubedelos.web.__file__).parent / "static" / "app.css").read_text()
    block = re.search(r"\.findings \.ref \{([^}]*)\}", css).group(1)
    assert "min-width" in block


def test_versions_wrap_between_versions_and_ids_stay_whole(client, seed):
    """Only the CVE id stays on one line; a long installed version wraps, a fixed list breaks only at its commas."""
    run_id = _run(seed)
    finding = _f("GHSA-abcd-efgh-ijkl").model_copy(update={"fixed_version": "1.24.13, 1.26.0-rc.3"})
    _put(seed, run_id, "img", [finding])
    html = client.get(f"/findings?run_id={run_id}").text
    assert '<td class="version fixed"><span class="v">1.24.13</span>, <span class="v">1.26.0-rc.3</span></td>' in html
    assert "nowrap" not in html.split("<tbody>")[1]
    css = (Path(kubedelos.web.__file__).parent / "static" / "app.css").read_text()
    version = re.search(r"\.version \{([^}]*)\}", css).group(1)
    assert "overflow-wrap: break-word" in version and "max-width: 14rem" in version
    assert re.search(r"\.cve \{[^}]*font-family: var\(--mono\);[^}]*white-space: nowrap;", css)
    assert "font-family: var(--mono)" in re.search(r"\.findings \.ref \{([^}]*)\}", css).group(1)


def test_past_end_count_is_pluralised(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "img", [_f("CVE-1")])
    assert "page 2 is past the end (1 finding)" in client.get(f"/findings?run_id={run_id}&page=2").text


def test_filters_are_an_even_grid_with_steady_pills(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "img", [_f("CVE-1")])
    html = client.get(f"/findings?run_id={run_id}").text
    actions = re.search(r'<div class="filter-actions">(.*?)</div>', html, re.S)
    assert actions and '<button type="submit" class="btn">Apply filters</button>' in actions.group(1)
    assert 'class="clear"' in actions.group(1)
    css = (Path(kubedelos.web.__file__).parent / "static" / "app.css").read_text()
    filters = re.search(r"\.filters \{([^}]*)\}", css).group(1)
    assert "display: grid" in filters and "repeat(auto-fill, minmax(10rem, 1fr))" in filters
    assert "grid-column: span 2" in re.search(r"\.filter-severity \{([^}]*)\}", css).group(1)
    # The check mark's space is always there, so checking a pill does not move the row; focus shows for keyboards only.
    assert re.search(r"\.pill::before \{[^}]*width: 0\.75rem;", css)
    assert re.search(r"\.pill:has\(input:checked\)::before \{\s*content: \"\\2713\";\s*background: none;\s*\}", css)
    assert ".pill:focus-within" not in css and ".pill:has(input:focus-visible)" in css


def test_image_refs_break_at_their_slashes():
    """A ref breaks after each slash, never mid-name, so the image column stays narrow enough for namespaces."""
    css = (Path(kubedelos.web.__file__).parent / "static" / "app.css").read_text()
    block = re.search(r"\.findings \.ref \{([^}]*)\}", css).group(1)
    assert "overflow-wrap: break-word" in block and "anywhere" not in block


def test_image_ref_has_a_break_after_each_slash(client, seed):
    run_id = _run(seed)
    _put(seed, run_id, "reg.example.com/team/app:1", [_f("CVE-1")])
    html = client.get(f"/findings?run_id={run_id}").text
    assert ">reg.example.com/<wbr>app:1@sha256:aaaaaaaa</span>" in html
