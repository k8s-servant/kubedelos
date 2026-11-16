import re

from kubedelos.config import Settings
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload

CLUSTER = Settings().scope


def _run(seed, *, scope=CLUSTER, context=None):
    run_id = seed.repo.start_run(context or seed.context, "ui", "0.76.1", scan_level="library,os", scope=scope)
    seed.repo.finish_run(run_id, "ok")
    return run_id


def _add(seed, run_id, ref, namespaces, severities=(), *, owner=None, team=None, status="ok"):
    image = ImageRef(ref=ref, repo="reg.example.com/app", tag=ref, digest=None)
    item = InventoryItem(
        image=image,
        platform="linux/amd64",
        workloads=[
            Workload(namespace=ns, kind="Deployment", name="w", container="c", owner=owner, team=team)
            for ns in namespaces
        ],
    )
    findings = [
        Finding(
            vuln_id=f"CVE-{ref}-{i}",
            pkg_name="p",
            installed_version="1",
            severity=Severity(s),
            target="t",
            pkg_type="os",
        )
        for i, s in enumerate(severities)
    ]
    seed.repo.add_result(
        run_id, item, ImageResult(image=image, platform="linux/amd64", status=status, findings=findings)
    )


def _seed(seed):
    run_id = _run(seed)
    _add(seed, run_id, "a", ["web"], ["HIGH", "HIGH", "LOW"], owner="web@example.com", team="payments")
    _add(seed, run_id, "b", ["api"], ["CRITICAL", "MEDIUM"], owner="api@example.com", team="platform")
    _add(seed, run_id, "c", ["batch"], ["CRITICAL", "HIGH"])
    _add(seed, run_id, "d", ["idle"])
    return run_id


def _rows(html):
    body = html[html.index("<tbody>") : html.index("</tbody>")]
    return re.findall(r"<tr>(.*?)</tr>", body, re.S)


def _names(html):
    return [re.search(r'<th scope="row">([^<]+)</th>', row).group(1) for row in _rows(html)]


def test_nav_lists_namespaces_between_findings_and_scans(client, seed):
    _seed(seed)
    nav = client.get("/namespaces").text.split('<nav aria-label="Main">', 1)[1].split("</nav>", 1)[0]
    labels = re.findall(r">([A-Z][a-z]+)</a>", nav)
    assert labels == ["Dashboard", "Findings", "Namespaces", "Compare", "Accepted", "Scans"]
    assert 'href="/namespaces" aria-current="page"' in nav


def test_worst_first_by_critical_then_high(client, seed):
    _seed(seed)
    html = client.get("/namespaces").text
    assert _names(html) == ["batch", "api", "web", "idle"]
    assert "4 namespaces" in html


def test_counts_link_to_the_exact_findings(client, seed):
    run_id = _seed(seed)
    html = client.get("/namespaces").text
    web = next(row for row in _rows(html) if '<th scope="row">web</th>' in row)
    assert f'href="/findings?run_id={run_id}&amp;namespace=web&amp;severity=HIGH">2</a>' in web
    assert f'href="/findings?run_id={run_id}&amp;namespace=web&amp;severity=LOW">1</a>' in web
    assert f'href="/findings?run_id={run_id}&amp;namespace=web">3</a>' in web  # the total
    assert "severity=CRITICAL" not in web  # a zero count is not a link
    assert "web@example.com" in web and "payments" in web
    # The link opens exactly those findings.
    linked = client.get("/findings", params={"run_id": run_id, "namespace": "web", "severity": "HIGH"}).text
    assert "1\u20132 of 2" in linked  # every one of them, and no more


def test_every_column_sorts_both_ways(client, seed):
    _seed(seed)
    asc = client.get("/namespaces", params={"sort": "namespace", "dir": "asc"}).text
    assert _names(asc) == ["api", "batch", "idle", "web"]
    assert 'aria-sort="ascending"' in asc
    desc = client.get("/namespaces", params={"sort": "total", "dir": "desc"}).text
    assert _names(desc)[0] == "web"
    owner = client.get("/namespaces", params={"sort": "owner"}).text
    assert _names(owner)[:2] == ["api", "web"]  # namespaces without an owner sort last
    for column in ("team", "critical", "high", "medium", "low", "unknown", "images"):
        assert client.get("/namespaces", params={"sort": column}).status_code == 200
    assert client.get("/namespaces", params={"sort": "bogus"}).status_code == 400


def test_sort_header_links_keep_the_filters_and_flip_direction(client, seed):
    _seed(seed)
    html = client.get("/namespaces", params={"q": "a", "sort": "namespace", "dir": "asc"}).text
    head = html[html.index("<thead>") : html.index("</thead>")]
    assert 'href="/namespaces?q=a&amp;sort=namespace&amp;dir=desc"' in head


def test_filters_by_text_and_severity(client, seed):
    _seed(seed)
    assert _names(client.get("/namespaces", params={"q": "PAY"}).text) == ["web"]  # team, any case
    assert _names(client.get("/namespaces", params={"q": "api@"}).text) == ["api"]  # owner
    critical = client.get("/namespaces", params={"has": "CRITICAL"}).text
    assert _names(critical) == ["batch", "api"]
    assert "2 of 4 namespaces" in critical
    none = client.get("/namespaces", params={"q": "zzz"}).text
    assert "No namespaces match" in none and 'href="/namespaces"' in none


def test_uses_the_newest_whole_cluster_run(client, seed):
    whole = _seed(seed)
    narrow = _run(seed, scope=Settings(namespaces=["web"]).scope)
    _add(seed, narrow, "z", ["web"], ["CRITICAL"])
    html = client.get("/namespaces").text
    assert f"Run {whole}<" in html
    pinned = client.get("/namespaces", params={"run_id": narrow}).text
    assert _names(pinned) == ["web"] and "pinned" in pinned


def test_without_a_whole_cluster_run_points_to_the_newest_findings(client, seed):
    narrow = _run(seed, scope=Settings(namespaces=["web"]).scope)
    html = client.get("/namespaces").text
    assert "no cluster-wide run" in html and f'href="/findings?run_id={narrow}"' in html


def test_empty_state_links_to_scans(client):
    html = client.get("/namespaces").text
    assert "No scans of" in html and '<a href="/scans">Scans page</a>' in html


def test_another_contexts_run_is_not_shown(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    theirs = _run(seed, context="prod-eu")
    _add(seed, theirs, "p", ["prod-ns"], ["CRITICAL"])
    assert client.get("/namespaces", params={"run_id": theirs}).status_code == 404
    html = client.get("/namespaces", params={"context": "prod-eu"}).text
    assert _names(html) == ["prod-ns"]
    assert f'href="/findings?context=prod-eu&amp;run_id={theirs}&amp;namespace=prod-ns&amp;severity=CRITICAL"' in html
    form = html[html.index('<form method="get" action="/namespaces"') : html.index("</form>")]
    assert '<input type="hidden" name="context" value="prod-eu">' in form


def test_the_form_s_any_severity_submits_an_empty_has(client, seed):
    _seed(seed)
    response = client.get("/namespaces", params={"q": "PAY", "has": ""})  # what the form sends for "any severity"
    assert response.status_code == 200 and _names(response.text) == ["web"]
    assert '<option value="">any severity</option>' in response.text
    assert client.get("/namespaces", params={"has": "SEVERE"}).status_code == 400  # a real bad value still is
