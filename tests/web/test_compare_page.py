import re

from kubedelos.config import Settings
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload

CLUSTER = Settings().scope


def _run(seed, *, scope=CLUSTER, level="library,os", context=None):
    context = context or seed.context
    run_id = seed.repo.start_run(context, context, "ui", "0.76.1", scan_level=level, scope=scope)
    seed.repo.finish_run(run_id, "ok")
    return run_id


def _add(seed, run_id, ref, vulns=(), *, status="ok"):
    name, tag = ref.rsplit(":", 1)
    image = ImageRef(ref=ref, repo=name, tag=tag, digest=None)
    findings = [
        Finding(
            vuln_id=v, pkg_name="openssl", installed_version="1", fixed_version="2", severity=Severity(s), target="t",
            pkg_type="os",
        )
        for v, s in vulns
    ]  # fmt: skip
    item = InventoryItem(
        image=image, platform="linux/amd64",
        workloads=[Workload(namespace="ns", kind="Deployment", name="w", container="c")],
    )  # fmt: skip
    kind = "trivy" if status == "error" else None
    seed.repo.add_result(
        run_id,
        item,
        ImageResult(image=image, platform="linux/amd64", status=status, error_kind=kind, findings=findings),
    )


def _pair(seed):
    old, new = _run(seed), _run(seed)
    _add(seed, old, "reg.example.com/app:1.2", [("CVE-1", "HIGH"), ("CVE-2", "CRITICAL")])
    _add(seed, old, "reg.example.com/old:1", [("CVE-9", "LOW")])
    _add(seed, new, "reg.example.com/app:1.3", [("CVE-1", "HIGH"), ("CVE-3", "MEDIUM")])
    _add(seed, new, "reg.example.com/fresh:1")
    return old, new


def _tiles(html):
    return dict(re.findall(r'data-tile="([a-z-]+)".*?class="tile-value[^"]*">(\d+)<', html, re.S))


def test_default_pair_is_the_dashboard_run_and_its_previous_comparable(client, seed):
    _pair(seed)
    html = client.get("/diff").text
    assert "Run 1 → Run 2" in html
    assert _tiles(html) == {"new": "1", "gone": "2", "added": "1", "removed": "1", "changed": "1"}
    assert "1 still open" in html


def test_tables_show_findings_worst_first_and_link_to_their_run(client, seed):
    old, new = _pair(seed)
    html = client.get("/diff").text
    new_table = html.split('id="new-title"', 1)[1].split("</table>", 1)[0]
    assert "CVE-3" in new_table and f'href="/findings?run_id={new}&amp;cve=CVE-3&amp;package=openssl"' in new_table
    gone = html.split('id="gone-title"', 1)[1].split("</table>", 1)[0]
    assert gone.index("CVE-2") < gone.index("CVE-9")  # Critical before Low
    assert "image gone" in gone.split("CVE-9", 1)[1].split("</tr>", 1)[0]
    assert f'href="/findings?run_id={old}&amp;cve=CVE-2&amp;package=openssl"' in gone
    images = html.split('id="images-title"', 1)[1]
    assert "reg.example.com/app:1.2" in images and "reg.example.com/app:1.3" in images


def test_any_two_runs_can_be_picked_in_either_order(client, seed):
    old, new = _pair(seed)
    third = _run(seed)
    swapped = client.get("/diff", params={"from": new, "to": old}).text
    assert "Run 1 → Run 2" in swapped
    picked = client.get("/diff", params={"from": old, "to": third}).text
    assert "Run 1 → Run 3" in picked
    form = picked.split('<form method="get" action="/diff"', 1)[1].split("</form>", 1)[0]
    assert f'<option value="{old}" selected>' in form and f'<option value="{third}" selected>' in form
    same = client.get("/diff", params={"from": old, "to": old}).text
    assert "Pick two different runs" in same


def test_a_mismatch_and_failed_images_are_named_above_the_numbers(client, seed):
    old = _run(seed)
    _add(seed, old, "reg.example.com/app:1", [("CVE-1", "HIGH")])
    narrow = _run(seed, scope=Settings(namespaces=["web"]).scope, level="os")
    _add(seed, narrow, "reg.example.com/app:1", status="error")
    html = client.get("/diff", params={"from": old, "to": narrow}).text
    banner = html.split('class="tiles', 1)[0]
    assert "scanned different things" in banner and "namespace web" in banner and "OS packages" in banner
    assert "Run 2 had 1 failed image" in banner


def test_no_earlier_comparable_run_offers_the_pickers(client, seed):
    _run(seed)
    html = client.get("/diff").text
    assert "no earlier comparable run" in html and '<form method="get" action="/diff"' in html


def test_empty_state_links_to_scans(client):
    html = client.get("/diff").text
    assert "No scans of" in html and 'href="/scans"' in html


def test_another_clusters_runs_are_not_shown(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    old, _new = _pair(seed)
    theirs = _run(seed, context="prod-eu")
    assert client.get("/diff", params={"from": old, "to": theirs}).status_code == 404
    html = client.get("/diff", params={"context": "prod-eu"}).text
    assert "no earlier comparable run" in html
    form = html.split('<form method="get" action="/diff"', 1)[1].split("</form>", 1)[0]
    assert '<input type="hidden" name="context" value="prod-eu">' in form and f'value="{old}"' not in form


def test_nav_dashboard_and_history_link_to_compare(client, seed):
    old, new = _pair(seed)
    nav = client.get("/diff").text.split('<nav aria-label="Main">', 1)[1].split("</nav>", 1)[0]
    assert re.findall(r">([A-Z][a-z]+)</a>", nav) == [
        "Dashboard", "Findings", "Namespaces", "Compare", "Reports", "Accepted", "Scans", "Settings", "About",
    ]  # fmt: skip
    assert f'href="/diff?from={old}&amp;to={new}"' in client.get("/").text  # the change tiles
    assert f'href="/diff?to={new}">compare</a>' in client.get("/scans").text


def test_hostile_refs_are_escaped(client, seed):
    _old, new = _run(seed), _run(seed)
    _add(seed, new, "reg.example.com/<script>x:1", [("CVE-<b>", "HIGH")])
    html = client.get("/diff").text
    assert "<script>x" not in html and "CVE-<b>" not in html
