import re
from datetime import date, timedelta

from kubedelos.config import Settings
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.store import accepted

CLUSTER = Settings().scope
ORIGIN = {"origin": "http://127.0.0.1:9370"}
TODAY = date(2026, 1, 1)  # the test clock's day


def _run(seed, context=None):
    run_id = seed.repo.start_run(context or seed.context, "ui", "0.76.1", scan_level="library,os", scope=CLUSTER)
    seed.repo.finish_run(run_id, "ok")
    return run_id


def _add(seed, run_id, ref, namespaces, vulns, *, fixed="2", severity="CRITICAL"):
    image = ImageRef(ref=f"reg.example.com/{ref}:1", repo=f"reg.example.com/{ref}", tag="1", digest=None)
    item = InventoryItem(
        image=image,
        platform="linux/amd64",
        workloads=[Workload(namespace=ns, kind="Deployment", name="w", container="c") for ns in namespaces],
    )
    findings = [
        Finding(
            vuln_id=v,
            pkg_name="openssl",
            installed_version="1",
            fixed_version=fixed,
            severity=Severity(severity),
            target="t",
            pkg_type="os",
        )
        for v in vulns
    ]
    seed.repo.add_result(run_id, item, ImageResult(image=image, platform="linux/amd64", status="ok", findings=findings))


def _seed(seed):
    run_id = _run(seed)
    _add(seed, run_id, "app", ["web"], ["CVE-1", "CVE-2"])
    _add(seed, run_id, "api", ["api"], ["CVE-1"])
    return run_id


def _accept(seed, vuln_id="CVE-1", *, context="my-cluster", days=30, **narrow):
    return accepted.add(
        seed.repo._conn,
        vuln_id=vuln_id,
        reason="behind the proxy",
        owner="sam",
        expires=TODAY + timedelta(days=days),
        context=context,
        now=seed.clock.now,
        **narrow,
    )


def _csrf(client) -> str:
    guard = client.app.state.guard
    return guard.csrf_token(client.cookies[guard.cookie_name])


def _post(client, path, **fields):
    data = {"csrf_token": _csrf(client), **fields}
    return client.post(path, data=data, headers=ORIGIN, follow_redirects=False)


FORM = {"cve": "CVE-1", "reason": "not reachable", "owner": "sam", "expires": "2026-03-01", "scope": "context"}


def test_nav_lists_accepted_after_namespaces(client, seed):
    nav = client.get("/accepted").text.split('<nav aria-label="Main">', 1)[1].split("</nav>", 1)[0]
    assert re.findall(r">([A-Z][a-z]+)</a>", nav) == [
        "Dashboard",
        "Findings",
        "Namespaces",
        "Compare",
        "Reports",
        "Accepted",
        "Scans",
        "Settings",
    ]
    assert 'href="/accepted" aria-current="page"' in nav


def test_empty_register_points_to_the_findings(client):
    html = client.get("/accepted").text
    assert "Nothing accepted" in html and 'href="/findings"' in html


def test_register_shows_state_days_left_and_cover(client, seed):
    _seed(seed)
    soon = _accept(seed, days=3, namespace="web")
    _accept(seed, "CVE-404", context=None)
    html = client.get("/accepted").text
    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html[html.index("<tbody>") :], re.S)
    assert "CVE-404" in rows[1] and "covers nothing" in rows[1] and "all clusters" in rows[1]
    first = rows[0]
    assert "CVE-1" in first and "3 days left" in first and "covers 1 finding" in first
    assert "web" in first and "behind the proxy" in first and "sam" in first
    assert f'action="/accepted/{soon}/revoke"' in first and 'name="csrf_token"' in first


def test_the_cve_filter_narrows_the_register(client, seed):
    _seed(seed)
    _accept(seed)
    _accept(seed, "CVE-2")
    html = client.get("/accepted", params={"cve": "CVE-2"}).text
    body = html[html.index("<tbody>") :]
    assert "CVE-2" in body and "CVE-1" not in body


def test_form_is_prefilled_from_the_findings_row(client, seed):
    params = {"cve": "CVE-1", "package": "openssl", "image": "reg.example.com/app", "namespace": "web"}
    html = client.get("/accepted/new", params=params).text
    form = html[html.index('<form method="post" action="/accepted"') :]
    for name, value in params.items():
        assert f'name="{name}" value="{value}"' in form
    assert 'name="expires" value="2026-04-01"' in form  # +90 days
    assert 'min="2026-01-01"' in form and 'max="2027-01-01"' in form
    assert re.search(r'name="owner" value="[^"]+"', form)  # the OS user
    assert 'name="csrf_token"' in form and 'value="context" checked' in form


def test_create_stores_and_redirects_to_the_register(client, seed):
    _seed(seed)
    response = _post(client, "/accepted", **FORM, package="openssl", image="", namespace="web")
    assert response.status_code == 303 and response.headers["location"] == "/accepted"
    (entry,) = accepted.register(seed.repo._conn, "my-cluster", None, TODAY)
    assert (entry.vuln_id, entry.context, entry.namespace, entry.pkg_name, entry.repo) == (
        "CVE-1",
        "my-cluster",
        "web",
        "openssl",
        None,
    )
    assert entry.expires == date(2026, 3, 1) and entry.owner == "sam"
    _post(client, "/accepted", **{**FORM, "scope": "all"})
    assert accepted.register(seed.repo._conn, "prod-eu", None, TODAY)[0].context is None


def test_create_requires_csrf(client, seed):
    response = client.post("/accepted", data=FORM, headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 403


def test_create_refuses_bad_input_and_keeps_what_was_typed(client, seed):
    cases = [
        ({"cve": " "}, "a CVE is required"),
        ({"reason": ""}, "a reason is required"),
        ({"reason": "x" * 501}, "at most 500"),
        ({"expires": "2025-12-31"}, "in the past"),
        ({"expires": "2027-01-02"}, "at most 365 days"),
        ({"expires": "soon"}, "not a date"),
        ({"scope": "elsewhere"}, "cluster"),
    ]
    for fields, message in cases:
        response = _post(client, "/accepted", **{**FORM, **fields})
        assert response.status_code == 400, fields
        assert message in response.text, fields
        assert 'value="sam"' in response.text  # the owner typed is kept
    assert accepted.register(seed.repo._conn, "my-cluster", None, TODAY) == []


def test_create_for_another_context_uses_the_posted_one(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    response = _post(client, "/accepted", **FORM, context="prod-eu")
    assert response.headers["location"] == "/accepted?context=prod-eu"
    assert accepted.register(seed.repo._conn, "prod-eu", None, TODAY)[0].context == "prod-eu"
    assert accepted.register(seed.repo._conn, "my-cluster", None, TODAY) == []
    assert _post(client, "/accepted", **FORM, context="nowhere").status_code == 404


def test_revoke_takes_effect_at_once(client, seed):
    run_id = _seed(seed)
    entry = _accept(seed)
    assert "CVE-1" not in client.get("/findings", params={"run_id": run_id}).text.split("<tbody>")[1]
    response = _post(client, f"/accepted/{entry}/revoke")
    assert response.status_code == 303 and response.headers["location"] == "/accepted"
    assert "CVE-1" in client.get("/findings", params={"run_id": run_id}).text.split("<tbody>")[1]
    assert "revoked" in client.get("/accepted").text
    assert _post(client, f"/accepted/{entry}/revoke").status_code == 404  # already revoked
    assert _post(client, "/accepted/999/revoke").status_code == 404
    assert client.post(f"/accepted/{entry}/revoke", headers=ORIGIN).status_code == 403  # CSRF


def test_revoke_refuses_another_clusters_entry(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    theirs = _accept(seed, context="prod-eu")
    assert _post(client, f"/accepted/{theirs}/revoke").status_code == 404
    assert _post(client, f"/accepted/{theirs}/revoke", context="prod-eu").status_code == 303


def test_findings_hide_accepted_rows_and_say_so(client, seed):
    run_id = _seed(seed)
    entry = _accept(seed, namespace="web")
    html = client.get("/findings", params={"run_id": run_id}).text
    body = html.split("<tbody>")[1]
    assert body.count("<tr>") == 2  # CVE-1 on api and CVE-2 on app; CVE-1 on app is accepted
    assert "1 accepted finding not shown" in html
    assert f'href="/findings?run_id={run_id}&amp;accepted=only"' in html
    only = client.get("/findings", params={"run_id": run_id, "accepted": "only"}).text
    only_body = only.split("<tbody>")[1]
    assert only_body.count("<tr>") == 1 and 'class="chip chip-accepted"' in only_body
    assert 'href="/accepted?cve=CVE-1"' in only_body
    assert '<option value="only" selected>' in only
    assert entry


def test_findings_rows_link_to_a_prefilled_accept_form(client, seed):
    run_id = _seed(seed)
    html = client.get("/findings", params={"run_id": run_id, "namespace": "web"}).text
    assert (
        'href="/accepted/new?cve=CVE-1&amp;package=openssl&amp;image=reg.example.com%2Fapp&amp;namespace=web"' in html
    )
    unfiltered = client.get("/findings", params={"run_id": run_id}).text
    assert 'href="/accepted/new?cve=CVE-2&amp;package=openssl&amp;image=reg.example.com%2Fapp"' in unfiltered


def test_dashboard_fix_list_leaves_accepted_out_and_counts_stay(client, seed):
    run_id = _seed(seed)
    before = client.get("/").text
    _accept(seed, "CVE-2")
    html = client.get("/").text
    fix = html[html.index("fix-first") :]
    assert "CVE-2" not in fix.split("</table>")[0]
    assert "1 accepted Critical/High finding not shown" in html
    assert f'href="/findings?run_id={run_id}&amp;severity=CRITICAL&amp;severity=HIGH&amp;accepted=only"' in html
    tiles = re.findall(r'class="tile-value[^"]*">(\d+)', before)
    assert tiles and re.findall(r'class="tile-value[^"]*">(\d+)', html) == tiles  # the numbers never move


def test_hostile_text_is_escaped(client, seed):
    _seed(seed)
    _accept(seed, "<script>x</script>", namespace="<b>ns</b>")
    html = client.get("/accepted").text
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html and "<b>ns</b>" not in html


def test_findings_say_when_every_finding_is_accepted(client, seed):
    run_id = _seed(seed)
    _accept(seed)
    _accept(seed, "CVE-2")
    html = client.get("/findings", params={"run_id": run_id}).text
    assert "Every finding here is accepted" in html and "No vulnerabilities found" not in html
    assert "3 accepted findings not shown" in html


def test_inactive_entries_show_no_cover_link_and_links_keep_the_narrowing(client, seed):
    run_id = _seed(seed)
    active = _accept(seed, namespace="web", pkg_name="openssl")
    revoked = _accept(seed, "CVE-2")
    accepted.revoke(seed.repo._conn, revoked, seed.clock.now)
    html = client.get("/accepted").text
    body = html[html.index("<tbody>") :]
    revoked_row = body[body.index("CVE-2") :]
    assert "covers" not in revoked_row.split("</tr>")[0]
    link = f"/findings?run_id={run_id}&amp;cve=CVE-1&amp;package=openssl&amp;namespace=web&amp;accepted=only"
    assert f'href="{link}"' in html and active


def test_revoke_with_an_unreadable_body_is_refused(client, seed):
    entry = _accept(seed)
    headers = {**ORIGIN, "x-csrf-token": _csrf(client), "content-type": "application/x-www-form-urlencoded"}
    response = client.post(f"/accepted/{entry}/revoke", headers=headers, content=b"\xff\xfe", follow_redirects=False)
    assert response.status_code == 400
    assert accepted.register(seed.repo._conn, "my-cluster", None, TODAY)[0].state == "active"


def test_register_names_the_run_by_its_number_in_the_cluster(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    _run(seed)  # my-cluster's run 1, id 1
    theirs = _run(seed, context="prod-eu")
    _add(seed, theirs, "app", ["web"], ["CVE-1"])
    _accept(seed, context="prod-eu")
    html = client.get("/accepted", params={"context": "prod-eu"}).text
    assert theirs == 2 and "covers 1 finding</a> in run 1" in html
