import csv
import io
import re

from kubedelos.config import Settings
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.store import accepted
from kubedelos.web.routes.reports import safe_cell

CLUSTER = Settings().scope


def _run(seed, status="ok", context=None):
    run_id = seed.repo.start_run(context or seed.context, "ui", "0.76.1", scan_level="library,os", scope=CLUSTER)
    seed.repo.finish_run(run_id, status)
    return run_id


def _add(seed, run_id, ref, vulns=(), *, namespaces=("web",), status="ok", error=None):
    name, tag = ref.rsplit(":", 1)
    image = ImageRef(ref=ref, repo=name, tag=tag, digest=None)
    findings = [
        Finding(
            vuln_id=v, pkg_name=pkg, installed_version="1", fixed_version=fixed, severity=Severity(s), target="t",
            pkg_type="os", title=title, primary_url="https://example.com/" + v,
        )
        for v, s, pkg, fixed, title in vulns
    ]  # fmt: skip
    item = InventoryItem(
        image=image, platform="linux/amd64",
        workloads=[Workload(namespace=ns, kind="Deployment", name="w", container="c") for ns in namespaces],
    )  # fmt: skip
    kind = "trivy" if status == "error" else None
    result = ImageResult(
        image=image, platform="linux/amd64", status=status, error_kind=kind, error=error, findings=findings
    )
    seed.repo.add_result(run_id, item, result)


def _seed(seed):
    run_id = _run(seed)
    _add(seed, run_id, "reg.example.com/app:1", [
        ("CVE-1", "CRITICAL", "openssl", "2", "=HYPERLINK(\"https://example.com\")"),
        ("CVE-2", "HIGH", "zlib", None, "plain title"),
        ("CVE-3", "LOW", "-curl", "3", "@SUM(1)"),
    ], namespaces=("web", "api"))  # fmt: skip
    _add(seed, run_id, "reg.example.com/b:2", [("CVE-1", "CRITICAL", "openssl", "2", "t")])
    return run_id


def _csv(response):
    return list(csv.reader(io.StringIO(response.text)))


def test_safe_cell_defuses_spreadsheet_formulas():
    for text in ("=1+1", "+1", "-1", "@A1", "\t=1", "\r=1"):
        assert safe_cell(text) == "'" + text
    assert safe_cell("CVE-1") == "CVE-1" and safe_cell(None) == "" and safe_cell(3) == "3"


def test_csv_has_every_row_of_the_view_and_is_formula_safe(client, seed):
    run_id = _seed(seed)
    response = client.get("/findings.csv", params={"run_id": run_id})
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/csv")
    assert response.headers["content-disposition"] == f'attachment; filename="kubedelos-my-cluster-run{1}.csv"'
    rows = _csv(response)
    assert rows[0] == [
        "severity", "cve", "package", "installed", "fixed_in", "class", "image", "namespaces", "accepted", "title", "url",
        "risk",
    ]  # fmt: skip
    assert len(rows) == 1 + 4
    first = dict(zip(rows[0], rows[1], strict=True))
    assert first["severity"] == "CRITICAL" and first["cve"] == "CVE-1" and first["namespaces"] == "api; web"
    assert first["title"].startswith("'=HYPERLINK") and first["accepted"] == "no"
    low = next(r for r in rows if r[1] == "CVE-3")
    assert low[2] == "'-curl" and low[9] == "'@SUM(1)"


def test_csv_follows_the_findings_filters_and_accepted_mode(client, seed):
    run_id = _seed(seed)
    accepted.add(
        seed.repo._conn, vuln_id="CVE-2", reason="r", owner="me", expires=seed.clock.now.date(), context=None,
        now=seed.clock.now,
    )  # fmt: skip
    hidden = _csv(client.get("/findings.csv", params={"run_id": run_id}))
    assert "CVE-2" not in [r[1] for r in hidden]
    shown = _csv(client.get("/findings.csv", params={"run_id": run_id, "accepted": "all", "severity": "HIGH"}))
    assert [(r[1], r[8]) for r in shown[1:]] == [("CVE-2", "yes")]
    by_ns = _csv(client.get("/findings.csv", params={"run_id": run_id, "namespace": "api", "sort": "cve"}))
    assert [r[1] for r in by_ns[1:]] == ["CVE-1", "CVE-3"]


def test_findings_page_links_to_the_csv_of_its_view(client, seed):
    run_id = _seed(seed)
    html = client.get("/findings", params={"run_id": run_id, "severity": "HIGH", "page": 1}).text
    assert f'href="/findings.csv?run_id={run_id}&amp;severity=HIGH"' in html


def test_csv_of_another_cluster_or_a_missing_run_is_404(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    theirs = _run(seed, context="prod-eu")
    assert client.get("/findings.csv", params={"run_id": theirs}).status_code == 404
    assert client.get("/findings.csv", params={"run_id": 999}).status_code == 404
    named = client.get("/findings.csv", params={"run_id": theirs, "context": "prod-eu"})
    assert named.status_code == 200 and "kubedelos-prod-eu-run1.csv" in named.headers["content-disposition"]
    assert _csv(named) == [_csv(named)[0]]  # a header row and nothing else


def test_csv_filename_keeps_only_safe_characters(client, seed, kube_contexts):
    kube_contexts.append('arn:aws:eks:eu-west-1:123:cluster/x"y')
    theirs = _run(seed, context='arn:aws:eks:eu-west-1:123:cluster/x"y')
    response = client.get(
        "/findings.csv", params={"run_id": theirs, "context": 'arn:aws:eks:eu-west-1:123:cluster/x"y'}
    )
    assert response.headers["content-disposition"] == (
        'attachment; filename="kubedelos-arn_aws_eks_eu-west-1_123_cluster_x_y-run1.csv"'
    )


def test_report_sheet_of_the_dashboard_run(client, seed):
    run_id = _seed(seed)
    _add(seed, run_id, "reg.example.com/broken:1", status="error", error="unexpected EOF")
    accepted.add(
        seed.repo._conn, vuln_id="CVE-2", reason="r", owner="me", expires=seed.clock.now.date(), context=None,
        now=seed.clock.now,
    )  # fmt: skip
    html = client.get("/report").text
    assert "Vulnerability report" in html and "my-cluster" in html and "Run 1" in html
    assert re.search(r"Critical</dt>\s*<dd>2</dd>", html)  # counts are not changed by an acceptance
    fix = html.split('id="fix-title"', 1)[1].split("</section>", 1)[0]
    assert "CVE-1" in fix and "openssl" in fix
    assert "1 accepted Critical/High finding not listed" in html
    assert "reg.example.com/broken:1" in html and "unexpected EOF" in html
    assert 'media="print"' in html or "@media print" in html or "report-sheet" in html


def test_report_links_and_pinning(client, seed):
    run_id = _seed(seed)
    assert f'href="/report?run_id={run_id}"' in client.get("/").text
    assert f'href="/report?run_id={run_id}">report</a>' in client.get("/scans").text
    assert "Run 1" in client.get("/report", params={"run_id": run_id}).text
    assert client.get("/report", params={"run_id": 999}).status_code == 404


def test_report_without_runs_points_to_scans(client):
    html = client.get("/report").text
    assert "No scans of" in html and 'href="/scans"' in html


def _form(html, action):
    return html.split(f'<form method="get" action="{action}"', 1)[1].split("</form>", 1)[0]


def test_reports_page_offers_each_run_for_the_report_and_the_csv(client, seed):
    first = _run(seed)
    newest = _seed(seed)
    _add(seed, newest, "reg.example.com/c:1", [], namespaces=("jobs",))
    html = client.get("/reports").text
    assert '<li><a href="/reports" aria-current="page">Reports</a></li>' in html
    report = _form(html, "/report")
    options = re.findall(r'<option value="(\d+)"( selected)?>Run (\d+)', report)
    assert options == [(str(newest), " selected", "2"), (str(first), "", "1")]
    assert '<button type="submit" class="btn">Open report</button>' in report
    export = _form(html, "/findings.csv")
    assert re.findall(r'<option value="(\d+)"( selected)?>Run', export) == [
        (str(newest), " selected"),
        (str(first), ""),
    ]
    checked = re.findall(r'name="severity" value="(\w+)"( checked)?', export)
    assert checked == [("CRITICAL", " checked"), ("HIGH", " checked"), ("MEDIUM", ""), ("LOW", ""), ("UNKNOWN", "")]
    assert re.findall(
        r'<option value="([\w-]+)"></option>',
        html.split('<datalist id="report-namespaces">')[1].split("</datalist>")[0],
    ) == ["api", "jobs", "web"]
    for name in ("has_fix", "pkg", "accepted"):
        assert f'name="{name}"' in export
    assert '<button type="submit" class="btn">Download CSV</button>' in export


def test_reports_page_forms_send_what_the_reports_take(client, seed):
    run_id = _seed(seed)
    report = client.get("/report", params={"run_id": run_id})
    assert report.status_code == 200
    sent = [
        ("run_id", run_id), ("severity", "CRITICAL"), ("severity", "HIGH"), ("namespace", ""),
        ("has_fix", "any"), ("pkg", "all"), ("accepted", "hide"),
    ]  # fmt: skip
    export = client.get("/findings.csv", params=sent)
    assert export.status_code == 200
    rows = _csv(export)
    assert {r[0] for r in rows[1:]} == {"CRITICAL", "HIGH"}


def test_reports_page_keeps_the_shown_context(client, seed, kube_contexts):
    kube_contexts.append("prod-eu")
    _seed(seed)
    theirs = _run(seed, context="prod-eu")
    html = client.get("/reports", params={"context": "prod-eu"}).text
    for action in ("/report", "/findings.csv"):
        form = _form(html, action)
        assert '<input type="hidden" name="context" value="prod-eu">' in form
        assert re.findall(r'<option value="(\d+)"', form) == [str(theirs)]


def test_reports_page_without_runs_points_to_scans(client):
    html = client.get("/reports").text
    assert "No scans of" in html and 'href="/scans"' in html
    assert "<form" not in html.split("<main", 1)[1]


def test_report_fix_table_has_a_risk_column_when_the_score_is_shown(client, risk_run, add_feeds):
    add_feeds()
    html = client.get("/report").text
    assert '<th scope="col" class="num">Risk</th>' in html
    assert html.index("CVE-HOT") < html.index("CVE-COLD")
    assert '<td class="num">53</td>' in html
    assert "risk-note" not in html


def test_report_fix_table_has_no_risk_column_when_hidden(client, seed):
    run_id = _run(seed)
    _add(seed, run_id, "reg.example.com/app:1", [("CVE-1", "CRITICAL", "openssl", "2", "t")])
    html = client.get("/report").text
    assert ">Risk</th>" not in html
    assert "Risk scores are hidden for this run" in html


def test_csv_risk_cells_are_ints_when_shown(client, risk_run, add_feeds):
    run_id, _, _ = risk_run
    add_feeds()
    rows = _csv(client.get("/findings.csv", params={"run_id": run_id, "sort": "risk"}))
    assert rows[0][-1] == "risk"
    assert [(r[1], r[-1]) for r in rows[1:]] == [("CVE-HOT", "53"), ("CVE-COLD", "45")]


def test_csv_risk_cells_are_empty_when_hidden(client, seed):
    rows = _csv(client.get("/findings.csv", params={"run_id": _seed(seed)}))
    assert rows[0][-1] == "risk" and len(rows) > 1 and {r[-1] for r in rows[1:]} == {""}
