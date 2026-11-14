import csv
import io
import json

from kubedelos import __version__
from kubedelos.output import render_csv, render_json, render_sarif, render_table, short_image


def _row(**kw):
    base = {
        "namespace": "prod",
        "kind": "Deployment",
        "workload": "api",
        "container": "app",
        "owner": None,
        "team": "core",
        "image": "reg.io/a:1",
        "repo": "reg.io/a",
        "tag": "1",
        "digest": None,
        "platform": "linux/amd64",
        "vuln_id": "CVE-1",
        "severity": "CRITICAL",
        "pkg_name": "openssl",
        "installed_version": "1.0",
        "fixed_version": "1.1",
        "title": "t",
        "primary_url": None,
        "target": "debian",
        "pkg_type": "os",
        "pkg_class": "os",
    }
    return base | kw


ROWS = [
    _row(),
    _row(vuln_id="CVE-2", severity="MEDIUM", fixed_version=None),
    _row(vuln_id="CVE-3", severity="LOW"),
    _row(vuln_id="CVE-1", workload="web"),
]


def test_render_sarif_schema_shape():
    doc = json.loads(render_sarif(ROWS))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "kubedelos"
    assert run["tool"]["driver"]["version"] == __version__
    assert sorted(r["id"] for r in run["tool"]["driver"]["rules"]) == ["CVE-1", "CVE-2", "CVE-3"]
    assert len(run["results"]) == 4
    levels = {(r["ruleId"], r["level"]) for r in run["results"]}
    assert levels == {("CVE-1", "error"), ("CVE-2", "warning"), ("CVE-3", "note")}
    first = run["results"][0]
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "reg.io/a:1"
    assert first["properties"] == {"namespace": "prod", "workload": "api", "severity": "CRITICAL"}
    assert "openssl" in first["message"]["text"] and "api" in first["message"]["text"]


def test_render_csv_header():
    out = render_csv(ROWS)
    assert out.splitlines()[0] == (
        "namespace,kind,workload,container,image,vuln_id,severity,pkg_name,pkg_class,installed_version,fixed_version,"
        "owner,team"
    )
    assert len(list(csv.reader(io.StringIO(out)))) == 5


def test_render_json_keeps_nulls():
    data = json.loads(render_json(ROWS))
    assert len(data) == 4 and data[0]["owner"] is None


def test_render_table_plain_and_empty():
    out = render_table(ROWS)
    assert "CVE-1" in out and "prod/api" in out and "\x1b" not in out
    assert "CVE" not in render_table([])


def test_render_table_does_not_parse_markup():
    out = render_table([_row(repo="reg.io/[bold]x[/bold]", installed_version="[/x]")])
    assert "[bold]x[/bold]" in out and "[/x]" in out


def test_render_csv_escapes_formula_cells_only_in_csv():
    rows = [_row(pkg_name='=HYPERLINK("x")', workload="-cmd", team="@t", owner="\tx", installed_version="1.0")]
    cells = next(csv.DictReader(io.StringIO(render_csv(rows))))
    assert cells["pkg_name"] == '\'=HYPERLINK("x")'
    assert cells["workload"] == "'-cmd" and cells["team"] == "'@t" and cells["owner"] == "'\tx"
    assert cells["installed_version"] == "1.0" and cells["image"] == "reg.io/a:1"
    assert json.loads(render_json(rows))[0]["pkg_name"] == '=HYPERLINK("x")'
    assert json.loads(render_sarif(rows))["runs"][0]["results"][0]["message"]["text"].startswith('=HYPERLINK("x")')


def test_render_table_handles_none_cells():
    assert "CVE-1" in render_table([_row(installed_version=None)])


def test_render_table_shows_tag_and_short_digest_but_other_formats_keep_full_ref():
    digest = "sha256:" + "c" * 64
    row = _row(image=f"reg.io/a@{digest}", repo="reg.io/a", tag="1.19", digest=digest)
    out = render_table([row])
    assert "reg.io/a:1.19@sha256:cccccccc" in out and "c" * 9 not in out
    assert "reg.io/a@sha256:cccccccc" in render_table([row | {"tag": None}])
    assert "reg.io/a:1" in render_table([_row()])  # no digest: repo:tag
    assert json.loads(render_json([row]))[0]["image"] == f"reg.io/a@{digest}"
    assert next(csv.DictReader(io.StringIO(render_csv([row]))))["image"] == f"reg.io/a@{digest}"
    uri = json.loads(render_sarif([row]))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert uri["artifactLocation"]["uri"] == f"reg.io/a@{digest}"


def test_short_image_is_public():
    row = {"repo": "reg.example.com/app", "tag": "1", "digest": "sha256:" + "a" * 64, "image": "ref"}
    assert short_image(row) == "reg.example.com/app:1@sha256:aaaaaaaa"
    assert short_image({"repo": "", "image": "ref"}) == "ref"
