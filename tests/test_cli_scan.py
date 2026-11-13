import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kubedelos import cli
from kubedelos.config import Settings
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.scan.service import ScanOutcome
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo

D = "sha256:" + "a" * 64


def _item(ref):
    return InventoryItem(
        image=ImageRef(ref=ref, repo=ref.split(":")[0], tag="1", digest=D),
        platform="linux/amd64",
        workloads=[Workload(namespace="prod", kind="Deployment", name="api", container="c")],
    )


def _finding(vid, sev):
    return Finding(vuln_id=vid, pkg_name="p", installed_version="1", severity=sev, target="t", pkg_type="os")


@pytest.fixture
def make_run(tmp_path, monkeypatch):
    monkeypatch.setenv("KUBEDELOS_DATA_DIR", str(tmp_path / "data"))
    seen = {}

    def build(findings, *, error=False, status=None, raises=None, warnings=()):
        repo = Repo(connect(Settings().db_path))
        run_id = repo.start_run("ctx", "cli", "0.76.1")
        item = _item("reg.io/a:1")
        repo.add_result(
            run_id, item, ImageResult(image=item.image, platform="linux/amd64", status="ok", findings=findings)
        )
        if error:
            bad = _item("reg.io/b:1")
            repo.add_result(
                run_id,
                bad,
                ImageResult(image=bad.image, platform="linux/amd64", status="error", error_kind="auth", error="x"),
            )
        repo.finish_run(run_id, status or ("partial" if error else "ok"))

        def fake_run_scan(settings, **kw):
            seen["settings"] = settings
            seen["kw"] = kw
            if raises:
                raise raises
            return ScanOutcome(run_id=run_id, warnings=list(warnings))

        monkeypatch.setattr(cli, "run_scan", fake_run_scan)

    build.seen = seen
    return build


def _run(*args):
    return CliRunner().invoke(cli.app, ["scan", *args])


@pytest.mark.parametrize(
    ("fail_on", "error", "code"),
    [("none", False, 0), ("high", False, 1), ("high", True, 2), ("none", True, 0), ("critical", False, 1)],
)
def test_cli_scan_exit_codes(make_run, fail_on, error, code):
    make_run([_finding("CVE-1", Severity.CRITICAL)], error=error)
    r = _run("--fail-on", fail_on)
    assert r.exit_code == code
    if error:
        assert "1 image(s) failed to scan" in r.stderr


def test_fail_on_uses_all_findings_not_filtered(make_run):
    make_run([_finding("CVE-1", Severity.MEDIUM)])
    r = _run("--fail-on", "medium", "--severity", "CRITICAL", "-o", "json")
    assert r.exit_code == 1
    assert json.loads(r.stdout) == []


def test_fail_on_below_threshold_passes(make_run):
    make_run([_finding("CVE-1", Severity.LOW)])
    assert _run("--fail-on", "high").exit_code == 0


def test_cli_scan_severity_filter(make_run):
    make_run(
        [_finding("CVE-C", Severity.CRITICAL), _finding("CVE-M", Severity.MEDIUM), _finding("CVE-H", Severity.HIGH)]
    )
    default = json.loads(_run("-o", "json").stdout)
    assert {f["vuln_id"] for f in default} == {"CVE-C", "CVE-H"}
    only = json.loads(_run("-o", "json", "--severity", "medium").stdout)
    assert [f["vuln_id"] for f in only] == ["CVE-M"]
    bad = _run("--severity", "bogus")
    assert bad.exit_code == 2


def test_flags_build_settings(make_run, monkeypatch):
    monkeypatch.setenv("KUBEDELOS_PARALLELISM", "7")
    make_run([])
    r = _run("-n", "a", "-n", "b", "--exclude-namespace", "kube-system", "--context", "c1", "--no-cache")
    assert r.exit_code == 0
    s = make_run.seen["settings"]
    assert s.namespaces == ["a", "b"] and s.exclude_namespaces == ["kube-system"] and s.context == "c1"
    assert s.parallelism == 7  # env still applies when the flag is not passed
    assert make_run.seen["kw"]["cache_max_age"].total_seconds() == 0


def test_cancelled_and_fatal(make_run):
    make_run([], raises=KeyboardInterrupt())
    r = _run()
    assert r.exit_code == 130 and "cancelled" in r.stderr
    make_run([], raises=RuntimeError("no kubeconfig"))
    r = _run()
    assert r.exit_code == 2 and "error: no kubeconfig" in r.stderr and "Traceback" not in r.stderr
    make_run([], status="cancelled")
    assert _run().exit_code == 130


def test_warnings_and_output_file(make_run, tmp_path):
    make_run([_finding("CVE-1", Severity.CRITICAL)], warnings=["namespace x forbidden"])
    out = Path(tmp_path / "o.sarif")
    r = _run("-o", "sarif", "--output-file", str(out))
    assert r.exit_code == 0
    assert "warning: namespace x forbidden" in r.stderr
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert r.stdout == ""


def test_unwritable_output_file_is_fatal_exit_2(make_run, tmp_path):
    make_run([_finding("CVE-1", Severity.CRITICAL)])
    r = _run("-o", "json", "--output-file", str(tmp_path / "missing-dir" / "o.json"), "--fail-on", "high")
    assert r.exit_code == 2
    assert "error: cannot write" in r.stderr and "Traceback" not in r.stderr
