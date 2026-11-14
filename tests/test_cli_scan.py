import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from kubedelos import cli
from kubedelos.config import Settings
from kubedelos.kube.inventory import InventoryWarning, collect
from kubedelos.models import Finding, ImageRef, ImageResult, InventoryItem, Severity, Workload
from kubedelos.scan.service import ScanOutcome
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo
from tests.kube.fakes import FakeKubeApi, pod

D = "sha256:" + "a" * 64
FAKE_TRIVY = Path(__file__).parent / "trivy" / "fake_trivy.py"


def _item(ref):
    return InventoryItem(
        image=ImageRef(ref=ref, repo=ref.split(":")[0], tag="1", digest=D),
        platform="linux/amd64",
        workloads=[Workload(namespace="prod", kind="Deployment", name="api", container="c")],
    )


def _finding(vid, sev):
    return Finding(vuln_id=vid, pkg_name="p", installed_version="1", severity=sev, target="t", pkg_type="os")


class FakeApi:
    def current_context(self):
        return "my-cluster"


@pytest.fixture
def make_run(tmp_path, monkeypatch):
    monkeypatch.setenv("KUBEDELOS_DATA_DIR", str(tmp_path / "data"))
    seen = {}

    def build(findings, *, error=False, error_msg="x", status=None, raises=None, warnings=(), failures=()):
        with contextlib.closing(connect(Settings().db_path)) as conn:
            repo = Repo(conn)
            run_id = repo.start_run("ctx", "cli", "0.76.1", scan_level="library,os")
            item = _item("reg.io/a:1")
            repo.add_result(
                run_id, item, ImageResult(image=item.image, platform="linux/amd64", status="ok", findings=findings)
            )
            if error:
                bad = _item("reg.io/b:1")
                result = ImageResult(
                    image=bad.image, platform="linux/amd64", status="error", error_kind="auth", error=error_msg
                )
                repo.add_result(run_id, bad, result)
            for ref, kind in failures:  # (ref, error_kind) of more failed images
                failed = InventoryItem(
                    image=ImageRef(ref=ref, repo=ref.rsplit(":", 1)[0], tag="1"), platform="linux/amd64"
                )
                repo.add_result(
                    run_id,
                    failed,
                    ImageResult(image=failed.image, platform="linux/amd64", status="error", error_kind=kind, error="x"),
                )
            repo.finish_run(run_id, status or ("partial" if error or failures else "ok"))

        def fake_run_scan(settings, **kw):
            seen["settings"] = settings
            seen["kw"] = kw
            if raises:
                raise raises
            return ScanOutcome(run_id=run_id, warnings=list(warnings))

        monkeypatch.setattr(cli, "run_scan", fake_run_scan)
        monkeypatch.setattr(cli.kube_client, "load", lambda settings: FakeApi())

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


def test_scan_prints_one_auth_hint_per_host(make_run):
    make_run(
        [],
        failures=[
            ("registry.example/team/a:1", "auth"),
            ("registry.example/team/b:1", "auth"),
            ("other.example/c:1", "auth"),
        ],
    )
    r = _run()
    hints = [line for line in r.stderr.splitlines() if line.startswith("hint: ")]
    assert len(hints) == 2
    assert "docker login other.example" in hints[0]
    assert "docker login registry.example" in hints[1]


def test_scan_no_hint_without_auth_errors(make_run):
    make_run([], failures=[("registry.example/team/a:1", "not_found")])
    r = _run()
    assert "error: registry.example/team/a:1" in r.stderr
    assert "hint:" not in r.stderr


def test_fail_on_uses_all_findings_not_filtered(make_run):
    make_run([_finding("CVE-1", Severity.MEDIUM), _finding("CVE-2", Severity.LOW)])
    r = _run("--fail-on", "low", "--severity", "CRITICAL", "-o", "json")
    assert r.exit_code == 1
    assert json.loads(r.stdout) == []
    assert "2 finding(s) at or above --fail-on are hidden by --severity" in r.stderr


def test_no_hidden_line_when_the_gate_fires_on_shown_findings(make_run):
    make_run([_finding("CVE-1", Severity.CRITICAL)])
    r = _run("--fail-on", "high")
    assert r.exit_code == 1 and "hidden by --severity" not in r.stderr


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


GAP = InventoryWarning("skipped namespace x: forbidden", coverage=True)
INFO = InventoryWarning("cannot list nodes: HTTP 403; assuming a default platform", coverage=False)


def test_warnings_and_output_file(make_run, tmp_path):
    make_run([_finding("CVE-1", Severity.CRITICAL)], warnings=[GAP])
    out = Path(tmp_path / "o.sarif")
    r = _run("-o", "sarif", "--output-file", str(out))
    assert r.exit_code == 0
    assert "warning: skipped namespace x: forbidden" in r.stderr
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert r.stdout == ""


def test_unwritable_output_file_is_fatal_exit_2(make_run, tmp_path):
    make_run([_finding("CVE-1", Severity.CRITICAL)])
    r = _run("-o", "json", "--output-file", str(tmp_path / "missing-dir" / "o.json"), "--fail-on", "high")
    assert r.exit_code == 2
    assert "error: cannot write" in r.stderr and "Traceback" not in r.stderr


@pytest.mark.parametrize(
    ("args", "code"),
    [(["--fail-on", "high"], 2), (["--fail-on", "high", "--allow-partial"], 1), ([], 0)],
)
def test_inventory_warnings_fail_closed(make_run, args, code):
    make_run([_finding("CVE-1", Severity.CRITICAL)], warnings=[GAP])
    r = _run(*args)
    assert r.exit_code == code
    assert "warning: skipped namespace x: forbidden" in r.stderr
    reason = "error: inventory incomplete (1 namespaces/resources skipped); pass --allow-partial to accept"
    assert (reason in r.stderr) == (code == 2)


def test_warnings_without_findings_and_allow_partial_is_clean(make_run):
    make_run([], warnings=[GAP])
    assert _run("--fail-on", "high", "--allow-partial").exit_code == 0
    assert _run("--fail-on", "high").exit_code == 2


def test_informational_warnings_do_not_fail_closed(make_run):
    make_run([], warnings=[INFO])
    r = _run("--fail-on", "high")
    assert r.exit_code == 0
    assert "warning: cannot list nodes" in r.stderr and "inventory incomplete" not in r.stderr


def test_namespace_scoped_identity_can_pass_or_fail_on_findings(make_run):
    api = FakeKubeApi(pods={"team": [pod("p", "team")]}, namespaces_forbidden=True, nodes_forbidden=True)
    _, warnings = collect(api, Settings(namespaces=["team"]))
    make_run([_finding("CVE-1", Severity.CRITICAL)], warnings=warnings)
    assert _run("-n", "team", "--fail-on", "high").exit_code == 1


def test_skipped_namespace_still_exits_2(make_run):
    api = FakeKubeApi(namespaces=[], pods={"team": [pod("p", "team")]}, forbidden={"team"}, namespaces_forbidden=True)
    _, warnings = collect(api, Settings(namespaces=["team"]))
    make_run([_finding("CVE-1", Severity.CRITICAL)], warnings=warnings)
    r = _run("-n", "team", "--fail-on", "high")
    assert r.exit_code == 2
    assert "inventory incomplete (1 namespaces/resources skipped)" in r.stderr


def test_scan_names_the_context_and_passes_the_api(make_run):
    make_run([])
    r = _run()
    assert r.exit_code == 0
    assert "scanning context my-cluster" in r.stderr
    assert isinstance(make_run.seen["kw"]["api"], FakeApi)


def test_failed_images_listed_on_stderr(make_run):
    make_run([], error=True, error_msg="UNAUTHORIZED: authentication required " + "y" * 300 + "\nsecond line")
    r = _run()
    assert r.exit_code == 0
    line = next(x for x in r.stderr.splitlines() if x.startswith("error: reg.io/b:1"))
    detail = line.removeprefix("error: reg.io/b:1 [linux/amd64] auth: ")
    assert detail.startswith("\u2026y")  # the end of the message is kept: that is where the cause is
    assert detail.endswith("y second line")
    assert len(detail) <= 300
    assert "1 image(s) failed to scan" in r.stderr


def test_sigterm_and_sighup_become_keyboard_interrupt_and_handlers_are_restored():
    before = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGHUP)}
    for sig in before:
        with pytest.raises(KeyboardInterrupt), cli._signals_as_interrupt():
            os.kill(os.getpid(), sig)
            time.sleep(5)  # the handler interrupts this
    assert {sig: signal.getsignal(sig) for sig in before} == before


_SIGTERM_SCRIPT = """
import os, signal, sys, threading, time
from pathlib import Path
from kubedelos import cli
from kubedelos.config import Settings
from kubedelos.models import ImageRef, InventoryItem
from kubedelos.trivy.runner import scan_many
trivy, tmp = Path(sys.argv[1]), Path(sys.argv[2])
pid_file = tmp / "scan.pid"
def kill_once_scanning():
    while not pid_file.exists():
        time.sleep(0.05)
    os.kill(os.getpid(), signal.SIGTERM)
threading.Thread(target=kill_once_scanning, daemon=True).start()
items = [InventoryItem(image=ImageRef(ref=f"registry.example/app:{i}", repo="registry.example/app", tag=str(i)),
                       platform="linux/amd64") for i in range(2)]
try:
    with cli._signals_as_interrupt():
        scan_many(items, cache_dir=tmp, trivy=trivy, settings=Settings(cache_dir=tmp, parallelism=1),
                  on_result=lambda r: None, cancel=threading.Event())
except KeyboardInterrupt:
    sys.exit(130)
"""


def _gone(pid):
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def test_sigterm_stops_running_scans(tmp_path):
    pid_file, child_file = tmp_path / "scan.pid", tmp_path / "child.pid"
    env = {
        **os.environ,
        "FAKE_TRIVY_PID_FILE": str(pid_file),
        "FAKE_TRIVY_CHILD_PID_FILE": str(child_file),
        "FAKE_TRIVY_SLEEP": "30",
    }
    proc = subprocess.run(
        [sys.executable, "-c", _SIGTERM_SCRIPT, str(FAKE_TRIVY), str(tmp_path)], env=env, timeout=60, check=False
    )
    assert proc.returncode == 130
    assert _gone(int(pid_file.read_text()))
    assert _gone(int(child_file.read_text()))


def test_cli_scan_pkg_types_passed(make_run):
    make_run([])
    r = _run("--pkg-types", "os")
    assert r.exit_code == 0, r.output
    assert make_run.seen["settings"].pkg_types == ("os",)


def test_cli_scan_pkg_types_rejects_unknown(make_run):
    make_run([])
    r = _run("--pkg-types", "secrets")
    assert r.exit_code == 2
    assert "error: --pkg-types:" in r.stderr


def test_cli_scan_late_validation_error_is_not_named_as_a_flag(make_run):
    with pytest.raises(ValidationError) as late:
        ImageRef(ref="x")  # missing repo: the kind of error odd cluster data could raise mid-scan
    make_run([], raises=late.value)
    r = _run()
    assert r.exit_code == 2
    assert "--repo" not in r.stderr
    assert "error:" in r.stderr


def test_cli_scan_bad_env_value_names_the_variable(make_run, monkeypatch):
    make_run([])  # the fixture reads Settings itself, so break the variable afterwards
    monkeypatch.setenv("KUBEDELOS_PKG_TYPES", "secrets")
    r = _run()
    assert r.exit_code == 2
    assert "error: KUBEDELOS_PKG_TYPES:" in r.stderr
    assert "--pkg-types" not in r.stderr


def test_cli_scan_scope_flags(make_run):
    make_run([])
    r = _run("--namespace-selector", "team=x", "-l", "app=web", "--exclude-image", "a/*", "--exclude-image", "b:*")
    assert r.exit_code == 0, r.output
    s = make_run.seen["settings"]
    assert (s.namespace_selector, s.selector, s.exclude_images) == ("team=x", "app=web", ["a/*", "b:*"])


def test_cli_scan_invalid_selector_exits_2(make_run):
    make_run([], raises=ValueError("invalid label selector 'x(': unable to parse requirement"))
    r = _run("-l", "x(")
    assert r.exit_code == 2
    assert "invalid label selector" in r.stderr


_TRIVY_NO_HOST = (
    "2026-11-14T08:37:11+02:00\tFATAL\tFatal error\trun error: image scan error: scan error: unable to initialize a "
    'scan service: unable to find the specified image "reg.io/b:1" in ["remote"]: 1 error occurred:\n'
    '\t* remote error: Get "https://reg.io/v2/": dial tcp: lookup reg.io: no such host\n\n'
)


def test_failed_image_line_shows_the_trivy_cause(make_run):
    make_run([], error=True, error_msg=_TRIVY_NO_HOST)
    r = _run()
    line = next(x for x in r.stderr.splitlines() if x.startswith("error: reg.io/b:1"))
    assert (
        line
        == 'error: reg.io/b:1 [linux/amd64] auth: remote error: Get "https://reg.io/v2/": dial tcp: lookup reg.io: no such host'
    )


def test_scan_multiline_exception_is_one_line(make_run):
    make_run([], raises=RuntimeError("trivy failed:\n\tsecond\n\nthird"))
    r = _run()
    assert r.exit_code == 2
    assert "error: trivy failed: second third\n" in r.stderr
