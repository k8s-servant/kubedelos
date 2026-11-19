"""Shared helpers for the MCP server tests: a fixed clock, and seeding of a database the way a scan would leave it."""

from datetime import UTC, datetime, timedelta

import pytest

from kubedelos.config import Settings
from kubedelos.kube.inventory import InventoryWarning
from kubedelos.models import (
    Exposure,
    Finding,
    ImageRef,
    ImageResult,
    InventoryItem,
    Network,
    PodSecurity,
    Rights,
    Severity,
    Workload,
    WorkloadFacts,
)
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo

NOW = datetime(2026, 2, 1, tzinfo=UTC)


@pytest.fixture
def anyio_backend():
    return "asyncio"


class Clock:
    def __init__(self, start):
        self.now = start

    def __call__(self):
        self.now += timedelta(minutes=1)
        return self.now


def seed(path, contexts):
    """One finished whole-cluster run per context; ``contexts`` maps a name to the day its run started."""
    conn = connect(path)
    for name, day in contexts.items():
        repo = Repo(conn, clock=Clock(datetime(2026, 1, day, tzinfo=UTC)))
        run_id = repo.start_run(name, "cli", "0.76.1", scan_level="library,os", scope=Settings().scope)
        repo.finish_run(run_id, "ok")
    conn.close()


def new_run(repo, context, status="ok", *, scope=None):
    """Start a run (whole-cluster unless ``scope`` is given) and finish it with ``status``, unless it is running."""
    run_id = repo.start_run(context, "cli", "0.76.1", scan_level="library,os", scope=scope or Settings().scope)
    if status != "running":
        repo.finish_run(run_id, status)
    return run_id


def finding(vuln, severity, pkg="openssl", fixed="1.2"):
    return Finding(
        vuln_id=vuln,
        pkg_name=pkg,
        installed_version="1.1",
        fixed_version=fixed,
        severity=Severity(severity),
        target="os",
        pkg_type="os",
    )


def add_image(repo, run_id, ref, findings=(), namespaces=("ns",), *, status="ok", error_kind=None):
    image = ImageRef(ref=ref, repo="reg.example.com/app", tag="1", digest="sha256:" + "a" * 64)
    workloads = [Workload(namespace=ns, kind="Deployment", name="a", container="c") for ns in namespaces]
    item = InventoryItem(image=image, platform="linux/amd64", workloads=workloads)
    result = ImageResult(
        image=image, platform="linux/amd64", status=status, findings=list(findings), error_kind=error_kind, error="x"
    )
    repo.add_result(run_id, item, result)


def add_gap(repo, run_id, text):
    repo.add_warnings(run_id, [InventoryWarning(text=text, coverage=True)])


def make_facts(*, root=True, level="none"):
    """Facts that differ by ``root`` and ``level``, so a test can tell which workload's facts it got back."""
    return WorkloadFacts(
        pod=PodSecurity(
            privileged=False, allow_privilege_escalation=False, runs_as_root=root, read_only_root_fs=True,
            host_network=False, host_pid=False, host_ipc=False, service_account="default", automount_token=None,
        ),
        exposure=Exposure(level=level),
        network=Network(ingress_isolated=False, egress_isolated=None),
        rights=Rights(status="off"),
    )  # fmt: skip


def add_workloads(repo, run_id, ref, workloads, findings=(), facts=None, *, status="ok"):
    """Add one image run by ``workloads`` (``Workload`` objects); ``facts`` maps some of them to ``WorkloadFacts``."""
    image = ImageRef(ref=ref, repo="reg.example.com/app", tag="1", digest="sha256:" + "a" * 64)
    item = InventoryItem(image=image, platform="linux/amd64", workloads=list(workloads), facts=facts or {})
    result = ImageResult(image=image, platform="linux/amd64", status=status, findings=list(findings))
    repo.add_result(run_id, item, result)
