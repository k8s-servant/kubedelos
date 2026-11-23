"""A fast, deterministic seeder for the performance tests: one large whole-cluster run written with ``executemany``.

``Repo`` inserts one image at a time inside its own transaction, which is far too slow for 100,000 findings, so this
writes the rows directly. Everything is derived from the row indexes, so two calls build two identical, comparable runs
(the second one sees the first as its previous run).

``seed_large(..., facts=True)`` also writes attack-surface facts and ``risk_points`` on every workload row, and
``seed_intel`` fills ``threat_intel`` to the real feeds' size, so the timed pages show the risk score.
"""

import sqlite3
from datetime import UTC, datetime, timedelta

from kubedelos import risk
from kubedelos.config import Settings
from kubedelos.models import Exposure, HostPath, Network, PodSecurity, Rights, WorkloadFacts

CONTEXT = "my-cluster"
# Half of the rows are Critical or High: the pessimistic mix, where the fix lists have the most units to group.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
VULNS = 6000  # distinct CVE ids; each one always comes with the same package, so fix rows span many images
PACKAGES = 600
DUPLICATED_PLATFORMS = 10
FAILED_PERCENT = 2

_START = datetime(2026, 1, 1, tzinfo=UTC)


def _pod(**changes) -> PodSecurity:
    base = {
        "privileged": False, "allow_privilege_escalation": False, "runs_as_root": False, "read_only_root_fs": True,
        "host_network": False, "host_pid": False, "host_ipc": False, "service_account": "default",
        "automount_token": None,
    }  # fmt: skip
    return PodSecurity(**base | changes)


# A mix of exposure levels, host access and rights, so the risk sort has many distinct scores to order.
_FACTS = (
    WorkloadFacts(
        pod=_pod(), exposure=Exposure(level="external"), network=Network(ingress_isolated=False, egress_isolated=None),
        rights=Rights(status="ok", reads_secrets=True, reads_secrets_scope="cluster"),
    ),
    WorkloadFacts(
        pod=_pod(runs_as_root=None), exposure=Exposure(level="cluster"),
        network=Network(ingress_isolated=True, egress_isolated=None), rights=Rights(status="ok"),
    ),
    WorkloadFacts(
        pod=_pod(privileged=True, host_path_volumes=(HostPath(path="/var/run", read_only=False),)),
        exposure=Exposure(level="cluster"), network=Network(ingress_isolated=False, egress_isolated=None),
        rights=Rights(status="partial", pod_exec=True),
    ),
    WorkloadFacts(
        pod=_pod(automount_token=False), exposure=Exposure(level="none"),
        network=Network(ingress_isolated=None, egress_isolated=None), rights=Rights(status="off"),
    ),
    WorkloadFacts(
        pod=_pod(runs_as_root=True, added_capabilities=("NET_ADMIN",)), exposure=Exposure(level="unknown"),
        network=Network(ingress_isolated=None, egress_isolated=None), rights=Rights(status="unknown"),
    ),
)  # fmt: skip
_FACTS_ROWS = tuple((facts.model_dump_json(), risk.workload_points(facts)) for facts in _FACTS)


def _finding(image: int, i: int, per_image: int) -> tuple:
    n = image * per_image + i
    vuln = (image * 31 + i * 7) % VULNS  # 7 is prime to VULNS, so an image never repeats a CVE
    pkg = vuln % PACKAGES
    library = pkg % 2 == 0
    name = f"lib{pkg}" if library else f"pkg{pkg}"
    fixed = f"2.{vuln % 9}" if vuln % 10 < 4 else None  # 40% of the findings have a fix
    return (
        f"CVE-2026-{vuln:05}",
        name,
        f"1.{image % 7}",
        fixed,
        SEVERITIES[n % len(SEVERITIES)],
        f"A flaw in {name} lets a remote attacker do something unwelcome",
        f"https://example.com/vuln/CVE-2026-{vuln:05}",
        "app/requirements.txt" if library else "reg.example.com/app (debian 12)",
        "python-pkg" if library else "debian",
        "library" if library else "os",
    )


def seed_large(
    conn: sqlite3.Connection, *, images: int = 1000, findings: int = 100_000, namespaces: int = 50, facts: bool = False
) -> int:
    """Write one ``ok`` whole-cluster run of ``images`` images and ``findings`` finding rows; return its id.

    ``facts`` writes facts and ``risk_points`` on every workload row, cycling through a mix of exposure levels.
    """
    run_count = conn.execute("SELECT COUNT(*) FROM scan_run").fetchone()[0]
    finished = (_START + timedelta(hours=run_count + 1)).isoformat()
    with conn:
        run_id = conn.execute(
            "INSERT INTO scan_run (started_at, finished_at, status, cluster, context, trigger, trivy_version, pkg_types,"
            " scope, number) VALUES (?, ?, 'ok', ?, ?, 'cli', '0.76.1', 'library,os', ?, ?)",
            (finished, finished, CONTEXT, CONTEXT, Settings().scope, run_count + 1),
        ).lastrowid
        failed = images * FAILED_PERCENT // 100
        ok = images - failed
        # (image index, platform) rows with findings: every ok image on amd64, the first few again on arm64 with the
        # same findings. The failed images follow, without findings.
        targets = [(i, "linux/amd64") for i in range(ok)] + [(i, "linux/arm64") for i in range(DUPLICATED_PLATFORMS)]
        per_image, extra = divmod(findings, len(targets))
        finding_rows: list[tuple] = []
        workload_rows: list[tuple] = []
        for k, (image, platform) in enumerate(targets + [(i, "linux/amd64") for i in range(ok, images)]):
            error = image >= ok
            ref = f"reg.example.com/team{image % 20}/app{image}:1.{image % 7}"
            result_id = conn.execute(
                "INSERT INTO image_result (run_id, image_key, ref, repo, tag, digest, platform, status, error_kind,"
                " error, os_family) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id, ref, ref, f"reg.example.com/team{image % 20}/app{image}", f"1.{image % 7}",
                    f"sha256:{image:064x}", platform, "error" if error else "ok",
                    ("auth" if image % 2 else "timeout") if error else None,
                    ("UNAUTHORIZED: authentication required" if image % 2 else "context deadline exceeded")
                    if error else None,
                    None if error else "debian",
                ),
            ).lastrowid  # fmt: skip
            for j in range(1 + image % 3):
                surface = _FACTS_ROWS[(image + j) % len(_FACTS_ROWS)] if facts else (None, None)
                workload_rows.append(
                    (result_id, f"ns-{(image + j * 17) % namespaces:02}", "Deployment", f"app{image}", "main", *surface)
                )
            if error:
                continue
            count = per_image + (k < extra)
            finding_rows.extend((result_id, *_finding(image, i, per_image)) for i in range(count))
        conn.executemany(
            "INSERT INTO workload (image_result_id, namespace, kind, name, container, facts, risk_points)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            workload_rows,
        )
        conn.executemany(
            "INSERT INTO finding (image_result_id, vuln_id, pkg_name, installed_version, fixed_version, severity,"
            " title, primary_url, target, pkg_type, pkg_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            finding_rows,
        )
        conn.execute(
            "UPDATE scan_run SET images_total = (SELECT COUNT(*) FROM image_result WHERE run_id = :id),"
            " images_error = (SELECT COUNT(*) FROM image_result WHERE run_id = :id AND status = 'error') WHERE id = :id",
            {"id": run_id},
        )
    return int(run_id)


ACCEPTANCES = 50


def seed_acceptances(conn: sqlite3.Connection, count: int = ACCEPTANCES) -> None:
    """``count`` active acceptances of the seed's CVEs: a third anywhere, a third in one namespace, a third on one image."""
    rows = []
    for i in range(count):
        vuln = f"CVE-2026-{i * 7:05}"
        namespace = f"ns-{i % 50:02}" if i % 3 == 1 else None
        repo = f"reg.example.com/team{i % 20}/app{i}" if i % 3 == 2 else None
        rows.append(
            (
                vuln,
                CONTEXT if i % 2 else None,
                CONTEXT if i % 2 else None,
                namespace,
                repo,
                "seeded",
                "me",
                "2099-01-01",
                _START.isoformat(),
            )
        )
    with conn:
        conn.executemany(
            "INSERT INTO acceptance (vuln_id, cluster, context, namespace, repo, reason, owner, expires_at, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )


INTEL_FILLER = 400_000  # with the 6,000 seeded CVEs, about the real feed (409,087 EPSS rows on 2026-11-20)


def seed_intel(conn: sqlite3.Connection, filler: int = INTEL_FILLER) -> None:
    """Feed rows the size of the real feeds: EPSS for every seeded CVE, KEV for 1% of them, plus ``filler`` other CVEs
    (EPSS only), and a ``threat_feed`` row for each feed."""
    seeded = [
        (f"CVE-2026-{vuln:05}", int(vuln % 100 == 0), "2026-01-01" if vuln % 100 == 0 else None, epss, epss)
        for vuln in range(VULNS)
        for epss in ((vuln % 97) / 96,)
    ]
    other = [(f"CVE-2019-{n:06}", 0, None, (n % 1000) / 1000, (n % 1000) / 1000) for n in range(filler)]
    fetched = _START.isoformat()
    with conn:
        conn.executemany(
            "INSERT INTO threat_intel (vuln_id, kev, kev_added, epss, epss_percentile) VALUES (?, ?, ?, ?, ?)",
            seeded + other,
        )
        conn.executemany(
            "INSERT INTO threat_feed (name, fetched_at, version, rows) VALUES (?, ?, NULL, ?)",
            (("kev", fetched, VULNS // 100), ("epss", fetched, len(seeded) + len(other))),
        )
