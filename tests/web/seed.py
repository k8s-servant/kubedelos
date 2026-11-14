"""A fast, deterministic seeder for the performance tests: one large whole-cluster run written with ``executemany``.

``Repo`` inserts one image at a time inside its own transaction, which is far too slow for 100,000 findings, so this
writes the rows directly. Everything is derived from the row indexes, so two calls build two identical, comparable runs
(the second one sees the first as its previous run).
"""

import sqlite3
from datetime import UTC, datetime, timedelta

from kubedelos.config import Settings

CONTEXT = "my-cluster"
# Half of the rows are Critical or High: the pessimistic mix, where the fix lists have the most units to group.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
VULNS = 6000  # distinct CVE ids; each one always comes with the same package, so fix rows span many images
PACKAGES = 600
DUPLICATED_PLATFORMS = 10
FAILED_PERCENT = 2

_START = datetime(2026, 1, 1, tzinfo=UTC)


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


def seed_large(conn: sqlite3.Connection, *, images: int = 1000, findings: int = 100_000, namespaces: int = 50) -> int:
    """Write one ``ok`` whole-cluster run of ``images`` images and ``findings`` finding rows; return its id."""
    run_count = conn.execute("SELECT COUNT(*) FROM scan_run").fetchone()[0]
    finished = (_START + timedelta(hours=run_count + 1)).isoformat()
    with conn:
        run_id = conn.execute(
            "INSERT INTO scan_run (started_at, finished_at, status, context, trigger, trivy_version, pkg_types, scope)"
            " VALUES (?, ?, 'ok', ?, 'cli', '0.76.1', 'library,os', ?)",
            (finished, finished, CONTEXT, Settings().scope),
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
                workload_rows.append(
                    (result_id, f"ns-{(image + j * 17) % namespaces:02}", "Deployment", f"app{image}", "main")
                )
            if error:
                continue
            count = per_image + (k < extra)
            finding_rows.extend((result_id, *_finding(image, i, per_image)) for i in range(count))
        conn.executemany(
            "INSERT INTO workload (image_result_id, namespace, kind, name, container) VALUES (?, ?, ?, ?, ?)",
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
