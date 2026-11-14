"""The UI's performance rule: indexed query plans, and every page under 300 ms on a 100,000-finding database.

The plan test runs by default on a small seed: ``EXPLAIN QUERY PLAN`` does not need the large data to show a full table
scan. The timing test is marked ``perf`` (deselected by default) because it seeds two runs of 100,000 findings.
"""

import re
import statistics
import time

import pytest
from fastapi.testclient import TestClient

from kubedelos.store import queries
from kubedelos.store.db import connect
from kubedelos.web.app import create_app
from tests.web.conftest import BASE_URL, PORT, TOKEN
from tests.web.seed import CONTEXT, seed_large

BUDGET = 0.3
SORTS = ("severity", "cve", "package", "image", "namespace", "fixed")
# A full pass over a big table, also through a covering index. The queries alias these tables as f, r and w.
FULL_SCAN = re.compile(r"^SCAN (finding|image_result|workload|scan_run|f|r|w)\b")
REACHED = re.compile(r"^SEARCH (finding|f) ")
KEYED = re.compile(r"\(image_result_id=")
PRIOR_RUNS = 4  # earlier runs that share the CVEs, so a lookup that reads every run's rows shows in the plan


def _plans(conn, call) -> list[str]:
    """The ``EXPLAIN QUERY PLAN`` detail lines of every statement ``call`` runs on ``conn``."""
    statements: list[str] = []
    conn.set_trace_callback(statements.append)
    try:
        call()
    finally:
        conn.set_trace_callback(None)
    return [row[3] for sql in statements for row in conn.execute(f"EXPLAIN QUERY PLAN {sql}")]


def test_query_plans_use_indexes(tmp_path):
    conn = connect(tmp_path / "small.db")
    for _ in range(PRIOR_RUNS):
        seed_large(conn, images=40, findings=2000, namespaces=5)
    run_id = seed_large(conn, images=40, findings=2000, namespaces=5)
    run = queries.newest_run(conn, CONTEXT, cluster_scope=True)
    calls = {
        "newest_run": lambda: queries.newest_run(conn, CONTEXT, cluster_scope=True),
        "previous_comparable": lambda: queries.previous_comparable(conn, run),
        "kpis": lambda: queries.kpis(conn, run_id),
        "fix_by_fix": lambda: queries.fix_by_fix(conn, run_id),
        "fix_by_image": lambda: queries.fix_by_image(conn, run_id),
        "findings_page": lambda: queries.findings_page(conn, run_id, queries.FindingFilter(), 2, per_page=10),
        "findings_page q": lambda: queries.findings_page(conn, run_id, queries.FindingFilter(q="lib"), 1),
        "failed_images": lambda: queries.failed_images(conn, run_id),
        "run_namespaces": lambda: queries.run_namespaces(conn, run_id),
    }
    offenders = {}
    for name, call in calls.items():
        plan = _plans(conn, call)
        assert plan, name
        bad = [line for line in plan if FULL_SCAN.match(line)]
        # Findings are found through the run's image rows only: a CVE or severity index would read the matching rows of
        # every run kept, so the page would slow down as history grows.
        bad += [line for line in plan if REACHED.match(line) and not KEYED.search(line)]
        if bad:
            offenders[name] = bad
    conn.close()
    assert not offenders


def _median(client: TestClient, path: str) -> float:
    times = []
    for _ in range(3):
        start = time.perf_counter()
        response = client.get(path)
        times.append(time.perf_counter() - start)
        assert response.status_code == 200, path
    return statistics.median(times)


@pytest.mark.perf
def test_pages_under_300ms(settings):
    conn = connect(settings.db_path)
    for _ in range(PRIOR_RUNS):  # earlier comparable runs: the dashboard computes deltas and history is not free
        seed_large(conn)
    run_id = seed_large(conn)
    _, total = queries.findings_page(conn, run_id, queries.FindingFilter(), 1)
    conn.close()
    last = -(-total // 100)
    middle = (last + 1) // 2
    pages = ["/", "/?by=image", "/findings", "/findings?q=lib&sort=package", f"/findings?page={last}"]
    pages += [f"/findings?sort={s}&dir={d}&page={middle}" for s in SORTS for d in ("asc", "desc")]
    app = create_app(settings, context=CONTEXT, token=TOKEN, port=PORT)
    with TestClient(app, base_url=BASE_URL) as client:
        assert client.get(f"/?token={TOKEN}", follow_redirects=False).status_code == 303
        for path in pages:
            client.get(path)  # warm the page cache and the templates
        timings = {path: _median(client, path) for path in pages}
    report = ", ".join(f"{path} {seconds * 1000:.0f} ms" for path, seconds in timings.items())
    assert all(seconds < BUDGET for seconds in timings.values()), report
