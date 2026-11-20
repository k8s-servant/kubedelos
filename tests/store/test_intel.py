from datetime import UTC, date, datetime

import pytest

from kubedelos.models import Workload
from kubedelos.risk import Intel
from kubedelos.store import intel
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo
from tests.mcp_server.conftest import add_workloads, make_facts, new_run

FETCHED = datetime(2026, 11, 20, 8, 0, tzinfo=UTC)


@pytest.fixture
def conn(tmp_path):
    conn = connect(tmp_path / "kubedelos.db")
    yield conn
    conn.close()


def _store_intel(conn):
    conn.executemany(
        "INSERT INTO threat_intel (vuln_id, kev, kev_added, epss, epss_percentile) VALUES (?, ?, ?, ?, ?)",
        [
            ("CVE-2024-0001", 1, "2024-01-10", 0.97, 0.999),
            ("CVE-2024-0002", 1, None, None, None),
            ("CVE-2024-0003", 0, None, 0.001, 0.1),
        ],
    )
    conn.commit()


def _store_feed(conn, name="kev"):
    conn.execute(
        "INSERT INTO threat_feed (name, fetched_at, version, rows) VALUES (?, ?, ?, ?)",
        (name, FETCHED.isoformat(), "v1", 3),
    )
    conn.commit()


def test_intel_for_returns_intel_for_stored_ids(conn):
    _store_intel(conn)
    got = intel.intel_for(conn, ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2099-0001", "CVE-2024-0001"])
    assert got == {
        "CVE-2024-0001": Intel(kev=True, kev_added=date(2024, 1, 10), epss=0.97, percentile=0.999),
        "CVE-2024-0002": Intel(kev=True, kev_added=None, epss=None, percentile=None),
        "CVE-2024-0003": Intel(kev=False, kev_added=None, epss=0.001, percentile=0.1),
    }
    assert intel.intel_for(conn, []) == {}


def test_intel_for_reads_many_ids(conn):
    _store_intel(conn)
    ids = [f"CVE-2000-{n:05d}" for n in range(5000)] + ["CVE-2024-0003"]
    assert set(intel.intel_for(conn, iter(ids))) == {"CVE-2024-0003"}


def test_feeds_gives_each_fetched_feed(conn):
    assert intel.feeds(conn) == {}
    _store_feed(conn, "kev")
    _store_feed(conn, "epss")
    assert intel.feeds(conn) == {"kev": FETCHED, "epss": FETCHED}


def test_risk_shown_needs_facts_or_feeds(tmp_path):
    conn = connect(tmp_path / "kubedelos.db")
    repo = Repo(conn)
    web = Workload(namespace="web", kind="Deployment", name="site", container="c")
    bare = new_run(repo, "my-cluster")
    add_workloads(repo, bare, "img-a", [web])
    with_facts = new_run(repo, "my-cluster")
    add_workloads(repo, with_facts, "img-a", [web], facts={web: make_facts()})
    try:
        assert intel.run_has_facts(conn, bare) is False
        assert intel.risk_shown(conn, bare) is False
        assert intel.run_has_facts(conn, with_facts) is True
        assert intel.risk_shown(conn, with_facts) is True
        assert intel.run_has_facts(conn, 999) is False
        _store_feed(conn)
        assert intel.risk_shown(conn, bare) is True
    finally:
        conn.close()


def test_run_has_facts_uses_the_indexes(conn):
    plan = " ".join(row[3] for row in conn.execute(f"EXPLAIN QUERY PLAN {intel.RUN_HAS_FACTS_SQL}", {"run": 1}))
    assert "idx_image_result_run" in plan and "idx_workload_image_result" in plan
    assert "SCAN" not in plan.replace("SCAN CONSTANT ROW", "")
