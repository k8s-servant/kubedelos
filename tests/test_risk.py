"""The risk score as a pure function: its weights, its ordering guarantees and its SQL twin."""

import itertools
import sqlite3
from datetime import date

import pytest

from kubedelos import risk
from kubedelos.models import Exposure, HostPath, Network, PodSecurity, Rights, WorkloadFacts
from kubedelos.risk import NO_FACTS_POINTS, NO_INTEL, SEVERITY_POINTS, Intel, score, workload_factors, workload_points

SEVERITIES = list(SEVERITY_POINTS)


def facts(
    *,
    level="none",
    isolated=False,
    status="ok",
    automount=True,
    root=False,
    privileged=False,
    caps=(),
    hostpath=None,
    **rights,
):
    return WorkloadFacts(
        pod=PodSecurity(
            privileged=privileged,
            allow_privilege_escalation=False,
            runs_as_root=root,
            read_only_root_fs=True,
            added_capabilities=tuple(caps),
            host_network=False,
            host_pid=False,
            host_ipc=False,
            host_path_volumes=() if hostpath is None else (HostPath(path="/x", read_only=hostpath),),
            service_account="default",
            automount_token=automount,
        ),
        exposure=Exposure(level=level),
        network=Network(ingress_isolated=isolated, egress_isolated=None),
        rights=Rights(status=status, **rights),
    )


def kev(epss=None):
    return Intel(True, date(2026, 11, 18), epss, None)


def epss(value):
    return Intel(False, None, value, None)


def factor(points_of, name):
    return {f.name: f.points for f in points_of}[name]


def test_points_table():
    assert score("LOW", kev(0.9), None).factors[1].points == risk.KEV_POINTS == 25
    for value, expected in [(0.5, 15), (0.1, 8), (0.099, 0), (None, 0)]:
        assert risk.exploit_factor(epss(value)).points == expected
    assert risk.exploit_factor(NO_INTEL).points == 0

    def points(name, f):
        return factor(workload_factors(f), name)

    assert points("exposure", facts(level="external")) == 15
    assert points("exposure", facts(level="cluster", isolated=True)) == 2
    assert points("exposure", facts(level="cluster", isolated=None)) == 5
    assert points("exposure", facts(level="cluster", isolated=False)) == 5
    assert points("exposure", facts(level="none")) == 0
    assert points("exposure", facts(level="unknown")) == 10
    assert points("host", facts(privileged=True)) == 10
    assert points("host", facts(root=None)) == 3
    assert points("host", facts(root=True)) == 3
    assert points("host", facts()) == 0
    assert points("host", facts(privileged=True, root=True)) == 10
    assert points("host", facts(privileged=True, root=None)) == 10
    assert points("rights", facts(cluster_admin=True)) == 10
    assert points("rights", facts(escalates=True)) == 10
    assert points("rights", facts(reads_secrets=True, reads_secrets_scope="cluster")) == 10
    assert points("rights", facts(pod_exec=True)) == 5
    assert points("rights", facts(reads_secrets=True, reads_secrets_scope=("ns",))) == 5
    assert points("rights", facts(status="ok")) == 0
    for flag in ("creates_workloads", "wildcard"):
        assert points("rights", facts(**{flag: True})) == 5
        assert points("rights", facts(automount=False, **{flag: True})) == 0
    assert points("rights", facts(status="partial")) == 5
    assert points("rights", facts(status="unknown")) == 5
    assert points("rights", facts(status="off")) == 5
    assert points("rights", facts(cluster_admin=True, automount=False)) == 0
    assert points("rights", facts(cluster_admin=True, automount=None)) == 10


def test_no_facts_counts_as_unknown():
    assert workload_points(None) == NO_FACTS_POINTS == 18
    assert all("not collected" in f.detail for f in workload_factors(None))


def test_unknown_never_below_known_harmless():
    for level, status, automount in itertools.product(
        ["external", "cluster", "none", "unknown"], ["ok", "partial", "unknown", "off"], [True, None]
    ):
        unknown_exposure = facts(level="unknown", status=status, automount=automount)
        assert workload_points(unknown_exposure) >= workload_points(
            facts(level="none", status=status, automount=automount)
        )
        unknown_rights = facts(level=level, status="unknown", automount=automount)
        assert workload_points(unknown_rights) >= workload_points(facts(level=level, status="ok", automount=automount))
        assert workload_points(None) >= workload_points(facts(root=False)) >= 0


def test_exploited_beats_not_exploited():
    for severity, f in itertools.product(SEVERITIES, [None, facts(level="external"), facts()]):
        kev_points = score(severity, kev(), f).points
        high = score(severity, epss(0.49), f).points
        low = score(severity, epss(0.09), f).points
        assert kev_points > high > low == score(severity, NO_INTEL, f).points


def test_exposure_orders_the_score():
    def at(f):
        return score("HIGH", NO_INTEL, f).points

    order = [
        at(facts(level="external")),
        at(facts(level="cluster", isolated=None)),
        at(facts(level="cluster", isolated=True)),
        at(facts(level="none")),
    ]
    assert order == sorted(order, reverse=True) and len(set(order)) == 4


def test_severity_decides_at_equal_exploit_points():
    ladder = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for lower, upper in itertools.pairwise(ladder):
        for intel in (NO_INTEL, epss(0.2), epss(0.7), kev()):
            assert score(upper, intel, None).points > score(lower, intel, None).points
    assert score("HIGH", epss(0.6), None).points > score("CRITICAL", epss(0.01), None).points


def test_repeatable():
    f = facts(level="external", privileged=True, cluster_admin=True)
    assert score("HIGH", kev(0.3), f) == score("HIGH", kev(0.3), f)


def test_score_is_sum_capped():
    f = facts(level="external", privileged=True, cluster_admin=True)
    result = score("CRITICAL", kev(), f)
    assert [x.name for x in result.factors] == ["severity", "exploited", "exposure", "host", "rights"]
    assert result.points == min(100, sum(x.points for x in result.factors)) == 100
    for severity, intel, each in itertools.product(
        SEVERITIES, [NO_INTEL, kev()], [None, f, facts(root=True, privileged=True)]
    ):
        assert score(severity, intel, each).points <= risk.MAX_SCORE


def test_sql_matches_python():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE ti (id INTEGER PRIMARY KEY, kev INTEGER, epss REAL)")
    rows = [(1, 1, 0.9), (2, 0, 0.5), (3, 0, 0.1), (4, 0, 0.099), (5, 0, None), (6, 1, None)]
    conn.executemany("INSERT INTO ti VALUES (?, ?, ?)", rows)
    conn.execute("CREATE TABLE f (id INTEGER PRIMARY KEY)")
    conn.executemany("INSERT INTO f VALUES (?)", [(i,) for i in range(1, 8)])  # 7 has no ti row
    sql = f"SELECT f.id, {risk.exploit_points_sql('t')} FROM f LEFT JOIN ti t ON t.id = f.id ORDER BY f.id"  # noqa: S608 - the fragment is generated from constants
    got = [row[1] for row in conn.execute(sql)]
    want = [risk.exploit_factor(Intel(bool(k), None, e, None)).points for _, k, e in rows] + [0]
    assert got == want
    for rank, name in enumerate(["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]):
        assert conn.execute(f"SELECT {risk.severity_points_sql(str(rank))}").fetchone()[0] == SEVERITY_POINTS[name]


def test_host_access_capabilities_normalised():
    assert risk.host_access(facts(caps=["cap_sys_admin"]))
    assert risk.host_access(facts(caps=["CAP_BPF"]))
    assert not risk.host_access(facts(caps=["CHOWN"]))


def test_parse_facts_stays_importable_from_both_places():
    from kubedelos import models
    from kubedelos.store import workloads

    assert workloads.parse_facts is models.parse_facts


@pytest.mark.parametrize("severity", ["bogus", ""])
def test_unrecognised_severity_scores_as_unknown(severity):
    assert score(severity, NO_INTEL, None).factors[0].points == SEVERITY_POINTS["UNKNOWN"]
