"""The risk score: one 0-100 number per finding, built from five explained factors.

The factors are severity, known exploitation (CISA KEV, then EPSS), and three facts about the workload that runs the
image: how far it is exposed, whether it can reach the node, and what its service account may do. It is a pure function
so the UI, the MCP tools and the stored column all agree, and every point can be traced to a ``Factor`` with a reason.

The workload part (exposure, host, rights) is stored per workload as ``risk_points``, so a change of the weights below
needs a migration that recomputes that column. The SQL fragments are generated from the same constants, so the numbers
exist in one place and the SQL and Python scores cannot drift apart.

Unknown is never scored below known-harmless: a workload whose facts were not collected or could not be worked out
counts for more than one known to be safe, because the absence of evidence is not evidence of safety.
"""

from dataclasses import dataclass
from datetime import date
from typing import Literal

from kubedelos.models import WorkloadFacts

MAX_SCORE = 100
SEVERITY_POINTS = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "UNKNOWN": 3}
KEV_POINTS = 25
EPSS_STEPS = ((0.5, 15), (0.1, 8))  # (minimum EPSS, points), highest first
EXPOSURE_POINTS = {"external": 15, "cluster": 5, "none": 0, "unknown": 10}
CLUSTER_ISOLATED_POINTS = 2
HOST_ACCESS_POINTS = 10
ROOT_POINTS = 3
RIGHTS_HIGH_POINTS = 10
RIGHTS_OTHER_POINTS = 5
RIGHTS_UNKNOWN_POINTS = 5

_RANKS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}  # the ``sev_rank`` of the queries

# Capabilities that allow escaping the container or controlling the node.
_HOST_CAPABILITIES = frozenset(
    {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH", "BPF", "ALL"}
)


@dataclass(frozen=True)
class Intel:
    """What the threat feeds say about one CVE."""

    kev: bool
    kev_added: date | None
    epss: float | None
    percentile: float | None


NO_INTEL = Intel(False, None, None, None)


@dataclass(frozen=True)
class Factor:
    name: Literal["severity", "exploited", "exposure", "host", "rights"]
    points: int
    detail: str


@dataclass(frozen=True)
class Score:
    points: int
    factors: tuple[Factor, ...]  # always severity, exploited, exposure, host, rights


def _writable_host_path(facts: WorkloadFacts) -> bool:
    return any(not volume.read_only for volume in facts.pod.host_path_volumes)


def _host_capability(facts: WorkloadFacts) -> bool:
    return any(cap.upper().removeprefix("CAP_") in _HOST_CAPABILITIES for cap in facts.pod.added_capabilities)


def _host_reasons(facts: WorkloadFacts) -> list[str]:
    pod = facts.pod
    checks = (
        ("privileged", pod.privileged),
        ("host pid", pod.host_pid),
        ("host network", pod.host_network),
        ("host ipc", pod.host_ipc),
        ("writable hostPath", _writable_host_path(facts)),
        ("powerful capability", _host_capability(facts)),
    )
    return [label for label, on in checks if on]


def host_access(facts: WorkloadFacts) -> bool:
    """Whether the pod can reach the node: host namespaces, privilege, a writable hostPath or a powerful capability."""
    return bool(_host_reasons(facts))


def _exposure(facts: WorkloadFacts) -> Factor:
    level = facts.exposure.level
    if level == "cluster":
        if facts.network.ingress_isolated:
            return Factor("exposure", CLUSTER_ISOLATED_POINTS, "cluster, ingress isolated")
        return Factor("exposure", EXPOSURE_POINTS["cluster"], "cluster")
    return Factor("exposure", EXPOSURE_POINTS[level], level)


def _host(facts: WorkloadFacts) -> Factor:
    """Host access is +10; root adds nothing on top of it, and counts +3 only on its own (True or unknown)."""
    reasons = _host_reasons(facts)
    if reasons:
        return Factor("host", HOST_ACCESS_POINTS, ", ".join(reasons))
    root = facts.pod.runs_as_root
    if root is None:
        return Factor("host", ROOT_POINTS, "root unknown")
    if root:
        return Factor("host", ROOT_POINTS, "runs as root")
    return Factor("host", 0, "no host access")


def _rights(facts: WorkloadFacts) -> Factor:
    rights = facts.rights
    if facts.pod.automount_token is False:
        return Factor("rights", 0, "token not mounted")
    high = [
        label
        for label, on in (
            ("cluster_admin", rights.cluster_admin),
            ("escalates", rights.escalates),
            ("reads secrets cluster-wide", rights.reads_secrets_scope == "cluster"),
        )
        if on
    ]
    other = [
        label
        for label, on in (
            ("pod_exec", rights.pod_exec),
            ("reads secrets", rights.reads_secrets),
            ("creates workloads", rights.creates_workloads),
            ("wildcard", rights.wildcard),
        )
        if on
    ]
    if high:
        return Factor("rights", RIGHTS_HIGH_POINTS, ", ".join(high))
    if other:
        return Factor("rights", RIGHTS_OTHER_POINTS, ", ".join(other))
    if rights.status == "ok":
        return Factor("rights", 0, "no notable rights")
    if rights.status == "partial":
        return Factor("rights", RIGHTS_OTHER_POINTS, "rights partly known")
    return Factor(
        "rights", RIGHTS_UNKNOWN_POINTS, "rights unknown" if rights.status == "unknown" else "rights not read"
    )


def workload_factors(facts: WorkloadFacts | None) -> tuple[Factor, Factor, Factor]:
    """The exposure, host and rights factors of a workload; no facts counts as unknown on every axis."""
    if facts is None:
        return (
            Factor("exposure", EXPOSURE_POINTS["unknown"], "facts not collected"),
            Factor("host", ROOT_POINTS, "facts not collected"),
            Factor("rights", RIGHTS_UNKNOWN_POINTS, "facts not collected"),
        )
    return _exposure(facts), _host(facts), _rights(facts)


def workload_points(facts: WorkloadFacts | None) -> int:
    return sum(f.points for f in workload_factors(facts))


NO_FACTS_POINTS = workload_points(None)


def exploit_factor(intel: Intel) -> Factor:
    if intel.kev:
        since = f"in KEV since {intel.kev_added.isoformat()}" if intel.kev_added else "in KEV"
        return Factor("exploited", KEV_POINTS, since)
    if intel.epss is None:
        return Factor("exploited", 0, "EPSS unknown")
    for minimum, points in EPSS_STEPS:
        if intel.epss >= minimum:
            return Factor("exploited", points, f"EPSS {intel.epss:.2f}")
    return Factor("exploited", 0, f"EPSS {intel.epss:.2f}")


def score(severity: str, intel: Intel, facts: WorkloadFacts | None) -> Score:
    """The 0-100 score of one finding, with the factors that make it up."""
    name = severity.upper()
    points = SEVERITY_POINTS.get(name, SEVERITY_POINTS["UNKNOWN"])
    factors = (
        Factor("severity", points, name.lower() if name in SEVERITY_POINTS else "unknown"),
        exploit_factor(intel),
        *workload_factors(facts),
    )
    return Score(min(MAX_SCORE, sum(f.points for f in factors)), factors)


def severity_points_sql(rank: str) -> str:
    """A CASE over a ``sev_rank`` SQL expression (4 is Critical ... 0 is Unknown) giving the severity points."""
    whens = " ".join(
        f"WHEN {_RANKS[name]} THEN {points}" for name, points in SEVERITY_POINTS.items() if name != "UNKNOWN"
    )
    return f"CASE {rank} {whens} ELSE {SEVERITY_POINTS['UNKNOWN']} END"


def exploit_points_sql(alias: str) -> str:
    """A CASE over a ``threat_intel`` row aliased ``alias`` (NULL columns from a LEFT JOIN score zero)."""
    steps = " ".join(f"WHEN {alias}.epss >= {minimum} THEN {points}" for minimum, points in EPSS_STEPS)
    return f"CASE WHEN {alias}.kev = 1 THEN {KEV_POINTS} {steps} ELSE 0 END"
