"""Pure helpers that turn stored run facts into the labels and numbers the UI shows.

No SQL and no I/O live here, so the rules (what counts as a whole-cluster run, when a run is stale, how a scope reads to
a person) are testable on their own and shared by every page.
"""

from datetime import datetime, timedelta

STALE_AFTER = timedelta(hours=24)


def is_cluster_scope(scope: dict | None) -> bool:
    """True for a run that covered the whole cluster; mirrors ``store.queries.CLUSTER_SCOPE_SQL``.

    Exclusions do not narrow a scope, but an explicit namespace list or a selector does. A run with no recorded scope
    is never treated as whole-cluster.
    """
    if scope is None:
        return False
    return not scope.get("namespaces") and scope.get("namespace_selector") is None and scope.get("selector") is None


def describe_scope(scope: dict | None) -> str:
    if scope is None:
        return "scope not recorded"
    parts: list[str] = []
    if is_cluster_scope(scope):
        parts.append("whole cluster")
    else:
        namespaces = scope.get("namespaces") or []
        if len(namespaces) == 1:
            parts.append(f"namespace {namespaces[0]}")
        elif namespaces:
            parts.append(f"namespaces {', '.join(namespaces)}")
        if scope.get("namespace_selector") is not None:
            parts.append(f"namespaces matching {scope['namespace_selector']}")
        if scope.get("selector") is not None:
            parts.append(f"pods matching {scope['selector']}")
    if scope.get("exclude_namespaces"):
        parts.append(f"excluding namespaces {', '.join(scope['exclude_namespaces'])}")
    if scope.get("exclude_images"):
        parts.append(f"excluding images {', '.join(scope['exclude_images'])}")
    return ", ".join(parts)


def describe_pkg_types(pkg_types: str | None) -> str:
    if pkg_types is None:
        return "package types not recorded"
    kinds = set(pkg_types.split(","))
    if kinds == {"library", "os"}:
        return "os + library packages"
    if kinds == {"os"}:
        return "OS packages only"
    if kinds == {"library"}:
        return "library packages only"
    return pkg_types


def ago(then: datetime, now: datetime) -> str:
    seconds = (now - then).total_seconds()
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    hours = int(seconds // 3600)
    if hours < 48:
        return f"{hours} h ago"
    return f"{hours // 24} days ago"


def is_stale(finished_at: datetime | None, now: datetime) -> bool:
    return finished_at is None or now - finished_at > STALE_AFTER


def delta(current: int, previous: int | None) -> int | None:
    return None if previous is None else current - previous
