from datetime import UTC, datetime, timedelta

from kubedelos.analytics import ago, delta, describe_pkg_types, describe_scope, is_cluster_scope, is_stale

NOW = datetime(2026, 1, 10, 12, 0, tzinfo=UTC)


def _scope(**kw):
    base = {
        "namespaces": [], "exclude_namespaces": [], "namespace_selector": None, "selector": None,
        "exclude_images": [],
    }  # fmt: skip
    return {**base, **kw}


def test_is_cluster_scope():
    assert is_cluster_scope(_scope())
    assert is_cluster_scope(_scope(exclude_namespaces=["kube-system"], exclude_images=["busybox:*"]))
    assert not is_cluster_scope(None)
    assert not is_cluster_scope(_scope(namespaces=["web"]))
    assert not is_cluster_scope(_scope(namespace_selector="team=x"))
    assert not is_cluster_scope(_scope(selector="app=web"))


def test_describe_scope():
    assert describe_scope(None) == "scope not recorded"
    assert describe_scope(_scope()) == "whole cluster"
    assert describe_scope(_scope(namespaces=["web"])) == "namespace web"
    assert describe_scope(_scope(namespaces=["a", "b"])) == "namespaces a, b"
    assert describe_scope(_scope(namespace_selector="team=x")) == "namespaces matching team=x"
    assert describe_scope(_scope(selector="app=web")) == "pods matching app=web"
    assert (
        describe_scope(_scope(exclude_namespaces=["kube-system"])) == "whole cluster, excluding namespaces kube-system"
    )
    assert describe_scope(_scope(exclude_images=["busybox:*"])) == "whole cluster, excluding images busybox:*"
    assert (
        describe_scope(_scope(namespaces=["web"], selector="app=web", exclude_images=["busybox:*"]))
        == "namespace web, pods matching app=web, excluding images busybox:*"
    )


def test_describe_pkg_types():
    assert describe_pkg_types("library,os") == "os + library packages"
    assert describe_pkg_types("os") == "OS packages only"
    assert describe_pkg_types("library") == "library packages only"
    assert describe_pkg_types(None) == "package types not recorded"


def test_ago():
    assert ago(NOW - timedelta(seconds=59), NOW) == "just now"
    assert ago(NOW - timedelta(minutes=5), NOW) == "5 min ago"
    assert ago(NOW - timedelta(hours=3, minutes=10), NOW) == "3 h ago"
    assert ago(NOW - timedelta(hours=47, minutes=59), NOW) == "47 h ago"
    assert ago(NOW - timedelta(hours=72), NOW) == "3 days ago"


def test_is_stale():
    assert not is_stale(NOW - timedelta(hours=23, minutes=59), NOW)
    assert is_stale(NOW - timedelta(hours=24, minutes=1), NOW)
    assert is_stale(None, NOW)


def test_delta():
    assert delta(5, 3) == 2
    assert delta(3, 5) == -2
    assert delta(3, None) is None
