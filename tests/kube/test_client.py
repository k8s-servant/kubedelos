from types import SimpleNamespace

import pytest
from kubernetes import config

from kubedelos.config import Settings
from kubedelos.kube import client as kube_client


@pytest.fixture
def loaders(monkeypatch):
    calls = {"kube": [], "incluster": 0}
    state = {"fail": False}

    def load_kube_config(config_file=None, context=None):
        calls["kube"].append((config_file, context))
        if state["fail"]:
            raise config.ConfigException("no such context")

    def load_incluster_config():
        calls["incluster"] += 1

    monkeypatch.setattr(kube_client.config, "load_kube_config", load_kube_config)
    monkeypatch.setattr(kube_client.config, "load_incluster_config", load_incluster_config)
    monkeypatch.setattr(
        kube_client.config, "list_kube_config_contexts", lambda config_file=None: ([], {"name": "my-cluster"})
    )
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    return calls, state


def test_load_uses_active_context(loaders):
    calls, _ = loaders
    api = kube_client.load(Settings())
    assert api.current_context() == "my-cluster"
    assert calls == {"kube": [(None, None)], "incluster": 0}


def test_load_passes_kubeconfig_and_context(loaders, tmp_path):
    calls, _ = loaders
    api = kube_client.load(Settings(kubeconfig=tmp_path / "kc", context="other"))
    assert api.current_context() == "other"
    assert calls["kube"] == [(str(tmp_path / "kc"), "other")]


def test_load_falls_back_to_in_cluster(loaders, monkeypatch):
    calls, state = loaders
    state["fail"] = True
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    api = kube_client.load(Settings())
    assert api.current_context() == kube_client.IN_CLUSTER
    assert calls["incluster"] == 1


@pytest.mark.parametrize("kw", [{"context": "typo"}, {"kubeconfig": "/nonexistent/kc"}])
def test_load_never_falls_back_when_a_cluster_was_named(loaders, monkeypatch, kw):
    calls, state = loaders
    state["fail"] = True
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    with pytest.raises(config.ConfigException):
        kube_client.load(Settings(**kw))
    assert calls["incluster"] == 0


def test_load_raises_outside_a_cluster(loaders):
    _, state = loaders
    state["fail"] = True
    with pytest.raises(config.ConfigException):
        kube_client.load(Settings())


def test_real_api_sets_request_timeout_on_every_list(monkeypatch):
    seen = []

    class Recorder:
        def __getattr__(self, name):
            def call(*args, **kwargs):
                seen.append((name, kwargs))
                return SimpleNamespace(items=[])

            return call

    for api in ("CoreV1Api", "AppsV1Api", "BatchV1Api"):
        monkeypatch.setattr(kube_client.client, api, Recorder)
    real = kube_client._RealKubeApi("my-cluster")
    real.list_namespaces()
    real.list_nodes()
    for fn in (real.list_pods, real.list_deployments, real.list_statefulsets, real.list_cronjobs):
        fn("ns")
    assert len(seen) == 6
    assert all(kw.get("_request_timeout") == kube_client.REQUEST_TIMEOUT for _, kw in seen)
    assert all("label_selector" not in kw for _, kw in seen)

    seen.clear()
    real.list_namespaces(label_selector="team=x")
    for fn in (real.list_pods, real.list_deployments, real.list_statefulsets, real.list_cronjobs):
        fn("ns", label_selector="app=web")
    assert [kw["label_selector"] for _, kw in seen] == ["team=x"] + ["app=web"] * 4
    assert all(kw.get("_request_timeout") == kube_client.REQUEST_TIMEOUT for _, kw in seen)
