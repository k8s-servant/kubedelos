import os
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

    class CustomRecorder(Recorder):
        def list_namespaced_custom_object(self, *args, **kwargs):
            seen.append(("list_namespaced_custom_object", kwargs))
            return {"items": []}

    for api in ("CoreV1Api", "AppsV1Api", "BatchV1Api", "NetworkingV1Api", "RbacAuthorizationV1Api"):
        monkeypatch.setattr(kube_client.client, api, Recorder)
    monkeypatch.setattr(kube_client.client, "CustomObjectsApi", CustomRecorder)
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


def _recording_apis(monkeypatch):
    seen = []

    class Recorder:
        def __getattr__(self, name):
            def call(*args, **kwargs):
                seen.append((name, args, kwargs))
                return {"items": []} if name == "list_namespaced_custom_object" else SimpleNamespace(items=[])

            return call

    for api in (
        "CoreV1Api",
        "AppsV1Api",
        "BatchV1Api",
        "NetworkingV1Api",
        "RbacAuthorizationV1Api",
        "CustomObjectsApi",
    ):
        monkeypatch.setattr(kube_client.client, api, Recorder)
    return seen


def test_real_api_sets_request_timeout_on_every_attack_surface_list(monkeypatch):
    seen = _recording_apis(monkeypatch)
    real = kube_client._RealKubeApi("my-cluster")
    for fn in (
        real.list_services,
        real.list_service_accounts,
        real.list_ingresses,
        real.list_network_policies,
        real.list_httproutes,
        real.list_roles,
        real.list_role_bindings,
    ):
        assert fn("ns") == []
    assert real.list_roles(None) == [] and real.list_role_bindings(None) == []
    assert real.list_cluster_roles() == [] and real.list_cluster_role_bindings() == []
    assert [name for name, _, _ in seen] == [
        "list_namespaced_service",
        "list_namespaced_service_account",
        "list_namespaced_ingress",
        "list_namespaced_network_policy",
        "list_namespaced_custom_object",
        "list_namespaced_role",
        "list_namespaced_role_binding",
        "list_role_for_all_namespaces",
        "list_role_binding_for_all_namespaces",
        "list_cluster_role",
        "list_cluster_role_binding",
    ]
    assert all(kw == {"_request_timeout": kube_client.REQUEST_TIMEOUT} for _, _, kw in seen)
    custom = next(args for name, args, _ in seen if name == "list_namespaced_custom_object")
    assert custom == ("gateway.networking.k8s.io", "v1", "ns", "httproutes")


def test_list_roles_all_namespaces_uses_the_cluster_wide_call(monkeypatch):
    seen = _recording_apis(monkeypatch)
    real = kube_client._RealKubeApi("my-cluster")
    real.list_roles(None)
    real.list_role_bindings(None)
    assert [name for name, _, _ in seen] == ["list_role_for_all_namespaces", "list_role_binding_for_all_namespaces"]


def test_real_api_reads_one_secret_with_the_timeout(monkeypatch):
    seen = []

    class Core:
        def read_namespaced_secret(self, name, ns, **kwargs):
            seen.append((name, ns, kwargs))
            return "the-secret"

    monkeypatch.setattr(kube_client.client, "CoreV1Api", Core)
    for api in ("AppsV1Api", "BatchV1Api"):
        monkeypatch.setattr(kube_client.client, api, lambda: None)
    assert kube_client._RealKubeApi("my-cluster").read_secret("web", "regcred") == "the-secret"
    assert seen == [("regcred", "web", {"_request_timeout": kube_client.REQUEST_TIMEOUT})]


def _kubeconfig(path, names, current=None):
    lines = ["apiVersion: v1", "kind: Config", "clusters: []", "users: []", "contexts:"]
    lines += [f"- name: {name!r}\n  context: {{cluster: c, user: u}}" for name in names]
    if current is not None:
        lines.append(f"current-context: {current!r}")
    path.write_text("\n".join(lines) + "\n")
    return path


def test_list_contexts_reads_names_without_logging_in(monkeypatch, tmp_path):
    monkeypatch.setattr(kube_client.config, "load_kube_config", lambda **kw: pytest.fail("must not load a context"))
    kubeconfig = _kubeconfig(tmp_path / "config", ["kind-lab", "Dev", "arn:aws:eks:eu-west-1:1:cluster/x"], "Dev")
    names = kube_client.list_contexts(Settings(kubeconfig=kubeconfig))
    assert names == ["arn:aws:eks:eu-west-1:1:cluster/x", "Dev", "kind-lab"]  # case-insensitive


def test_list_contexts_needs_no_current_context(tmp_path):
    # Normal after `kubectl config unset current-context`; `kubedelos ui --context` still works then.
    kubeconfig = _kubeconfig(tmp_path / "config", ["a", "b"])
    assert kube_client.list_contexts(Settings(kubeconfig=kubeconfig)) == ["a", "b"]


def test_list_contexts_merges_the_kubeconfig_paths(monkeypatch, tmp_path):
    one = _kubeconfig(tmp_path / "one", ["a"], "a")
    two = _kubeconfig(tmp_path / "two", ["b"])
    monkeypatch.setattr(kube_client.kube_config, "KUBE_CONFIG_DEFAULT_LOCATION", f"{one}{os.pathsep}{two}")
    assert kube_client.list_contexts(Settings()) == ["a", "b"]


@pytest.mark.parametrize("content", [None, "contexts: [unclosed\n", "", "just a string\n", "contexts: 7\n"])
def test_list_contexts_is_empty_without_a_readable_kubeconfig(tmp_path, content):
    # A kubeconfig another tool is halfway through rewriting must not break every page.
    kubeconfig = tmp_path / "config"
    if content is not None:
        kubeconfig.write_text(content)
    assert kube_client.list_contexts(Settings(kubeconfig=kubeconfig)) == []
