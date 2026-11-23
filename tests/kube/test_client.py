import base64
import hashlib
import os
import ssl
import threading
from types import SimpleNamespace

import pytest
import yaml
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


@pytest.mark.parametrize("raw", ["https://AKS.example.com", "https://aks.example.com/", "https://aks.example.com:443"])
def test_normalise_server_folds_case_slash_and_default_port(raw):
    assert kube_client.normalise_server(raw) == "https://aks.example.com"


def test_normalise_server_keeps_other_ports_paths_and_ipv6():
    assert kube_client.normalise_server("https://10.0.0.1:6443") == "https://10.0.0.1:6443"
    assert kube_client.normalise_server("http://Example.com:80/") == "http://example.com"
    assert (
        kube_client.normalise_server("https://example.com/k8s/clusters/c-1/") == "https://example.com/k8s/clusters/c-1"
    )
    assert kube_client.normalise_server("https://[fd00::1]:443/") == "https://[fd00::1]"
    assert kube_client.normalise_server("https://[fd00::1]:6443") == "https://[fd00::1]:6443"


def _write_kubeconfig(path, clusters, contexts):
    """``clusters`` maps name -> server (None for no server); ``contexts`` maps name -> cluster name."""
    lines = ["clusters:"] if clusters else []
    for name, server in clusters.items():
        lines.append(
            f"- name: {name}\n  cluster: {{{'server: ' + server if server else 'insecure-skip-tls-verify: true'}}}"
        )
    lines.append("contexts:")
    lines += [f"- name: {name}\n  context: {{cluster: {cluster}, user: u}}" for name, cluster in contexts.items()]
    path.write_text("\n".join(lines) + "\n")
    return path


def test_cluster_keys_group_contexts_of_one_server(tmp_path):
    kubeconfig = _write_kubeconfig(
        tmp_path / "config",
        {
            "prod": "https://prod.example.com:443/",
            "prod-admin": "https://PROD.example.com",
            "dev": "https://dev.example.com",
        },
        {"prod": "prod", "prod-admin": "prod-admin", "dev": "dev"},
    )
    assert kube_client.cluster_keys(Settings(kubeconfig=kubeconfig)) == {
        "prod": "https://prod.example.com",
        "prod-admin": "https://prod.example.com",
        "dev": "https://dev.example.com",
    }


def test_cluster_keys_fall_back_to_the_context_name(tmp_path):
    kubeconfig = _write_kubeconfig(
        tmp_path / "config", {"no-server": None}, {"broken": "missing", "no-server": "no-server"}
    )
    assert kube_client.cluster_keys(Settings(kubeconfig=kubeconfig)) == {"broken": "broken", "no-server": "no-server"}


def test_cluster_keys_first_file_wins_like_kubectl(monkeypatch, tmp_path):
    one = _write_kubeconfig(tmp_path / "one", {"prod": "https://a.example.com"}, {"prod": "prod"})
    two = _write_kubeconfig(tmp_path / "two", {"prod": "https://b.example.com"}, {"prod": "prod", "other": "prod"})
    monkeypatch.setattr(kube_client.kube_config, "KUBE_CONFIG_DEFAULT_LOCATION", f"{one}{os.pathsep}{two}")
    assert kube_client.cluster_keys(Settings()) == {"prod": "https://a.example.com", "other": "https://a.example.com"}


def test_cluster_keys_skip_an_unreadable_file(monkeypatch, tmp_path):
    bad = tmp_path / "bad"
    bad.write_text("contexts: [unclosed\n")
    good = _write_kubeconfig(tmp_path / "good", {"c": "https://c.example.com"}, {"a": "c"})
    monkeypatch.setattr(kube_client.kube_config, "KUBE_CONFIG_DEFAULT_LOCATION", f"{bad}{os.pathsep}{good}")
    assert kube_client.cluster_keys(Settings()) == {"a": "https://c.example.com"}
    assert kube_client.cluster_keys(Settings(kubeconfig=tmp_path / "missing")) == {}


# Two throwaway self-signed test CAs (subjects ca-a.example.com and ca-b.example.com), made for these tests only.
CA_A = """-----BEGIN CERTIFICATE-----
MIIBbDCCARKgAwIBAgIURbn8oX3tYUbIKAijboq2rtiVj54wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQY2EtYS5leGFtcGxlLmNvbTAgFw0yNjExMjMyMTA0MTRaGA8y
MTI2MTAzMDIxMDQxNFowGzEZMBcGA1UEAwwQY2EtYS5leGFtcGxlLmNvbTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABNBMtOEDtdH4Q2El4T6Lsc/yvbUy/++BRvTV
J9Y8jWPQAlc11lzs5ilKiXQnc6Y5IBAeFPA+cvi0NcHqswSyMZKjMjAwMB0GA1Ud
DgQWBBRTBH7H/8zGDJAvPjX5y92xJaoXzjAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
SM49BAMCA0gAMEUCIAJbSOECk+2dFZsaPDtZ6IOe1bJQf8sNMKNcDrNFsmTNAiEA
zFY2Z/KpsY3Zz7MVj+cboGggJAluK1z615zYL/SlKFM=
-----END CERTIFICATE-----
"""
CA_B = """-----BEGIN CERTIFICATE-----
MIIBbDCCARKgAwIBAgIUatGP1a3Me5tK6/NELoJKQL36ZF4wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQY2EtYi5leGFtcGxlLmNvbTAgFw0yNjExMjMyMTA0MTRaGA8y
MTI2MTAzMDIxMDQxNFowGzEZMBcGA1UEAwwQY2EtYi5leGFtcGxlLmNvbTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABB9cZWwuVFeZI5KfY1RggMhco25Tq3uFyLiT
lvezjLFYw7L9YBWokPTkzLkyj9J1MKoICyZlIIfMamXxcfWGCnajMjAwMB0GA1Ud
DgQWBBQVDngi5XYrz0DF8er55sfvD4BiiDAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
SM49BAMCA0gAMEUCIBN2ht/z3re2aTmv2dwEoFhw6a48LDzfu4qKAXvkN5UlAiEA
5GIORBxo75FheK3qwL9qYnBor+FTspg9qpw5BBP75T4=
-----END CERTIFICATE-----
"""


def _b64(pem):
    return base64.b64encode(pem.encode()).decode()


def _fingerprint(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()[:12]


def _write_yaml(path, clusters, contexts):
    """clusters maps name -> the cluster entry's fields; contexts maps name -> cluster name."""
    doc = {
        "clusters": [{"name": name, "cluster": fields} for name, fields in clusters.items()],
        "contexts": [
            {"name": name, "context": {"cluster": cluster, "user": "u"}} for name, cluster in contexts.items()
        ],
    }
    path.write_text(yaml.safe_dump(doc))
    return path


SERVER = "https://127.0.0.1:6443"


def test_cluster_keys_join_a_user_and_an_admin_context_of_one_server_and_ca(tmp_path):
    entry = {"server": SERVER, "certificate-authority-data": _b64(CA_A)}
    kubeconfig = _write_yaml(
        tmp_path / "config", {"aks": entry, "aks-admin": dict(entry)}, {"aks": "aks", "aks-admin": "aks-admin"}
    )
    key = f"{SERVER}#ca={_fingerprint(CA_A)}"
    assert kube_client.cluster_keys(Settings(kubeconfig=kubeconfig)) == {"aks": key, "aks-admin": key}


def test_cluster_keys_tell_two_cas_behind_one_server_apart(tmp_path):
    clusters = {
        "tunnel-a": {"server": SERVER, "certificate-authority-data": _b64(CA_A)},
        "tunnel-b": {"server": SERVER, "certificate-authority-data": _b64(CA_B)},
    }
    kubeconfig = _write_yaml(tmp_path / "config", clusters, {"a": "tunnel-a", "b": "tunnel-b"})
    keys = kube_client.cluster_keys(Settings(kubeconfig=kubeconfig))
    assert keys == {"a": f"{SERVER}#ca={_fingerprint(CA_A)}", "b": f"{SERVER}#ca={_fingerprint(CA_B)}"}
    assert keys["a"] != keys["b"]


def test_cluster_keys_give_one_ca_as_data_or_as_a_relative_file_the_same_key(monkeypatch, tmp_path):
    (tmp_path / "certs").mkdir()
    # The same certificate with other line breaks and a comment line before it, as a file: the same DER, the same key.
    (tmp_path / "certs" / "ca.crt").write_bytes(b"# my-cluster CA\r\n" + CA_A.replace("\n", "\r\n").encode())
    one = _write_yaml(tmp_path / "one", {"c": {"server": SERVER, "certificate-authority-data": _b64(CA_A)}}, {"x": "c"})
    two = _write_yaml(tmp_path / "two", {"d": {"server": SERVER, "certificate-authority": "certs/ca.crt"}}, {"y": "d"})
    monkeypatch.chdir(tmp_path / "certs")  # the path resolves against the kubeconfig's directory, not the cwd
    monkeypatch.setattr(kube_client.kube_config, "KUBE_CONFIG_DEFAULT_LOCATION", f"{one}{os.pathsep}{two}")
    keys = kube_client.cluster_keys(Settings())
    assert keys["x"] == keys["y"] == f"{SERVER}#ca={_fingerprint(CA_A)}"


def test_cluster_keys_add_the_tls_server_name(tmp_path):
    clusters = {
        "one": {"server": SERVER, "tls-server-name": "one.example.com", "certificate-authority-data": _b64(CA_A)},
        "two": {"server": SERVER, "tls-server-name": "two.example.com", "certificate-authority-data": _b64(CA_A)},
    }
    kubeconfig = _write_yaml(tmp_path / "config", clusters, {"one": "one", "two": "two"})
    fp = _fingerprint(CA_A)
    assert kube_client.cluster_keys(Settings(kubeconfig=kubeconfig)) == {
        "one": f"{SERVER}#sni=one.example.com#ca={fp}",
        "two": f"{SERVER}#sni=two.example.com#ca={fp}",
    }


def test_cluster_keys_without_a_ca_are_the_server_alone(tmp_path):
    kubeconfig = _write_yaml(tmp_path / "config", {"c": {"server": "https://API.example.com:443/"}}, {"x": "c"})
    assert kube_client.cluster_keys(Settings(kubeconfig=kubeconfig)) == {"x": "https://api.example.com"}


@pytest.mark.parametrize(
    "fields",
    [
        {"certificate-authority": "missing.crt"},
        {"certificate-authority": "."},  # a directory
        {"certificate-authority": "ca\x00.crt"},  # open() refuses a NUL byte with ValueError
        {"certificate-authority-data": "not base64!"},
        {"certificate-authority-data": _b64("no certificate here")},
        {"certificate-authority-data": _b64("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n")},
        {"certificate-authority-data": 42},
    ],
)
def test_cluster_keys_skip_a_ca_that_cannot_be_read(tmp_path, fields):
    kubeconfig = _write_yaml(tmp_path / "config", {"c": {"server": SERVER, **fields}}, {"x": "c"})
    assert kube_client.cluster_keys(Settings(kubeconfig=kubeconfig)) == {"x": SERVER}


def test_cluster_keys_do_not_open_a_ca_path_that_is_not_a_regular_file(tmp_path):
    # Opening a FIFO blocks until a writer appears, which would hang `kubedelos ui` on start.
    os.mkfifo(tmp_path / "ca.crt")
    kubeconfig = _write_yaml(
        tmp_path / "config", {"c": {"server": SERVER, "certificate-authority": "ca.crt"}}, {"x": "c"}
    )
    keys: dict = {}
    worker = threading.Thread(target=lambda: keys.update(kube_client.cluster_keys(Settings(kubeconfig=kubeconfig))))
    worker.daemon = True
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive(), "cluster_keys blocked on a FIFO"
    assert keys == {"x": SERVER}


def test_cluster_keys_fingerprint_the_first_certificate_of_a_bundle(tmp_path):
    clusters = {
        "bundle": {"server": SERVER, "certificate-authority-data": _b64(CA_A + CA_B)},
        "single": {"server": SERVER, "certificate-authority-data": _b64(CA_A)},
    }
    kubeconfig = _write_yaml(tmp_path / "config", clusters, {"x": "bundle", "y": "single"})
    keys = kube_client.cluster_keys(Settings(kubeconfig=kubeconfig))
    assert keys["x"] == keys["y"]
