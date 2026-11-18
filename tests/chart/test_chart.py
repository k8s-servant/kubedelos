"""Renders the Helm chart with ``helm template`` and checks the documents it produces.

The chart is the install path of ``kubedelos serve``; these tests pin its hardening, its read-only RBAC, that the
ConfigMap it writes loads as ``Settings``, the NetworkPolicy guard on header trust, the optional Ingress and HTTPRoute
and the warnings in NOTES.txt. They skip without ``helm`` unless ``KUBEDELOS_REQUIRE_HELM=1`` (CI sets it).
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from kubedelos.config import Settings

CHART = Path(__file__).resolve().parents[2] / "charts" / "kubedelos"
BASE = {"clusterName": "my-cluster"}

if shutil.which("helm") is None:
    if os.environ.get("KUBEDELOS_REQUIRE_HELM") == "1":
        pytest.fail("helm is required (KUBEDELOS_REQUIRE_HELM=1) but is not on PATH", pytrace=False)
    pytest.skip("helm is not installed", allow_module_level=True)


def _run(values: dict | None, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    values_file = tmp_path / "values.yaml"
    values_file.write_text(yaml.safe_dump(values or {}))
    return subprocess.run(
        ["helm", "template", "t", str(CHART), "-n", "kd", "-f", str(values_file)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def render(tmp_path):
    def _render(values: dict | None = None) -> list[dict]:
        result = _run({**BASE, **(values or {})}, tmp_path)
        assert result.returncode == 0, result.stderr
        return [doc for doc in yaml.safe_load_all(result.stdout) if doc]

    return _render


@pytest.fixture
def render_error(tmp_path):
    def _render_error(values: dict | None = None) -> str:
        result = _run(values, tmp_path)
        assert result.returncode != 0, "the render was expected to fail"
        return result.stderr

    return _render_error


def kind(docs: list[dict], name: str) -> dict:
    found = [doc for doc in docs if doc["kind"] == name]
    assert len(found) == 1, f"expected one {name}, got {len(found)}"
    return found[0]


def test_missing_cluster_name_fails_to_render(render_error):
    assert "clusterName is required" in render_error({})


def test_deployment_is_one_hardened_replica(render):
    deployment = kind(render(), "Deployment")
    spec = deployment["spec"]
    assert spec["replicas"] == 1
    assert spec["strategy"]["type"] == "Recreate"
    pod = spec["template"]["spec"]
    security = pod["securityContext"]
    assert security["runAsNonRoot"] is True
    assert security["runAsUser"] == 65532
    assert security["fsGroup"] == 65532
    assert security["seccompProfile"]["type"] == "RuntimeDefault"
    assert pod["automountServiceAccountToken"] is True
    assert pod["terminationGracePeriodSeconds"] == 60
    container = pod["containers"][0]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    for probe in ("livenessProbe", "readinessProbe"):
        assert container[probe]["httpGet"] == {"path": "/healthz", "port": "http"}
    mounts = {mount["mountPath"]: mount["name"] for mount in container["volumeMounts"]}
    volumes = {volume["name"]: volume for volume in pod["volumes"]}
    assert "persistentVolumeClaim" in volumes[mounts["/data"]]
    assert "emptyDir" in volumes[mounts["/tmp"]]


def test_replicas_is_not_a_value(render_error):
    assert render_error({**BASE, "replicas": 2})


def test_image_defaults_to_app_version_and_digest_wins(render):
    container = kind(render(), "Deployment")["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == "ghcr.io/k8s-servant/kubedelos:0.0.0"
    digest = "sha256:" + "a" * 64
    container = kind(render({"image": {"digest": digest}}), "Deployment")["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == f"ghcr.io/k8s-servant/kubedelos@{digest}"


def test_service_maps_80_to_8080(render):
    port = kind(render(), "Service")["spec"]["ports"][0]
    assert (port["port"], port["targetPort"]) == (80, "http")
    container = kind(render(), "Deployment")["spec"]["template"]["spec"]["containers"][0]
    assert container["ports"][0] == {"name": "http", "containerPort": 8080, "protocol": "TCP"}


def test_pvc_defaults_and_existing_claim(render):
    docs = render()
    pvc = kind(docs, "PersistentVolumeClaim")
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert pvc["spec"]["resources"]["requests"]["storage"] == "10Gi"
    volumes = {v["name"]: v for v in kind(docs, "Deployment")["spec"]["template"]["spec"]["volumes"]}
    assert volumes["data"]["persistentVolumeClaim"]["claimName"] == pvc["metadata"]["name"]

    docs = render({"persistence": {"existingClaim": "mine"}})
    assert not [doc for doc in docs if doc["kind"] == "PersistentVolumeClaim"]
    volumes = {v["name"]: v for v in kind(docs, "Deployment")["spec"]["template"]["spec"]["volumes"]}
    assert volumes["data"]["persistentVolumeClaim"]["claimName"] == "mine"


def test_clusterrole_is_read_only_and_exact(render):
    rules = kind(render(), "ClusterRole")["rules"]
    actual = {(tuple(r["apiGroups"]), tuple(r["resources"])): set(r["verbs"]) for r in rules}
    assert len(actual) == len(rules)
    assert actual == {
        (("",), ("namespaces", "pods", "nodes")): {"get", "list"},
        (("apps",), ("deployments", "statefulsets")): {"list"},
        (("batch",), ("cronjobs",)): {"list"},
    }
    binding = kind(render(), "ClusterRoleBinding")
    assert binding["subjects"][0]["kind"] == "ServiceAccount"
    assert binding["subjects"][0]["namespace"] == "kd"


def test_configmap_env(render):
    data = kind(render(), "ConfigMap")["data"]
    assert data["KUBEDELOS_CLUSTER_NAME"] == "my-cluster"
    for name in ("NAMESPACE_SELECTOR", "SELECTOR"):
        assert f"KUBEDELOS_{name}" not in data
    assert data["KUBEDELOS_NAMESPACES"] == "[]"
    expected = {
        "KUBEDELOS_SWEEP_ENABLED": "true",
        "KUBEDELOS_SWEEP_SCHEDULE": "0 3 * * *",
        "KUBEDELOS_SWEEP_TIMEZONE": "UTC",
        "KUBEDELOS_RETENTION_DAYS": "180",
        "KUBEDELOS_READ_ONLY": "false",
        "KUBEDELOS_TRUST_PROXY_HEADERS": "false",
        "KUBEDELOS_IDENTITY_HEADER": "X-Auth-Request-Email",
        "KUBEDELOS_SECURE_COOKIES": "true",
        "KUBEDELOS_PARALLELISM": "4",
        "KUBEDELOS_SCAN_TIMEOUT_S": "600",
        "KUBEDELOS_LOG_LEVEL": "info",
    }
    for key, value in expected.items():
        assert data[key] == value
    assert all(isinstance(value, str) for value in data.values())

    scoped = kind(
        render(
            {
                "scope": {
                    "namespaces": ["web", "jobs"],
                    "excludeNamespaces": ["kube-system"],
                    "excludeImages": ["docker.io/library/*"],
                    "namespaceSelector": "team=a",
                    "selector": "app=b",
                }
            }
        ),
        "ConfigMap",
    )["data"]
    assert json.loads(scoped["KUBEDELOS_NAMESPACES"]) == ["web", "jobs"]
    assert json.loads(scoped["KUBEDELOS_EXCLUDE_NAMESPACES"]) == ["kube-system"]
    assert json.loads(scoped["KUBEDELOS_EXCLUDE_IMAGES"]) == ["docker.io/library/*"]
    assert scoped["KUBEDELOS_NAMESPACE_SELECTOR"] == "team=a"
    assert scoped["KUBEDELOS_SELECTOR"] == "app=b"


def test_configmap_values_load_as_settings(render, monkeypatch):
    docs = render({"scope": {"namespaces": ["web", "jobs"]}, "sweep": {"enabled": False}, "readOnly": True})
    for key, value in kind(docs, "ConfigMap")["data"].items():
        monkeypatch.setenv(key, value)
    settings = Settings()
    assert settings.namespaces == ["web", "jobs"]
    assert settings.cluster_name == "my-cluster"
    assert settings.sweep_enabled is False
    assert settings.read_only is True
    assert settings.secure_cookies is True
    assert "t-kubedelos.kd.svc.cluster.local" in settings.allowed_hosts


def test_allowed_hosts_include_the_service_names(render):
    docs = render({"clusterDomain": "example.local"})
    hosts = kind(docs, "ConfigMap")["data"]["KUBEDELOS_ALLOWED_HOSTS"].split(",")
    name = kind(docs, "Service")["metadata"]["name"]
    assert hosts[:4] == [name, f"{name}.kd", f"{name}.kd.svc", f"{name}.kd.svc.example.local"]
    extra = kind(render({"extraAllowedHosts": ["kubedelos.example.com"]}), "ConfigMap")["data"]
    assert extra["KUBEDELOS_ALLOWED_HOSTS"].endswith(",kubedelos.example.com")


def test_deployment_rolls_on_config_change(render):
    def checksum(values):
        return kind(render(values), "Deployment")["spec"]["template"]["metadata"]["annotations"]["checksum/config"]

    assert checksum({}) == checksum({})
    assert checksum({}) != checksum({"retentionDays": 30})


TRUST = {"auth": {"trustProxyHeaders": True}}
PROXY = {
    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "auth"}},
    "podSelector": {"matchLabels": {"app": "oauth2-proxy"}},
}


def allowed_hosts(docs: list[dict]) -> list[str]:
    return kind(docs, "ConfigMap")["data"]["KUBEDELOS_ALLOWED_HOSTS"].split(",")


def test_networkpolicy_on_by_default_admits_nothing(render):
    docs = render()
    policy = kind(docs, "NetworkPolicy")["spec"]
    pod_labels = kind(docs, "Deployment")["spec"]["template"]["metadata"]["labels"]
    assert policy["podSelector"]["matchLabels"].items() <= pod_labels.items()
    assert policy["policyTypes"] == ["Ingress"]
    assert policy["ingress"] == []
    assert "egress" not in policy


def test_networkpolicy_can_be_turned_off(render):
    assert not [doc for doc in render({"networkPolicy": {"enabled": False}}) if doc["kind"] == "NetworkPolicy"]


def test_networkpolicy_ingress_from_and_egress(render):
    egress = [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": [{"port": 443, "protocol": "TCP"}]}]
    policy = kind(render({"networkPolicy": {"ingressFrom": [PROXY], "egress": egress}}), "NetworkPolicy")["spec"]
    assert policy["ingress"] == [{"from": [PROXY], "ports": [{"port": 8080, "protocol": "TCP"}]}]
    assert policy["policyTypes"] == ["Ingress", "Egress"]
    assert policy["egress"] == egress


@pytest.mark.parametrize(
    "network_policy",
    [
        {"enabled": False, "ingressFrom": [PROXY]},
        {"ingressFrom": []},
        {"ingressFrom": [{}]},
        {"ingressFrom": [{"podSelector": {}}]},
        {"ingressFrom": [{"podSelector": None}]},
        {"ingressFrom": [{"podSelector": {"matchLabels": {}}}]},
        {"ingressFrom": [{"podSelector": {"matchLabels": {}, "matchExpressions": []}}]},
        {"ingressFrom": [{"namespaceSelector": {}}]},
        {"ingressFrom": [{"namespaceSelector": {}, "podSelector": {"matchLabels": {"app": "proxy"}}}]},
        {"ingressFrom": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]},
        {"ingressFrom": [{"ipBlock": {"cidr": "::/0"}}]},
        {"ingressFrom": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}}]},
        {"ingressFrom": [PROXY, {"podSelector": {}}]},
    ],
)
def test_trust_requires_a_restricting_networkpolicy(render_error, network_policy):
    assert "networkPolicy.ingressFrom" in render_error({**BASE, **TRUST, "networkPolicy": network_policy})


def test_trust_renders_with_a_named_proxy(render):
    docs = render({**TRUST, "networkPolicy": {"ingressFrom": [PROXY]}})
    assert kind(docs, "ConfigMap")["data"]["KUBEDELOS_TRUST_PROXY_HEADERS"] == "true"
    assert kind(docs, "NetworkPolicy")["spec"]["ingress"][0]["from"] == [PROXY]


def test_trust_renders_with_a_restricted_ip_block_or_labelled_pods(render):
    sources = [
        {"ipBlock": {"cidr": "10.1.2.0/24"}},
        {"podSelector": {"matchExpressions": [{"key": "app", "operator": "In", "values": ["proxy"]}]}},
    ]
    render({**TRUST, "networkPolicy": {"ingressFrom": sources}})


def test_ingress_and_allowed_hosts(render):
    tls = [{"hosts": ["kubedelos.example.com"], "secretName": "kubedelos-tls"}]
    annotations = {"nginx.ingress.kubernetes.io/proxy-body-size": "1m"}
    docs = render(
        {
            "ingress": {
                "enabled": True,
                "className": "nginx",
                "annotations": annotations,
                "hosts": [{"host": "kubedelos.example.com"}],
                "tls": tls,
            }
        }
    )
    ingress = kind(docs, "Ingress")
    service = kind(docs, "Service")["metadata"]["name"]
    assert ingress["metadata"]["annotations"] == annotations
    assert ingress["spec"]["ingressClassName"] == "nginx"
    assert ingress["spec"]["tls"] == tls
    rule = ingress["spec"]["rules"][0]
    assert rule["host"] == "kubedelos.example.com"
    assert rule["http"]["paths"] == [
        {"path": "/", "pathType": "Prefix", "backend": {"service": {"name": service, "port": {"number": 80}}}}
    ]
    assert "kubedelos.example.com" in allowed_hosts(docs)


def test_ingress_and_httproute_are_off_by_default(render):
    kinds = {doc["kind"] for doc in render()}
    assert not kinds & {"Ingress", "HTTPRoute"}


def test_httproute_and_allowed_hosts(render):
    parent_refs = [{"name": "my-gateway", "namespace": "gateways", "sectionName": "https"}]
    docs = render(
        {
            "httpRoute": {
                "enabled": True,
                "parentRefs": parent_refs,
                "hostnames": ["kubedelos.example.com", "scans.example.com"],
                "annotations": {"example.com/team": "platform"},
            }
        }
    )
    route = kind(docs, "HTTPRoute")
    service = kind(docs, "Service")["metadata"]["name"]
    assert route["apiVersion"] == "gateway.networking.k8s.io/v1"
    assert route["metadata"]["annotations"] == {"example.com/team": "platform"}
    assert route["spec"]["parentRefs"] == parent_refs
    assert route["spec"]["hostnames"] == ["kubedelos.example.com", "scans.example.com"]
    assert route["spec"]["rules"][0]["backendRefs"] == [{"name": service, "port": 80}]
    assert {"kubedelos.example.com", "scans.example.com"} <= set(allowed_hosts(docs))


def test_extra_allowed_hosts(render):
    docs = render(
        {
            "ingress": {"enabled": True, "hosts": [{"host": "a.example.com"}]},
            "httpRoute": {
                "enabled": True,
                "parentRefs": [{"name": "gw"}],
                "hostnames": ["b.example.com", "a.example.com"],
            },
            "extraAllowedHosts": ["c.example.com", "b.example.com"],
        }
    )
    hosts = allowed_hosts(docs)
    assert hosts[4:] == ["a.example.com", "b.example.com", "c.example.com"]
    assert len(hosts) == len(set(hosts))


def test_disabled_exposure_adds_no_allowed_hosts(render):
    docs = render(
        {
            "ingress": {"hosts": [{"host": "a.example.com"}]},
            "httpRoute": {"hostnames": ["b.example.com"]},
        }
    )
    assert len(allowed_hosts(docs)) == 4


@pytest.fixture
def notes(tmp_path):
    def _notes(values: dict | None = None) -> str:
        values_file = tmp_path / "values.yaml"
        values_file.write_text(yaml.safe_dump({**BASE, **(values or {})}))
        result = subprocess.run(
            ["helm", "install", "t", str(CHART), "-n", "kd", "--dry-run=client", "-o", "json", "-f", str(values_file)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return " ".join(json.loads(result.stdout)["info"]["notes"].split())

    return _notes


INVENTORY = "can read the whole vulnerability inventory"
START_SCANS = "start scans and accept risks"
HIDES = "hides its findings"
INGRESS = {"ingress": {"enabled": True, "hosts": [{"host": "kubedelos.example.com"}]}}
ROUTE = {"httpRoute": {"enabled": True, "parentRefs": [{"name": "gw"}], "hostnames": ["kubedelos.example.com"]}}


@pytest.mark.parametrize("exposure", [INGRESS, ROUTE])
def test_notes_exposed_with_trust_off(notes, exposure):
    text = notes(exposure)
    assert INVENTORY in text
    assert START_SCANS in text
    assert "unless your proxy" in text
    text = notes({**exposure, "readOnly": True})
    assert INVENTORY in text
    assert START_SCANS not in text


def test_notes_writes_open_with_trust_off(notes):
    text = notes()
    assert HIDES in text
    assert INVENTORY not in text
    assert "kubectl port-forward" not in text


def test_notes_trust_on_names_both_bypasses(notes):
    text = notes({**TRUST, **INGRESS, "networkPolicy": {"ingressFrom": [PROXY]}})
    assert "kubectl port-forward" in text
    assert "does not enforce NetworkPolicy" in text
    assert INVENTORY not in text
    assert HIDES not in text


def test_notes_read_only_drops_the_write_warnings(notes):
    text = notes({"readOnly": True})
    assert HIDES not in text
    assert START_SCANS not in text
